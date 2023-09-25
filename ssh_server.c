/* Handle networking and I/O*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Handle SSH */
#include <libssh/libssh.h>
#include <libssh/server.h>

/* Handle IP collection */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Geolocate IP address */
#include <curl/curl.h> 

/* handle log files */
#include <pthread.h>

#define SSH_PORT 2222
#define LOGFILE "logins.txt"

pthread_mutex_t logfile_lock;

/* Store libcurl responses */
struct MemoryStruct {
    char *memory;
    size_t size;
};

/* Write IP Geo data */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize);
    if (ptr == NULL) {
        return 0;  /* Out of memory */
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;

    return realsize;
}

/* Log login attempts */
static int auth_password_callback(ssh_session session, const char *user, const char *password, void *userdata) {
    FILE *logfile_handle;
    pthread_mutex_lock(&logfile_lock);

    /* Get the socket file descriptor from the SSH session */
    int sockfd = ssh_get_fd(session);

    /* Use getpeername to retrieve the client's IP address */
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ip_address, INET_ADDRSTRLEN);

    if (ip_address == NULL) {
        perror("Failed to get client IP address");
        pthread_mutex_unlock(&logfile_lock);
        return SSH_AUTH_ERROR;
    }

    logfile_handle = fopen(LOGFILE, "a");
    if (logfile_handle == NULL) {
        perror("Failed to open log file");
        pthread_mutex_unlock(&logfile_lock);
        return SSH_AUTH_ERROR;
    }

    printf("New login from %s: %s:%s\n", ip_address, user, password);
    fprintf(logfile_handle, "%s:%s:%s\n", ip_address, user, password);

    /* Perform an HTTP GET request to retrieve additional information about */
    /* the IP address using libcurl                                         */
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* Dynamically allocate memory */
    chunk.size = 0;            /* Initialize the response data buffer */

    curl = curl_easy_init();
    if (curl) {
        char ip_api_url[128];
        snprintf(ip_api_url, sizeof(ip_api_url), "http://ip-api.com/json/%s", ip_address);

        curl_easy_setopt(curl, CURLOPT_URL, ip_api_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            printf("IP API Response:\n%s\n", chunk.memory);
            fprintf(logfile_handle, "IP API Response:\n%s\n", chunk.memory); // Log the response
        } else {
            fprintf(stderr, "Failed to fetch IP API data: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
        free(chunk.memory);  /* Clean up the response data buffer */
    }

    fclose(logfile_handle);
    pthread_mutex_unlock(&logfile_lock);

    return SSH_AUTH_DENIED;
}

void *handle_connection(void *data) {
    ssh_session session = (ssh_session)data;
    ssh_message message;
    int auth = 0;

    ssh_server_accept(session);

    while (1) {
        message = ssh_message_get(session);
        if (message == NULL) {
            break;
        }

        switch (ssh_message_type(message)) {
            case SSH_REQUEST_AUTH:
                if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                    auth = auth_password_callback(session, ssh_message_auth_user(message), ssh_message_auth_password(message), NULL);
                }
                ssh_message_reply_default(message);
                break;
            case SSH_REQUEST_CHANNEL:
                if (auth == SSH_AUTH_DENIED) {
                    ssh_message_reply_default(message);
                    break;
                }
                break;
            default:
                ssh_message_reply_default(message);
                break;
        }

        ssh_message_free(message);
    }

    ssh_disconnect(session);
    ssh_free(session);

    return NULL;
}

int main() {
    ssh_bind sshbind;
    ssh_session session;
    int rc;

    pthread_mutex_init(&logfile_lock, NULL);

    ssh_init();
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Failed to create SSH bind\n");
        return 1;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "2222");
    if (rc < 0) {
        fprintf(stderr, "Failed to set SSH bind options\n");
        return 1;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc < 0) {
        fprintf(stderr, "Failed to start listening for SSH connections\n");
        return 1;
    }

    printf("SSH server listening on port %d...\n", SSH_PORT);

    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Failed to create SSH session\n");
            return 1;
        }

        rc = ssh_bind_accept(sshbind, session);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "Failed to accept SSH connection\n");
            return 1;
        }

        pthread_t thread;
        rc = pthread_create(&thread, NULL, handle_connection, (void *)session);
        if (rc != 0) {
            fprintf(stderr, "Failed to create thread\n");
            return 1;
        }
    }

    pthread_mutex_destroy(&logfile_lock);

    return 0;
}
