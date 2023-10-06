/* Handle networking and I/O*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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

/* Function to print an error message with the given prefix */
void print_error(const char *prefix) {
    fprintf(stderr, "%s: %s\n", prefix, strerror(errno));
}

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

static void *ssh_server_thread(void *arg) {
    ssh_session session = (ssh_session)arg;

    /* Set up fake banner */
    /* ssh_set_banner(session, "Ubuntu 20.04 LTS"); */
    
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "Key exchange failed\n");
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    pthread_mutex_lock(&logfile_lock);
    int sockfd = ssh_get_fd(session);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(sockfd, (struct sockaddr *)&client_addr, &addr_len);
    
    char ip_address[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ip_address, INET_ADDRSTRLEN);

    if (inet_ntop(AF_INET, &(client_addr.sin_addr), ip_address, INET_ADDRSTRLEN) == NULL) {
        perror("Failed to get client IP address");
        pthread_mutex_unlock(&logfile_lock);
        return NULL;
    }
    else {
        FILE *logfile_handle = fopen(LOGFILE, "a");
        if (logfile_handle == NULL) {
            perror("Failed to open log file");
        } else {
            printf("New login from %s\n", ip_address);
            fprintf(logfile_handle, "IP: %s\n", ip_address);

            /* Perform an HTTP GET request to retrieve additional IP information */
            CURL *curl;
            CURLcode res;
            struct MemoryStruct chunk;

            chunk.memory = malloc(1);
            chunk.size = 0;

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
                    fprintf(logfile_handle, "IP API Response:\n%s\n", chunk.memory);
                } else {
                    fprintf(stderr, "Failed to fetch IP API data: %s\n", curl_easy_strerror(res));
                }

                curl_easy_cleanup(curl);
                free(chunk.memory);
                fclose(logfile_handle);
            } /* fi */
        } /* esle */
    } /* esle */

    pthread_mutex_unlock(&logfile_lock);

    /* Reject client connection */
    ssh_disconnect(session);
    ssh_free(session);

    return NULL;
}

int main() {
    ssh_bind sshbind;
    int rc;

    pthread_mutex_init(&logfile_lock, NULL);

    ssh_init();
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Failed to create SSH bind\n");
        return 1;
    }

    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "2222");
    /* rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0"); */ 
    /* delete after use */

    if (rc < 0) {
        fprintf(stderr, "Failed to set SSH bind options\n");
        return 1;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc < 0) {
        fprintf(stderr, "Failed to start listening for SSH connections\n");
        return 1;
    }

    pthread_t tid;
    pthread_create(&tid, NULL, ssh_server_thread, sshbind);

    /* Wait for server thread to finish (you can add a termination condition) */
    pthread_join(tid, NULL);

    /* Cleanup */
    pthread_mutex_destroy(&logfile_lock);
    ssh_bind_free(sshbind);

    return 0;
}
