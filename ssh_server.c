/* Handle I/O */
#include <stdio.h>
#include <string.h>

/* Handle SSH */
#include <libssh/libssh.h>
#include <libssh/server.h>

/* Geolocate IP address */
#include <json-c/json.h>
#include <curl/curl.h>
#include <time.h>

/* Handle networking */
#include <arpa/inet.h>

/* Log output file */
#define LISTENADDRESS   "0.0.0.0"
#define PORT            2222
#define RSA_KEYFILE     "/Users/Thomas/Documents/SSHoney/keys/id_rsa"
#define LOGFILE         "/Users/Thomas/Documents/SSHoney/log.json"

/* SSH Session Info */
static ssh_session session;
static ssh_bind sshbind;

/* Custom Definitions */
#define DEBUG 0
#define MAXBUF 100
char curl_response_data[4096]; /* Declare a buffer to store the cURL response data */

struct connection {
    ssh_session session;
    ssh_message message;
    char client_ip[MAXBUF];
    char con_time[MAXBUF];
    char *user;
    char *pass;
    const char *ipGeo;
};

int handle_auth(ssh_session session);

/* Callback function to handle the received data */
size_t write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp) {
    char **response_ptr = (char **)userp;

    /* Calculate the total size of the data */
    size_t total_size = size * nmemb;

    /* Allocate memory for the response and copy the data */
    *response_ptr = (char *)malloc(total_size + 1);  // +1 for null-terminator
    if (*response_ptr) {
        strncpy(*response_ptr, (char *)buffer, total_size);
        (*response_ptr)[total_size] = '\0';  // Null-terminate the response
    }

    return total_size;
}

/* Write IP Geo data */
/* Function to perform geolocation using the ip-api.com API and log data in JSON format */
static void geolocate_ip_and_log(struct connection *c) {
    char url[100]; /* Character buffer for URL string */
    char *response = NULL;  /* pointer to curl response (JSON) */

    /* Create the API URL */
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", c->client_ip);

    /* Initialize libcurl */
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the callback function to handle the received data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the HTTP request
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            // Response is now stored in the 'response' variable
            if (!response) {
                fprintf(stderr, "No response data received.\n");
            }
        }

        // Cleanup libcurl
        curl_easy_cleanup(curl);
    }

    /* Parse the JSON response and create a JSON object */
    struct json_object *json_obj = json_tokener_parse(response);
    free(response);  // Free allocated memory for curl response data
    
    /* Create a JSON object to store log data */
    struct json_object *log_data = json_object_new_object();
    json_object_object_add(log_data, "time", json_object_new_string(c->con_time));
    json_object_object_add(log_data, "ip", json_object_new_string(c->client_ip));
    json_object_object_add(log_data, "user", json_object_new_string(c->user));
    json_object_object_add(log_data, "pass", json_object_new_string(c->pass));

    /* Add geolocation data to the log_data object (use data from json_obj) */
    c->ipGeo = json_object_to_json_string(json_obj);
    json_object_object_add(log_data, "ipGeo", json_object_new_string(c->ipGeo));

    /* Convert the log_data JSON object to a string */
    const char *log_data_str = json_object_to_json_string(log_data);
    
    /* Write the log_data to the JSON file */
    FILE *json_file = fopen(LOGFILE, "a+");
    if (json_file) {
        fprintf(json_file, "%s\n", log_data_str);
        fclose(json_file);
    }
    
    /* Free JSON objects */
    json_object_put(log_data);
    json_object_put(json_obj);
}

/* Stores the client's IP address in the connection struct and performs geolocation. */
static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);

    /* Perform geolocation based on the client's IP address and log data in JSON format */
    geolocate_ip_and_log(c);

    return 0;
}

/* Stores the current UTC time. Returns 0 on error. */
static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t));
}

/* Write information about a connection attempt to LOGFILE. */
static int log_attempt(struct connection *c) {
    const char *user = ssh_message_auth_user(c->message);
    const char *pass = ssh_message_auth_password(c->message); // TODO: Implement with callback instead
    c->user = (char *)user;
    c->pass = (char *)pass;

    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        return -1;
    }

    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }

    return 0;
}

/* Signal handler for cleaning up after child processes.
 * Handle cleanup at SIGCHLD to handle multiple simultaneous connections. */
static int cleanup_child_processes(void) {
    int status;
    int pid;
    
    /* Wait for and reap child processes */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {}

    /* Re-install the signal handler for the next child */
    signal(SIGCHLD, (void (*)())cleanup_child_processes);

    return 0;
}

/* SIGINT handler. Cleanup SSH objects and exit gracefully. */
static void handle_sigint(void) {
    ssh_disconnect(session); /* Disconnect the SSH session */
    ssh_bind_free(sshbind); /* Free SSH resources */
    ssh_finalize(); /* Finalize SSH */
    exit(0);
}

/* Handles password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    struct connection con;
    con.session = session;

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(con.session));
        return -1;
    }
    if (DEBUG) { printf("Successful key exchange.\n"); }

    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    while (1) {
        if ((con.message = ssh_message_get(con.session)) == NULL) {
            break;
        }

        /* Log the authentication request and disconnect. */
        if (ssh_message_subtype(con.message) == SSH_AUTH_METHOD_PASSWORD) {
                log_attempt(&con);
        }
        else {
            if (DEBUG) { fprintf(stderr, "Not a password authentication attempt.\n"); }
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(con.message);
        ssh_message_free(con.message);
    }

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}

int main() {
    int port = PORT;

    /* Cleanup after child process exits */
    signal(SIGCHLD, (void (*)())cleanup_child_processes);
    signal(SIGINT, (void(*)())handle_sigint);

    /* Create and configure the ssh session. */
    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,RSA_KEYFILE);

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return -1;
    }
    if (DEBUG) { printf("Listening on port %d.\n", port); }

    printf("Starting SSHoney... 🍯\n");
    printf("Listening for connections...\n");

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: `%s'.\n",ssh_get_error(sshbind));
            return -1;
        }
        printf("Accepted a connection.\n");

        switch (fork())  {
            case -1:
                fprintf(stderr,"Fork returned error: `%d'.\n",-1);
                exit(-1);

            case 0:
                exit(handle_auth(session));

            default:
                break;
        }
    }

    return 0;
}
