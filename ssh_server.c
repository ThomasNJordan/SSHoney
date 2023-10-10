/* Handle networking and I/O */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

/* Handle SSH */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <time.h>

/* Handle IP collection */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Geolocate IP address */
#include <json-c/json.h>
#include <curl/curl.h>

/* Handle threads */
#include <pthread.h>
#include <sys/wait.h>

/* Log output file */
#define LISTENADDRESS   "0.0.0.0"
#define PORT            2222
#define RSA_KEYFILE     "/Users/Thomas/Documents/SSHoney/keys/id_rsa"
#define LOGFILE         "/Users/Thomas/Documents/SSHoney/log.txt"

pthread_mutex_t logfile_lock;

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
};

int handle_auth(ssh_session session);

/* Write IP Geo data */
/* Function to perform geolocation using the ip-api.com API and log data in JSON format */
static void geolocate_ip_and_log(struct connection *c) {
    CURL *curl;
    CURLcode res;
    char url[100];

    /* Create the API URL */
    snprintf(url, sizeof(url), "http://ip-api.com/json/%s", c->client_ip);

    /* Initialize libcurl */
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);

        /* Set a callback function to receive the HTTP response */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);

        /* Set the buffer to receive the response data */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, curl_response_data);

        /* Perform the HTTP request */
        res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        /* Cleanup libcurl */
        curl_easy_cleanup(curl);
    }

    printf("%s", curl_response_data);

    /* Parse the JSON response and create a JSON object */
    struct json_object *json_obj = json_tokener_parse(curl_response_data);
    
    /* Create a JSON object to store log data */
    struct json_object *log_data = json_object_new_object();
    json_object_object_add(log_data, "time", json_object_new_string(c->con_time));
    json_object_object_add(log_data, "ip", json_object_new_string(c->client_ip));
    json_object_object_add(log_data, "user", json_object_new_string(c->user));
    json_object_object_add(log_data, "pass", json_object_new_string(c->pass));
    
    /* Add geolocation data to the log_data object (use data from json_obj) */
    printf("Reached\n");
    printf("%s", curl_response_data);
    json_object_object_add(log_data, "Location", json_object_new_string(json_object_get_string(json_object_object_get(json_obj, "country"))));
    printf("Reached\n");

    /* Convert the log_data JSON object to a string */
    const char *log_data_str = json_object_to_json_string(log_data);
    
    /* Write the log_data to the JSON file */
    FILE *json_file = fopen("log.json", "a+");
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

/* Write interesting information about a connection attempt to  LOGFILE. 
 * Returns -1 on error. */
static int log_attempt(struct connection *c) {
    FILE *f;
    int r;

    const char *user = ssh_message_auth_user(c->message);
    const char *pass = ssh_message_auth_password(c->message);
    c->user = (char *)user;
    c->pass = (char *)pass;

    if ((f = fopen(LOGFILE, "a+")) == NULL) {
        fprintf(stderr, "Unable to open %s\n", LOGFILE);
        return -1;
    }

    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        return -1;
    }

    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }

    printf("Login attempt: %s %s %s %s\n", c->con_time, c->client_ip, c->user, c->pass); 
    r = fprintf(f, "%s\t%s\t%s\t%s\t\n", c->con_time, c->client_ip, c->user, c->pass);
    fclose(f);
    return r;
}


/* Signal handler for cleaning up after child processes.
 * We handle cleanup at SIGCHLD to handle multiple simultaneous connections. */
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

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
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
