/*********************************************************************/
/* SSHoney.c: A SSH Honeypot                                         */
/* Name: Thomas Jordan                                               */
/* Last Modified: 5/24/2023                                          */
/*********************************************************************/

#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "log.h"
#include "ssh_server.h"

#define BUF_SIZE (256 * 1024)    /* https://github.com/openssh/openssh-portable/blob/master/packet.c */

/* Displays an error message to the command line */
void FatalError(const char *ErrorMsg);

/* Prints out the available command flags */
void PrintUsage();

int main(int argc, char *argv[]) {
    /**************************/
    /* Command line arguments */
    /**************************/
    int server_socket_fd,       /* socket file descriptor for service */
    data_socket_fd,             /* socket file descriptor for data */
    port_no;                    /* port number */
    int argumentCounter = 1;    /* tracks argv */
    int customOuput = 0;        /* if user specifies output file */
    int isPort = 0;             /* check if a port was defined */
    char* logName;              /* log file name */

    if (argc > 1) {
        /* -h option */
        if (strcmp(argv[argumentCounter], "-h") == 0) {
            PrintUsage();
            exit(0);
        }

        /* -p option */
        if (strcmp(argv[argumentCounter], "-p") == 0) {
            argumentCounter++; /* Go to next argument */
            isPort = 1;
            if (argumentCounter > argc) {
                FatalError("Please specify a port number\n");
            } /* fi */
            port_no = atoi(argv[argumentCounter]);
            if (port_no < 0 || port_no > 65535) { /* Sanity check port number */
                FatalError("Invalid port number");
            } /* fi */
        }

        /* -o option */
        if (strcmp(argv[argumentCounter], "-o") == 0) {
            argumentCounter++; /* Go to next argument */
            customOuput = 1;
            if (argumentCounter > argc) {
                FatalError("Please specify a output log name");
            } /* fi */
            logName = argv[argumentCounter];
            logToFile("", logName, 0);
        } /* fi */
    } /* fi */
    else {
        logToFile("", "log.txt", 0); /* Write log to log.txt */
    }

    /********************************************************************/
    /* Set up socket and begin listening for connections                */
    /********************************************************************/

    /* If user did not give a port, default to 22 */
    if (isPort != 1) {
        port_no = 22;
    }

    socklen_t client_len; /* length of client address */
    struct sockaddr_in
    server_addr, /* server address (this host) */
    client_addr; /* client address we connect with */
    char buffer[BUF_SIZE]; /* message buffer */

    /* create a socket */
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0) {
        fprintf(stderr, "Service socket creation failed\n");
        exit(3);
    }
    printf("Preparing the server address...\n");
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_no);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    /* bind socket to server address */
    printf("Assigning the server name to the socket...\n");
    if (bind(server_socket_fd, (struct sockaddr*)&server_addr,
                                sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "Binding the server to a socket failed\n");
        exit(4);
    }
    printf("Listening on port %d...\n", port_no);
    if (listen(server_socket_fd, 5) < 0) /* max 5 clients in backlog */
    {
        fprintf(stderr, "Listening on socket failed\n");
        exit(5);
    }
    /* Setup connection */
    client_len = sizeof(client_addr);
    data_socket_fd = accept(server_socket_fd, (struct sockaddr*)&client_addr,
        &client_len);
    if (data_socket_fd < 0) {
        fprintf(stderr, "Data socket creation (accept) failed\n");
        exit(6);
    }
    /*****************************************************************/
    /* After a successful connection, serve client requests here...  */
    /*****************************************************************/
    while (1) { /* Same as while(true) in other languages */
        /* Read data from packet */
        memset(buffer, 0, sizeof(buffer));
        int n = read(data_socket_fd, buffer, sizeof(buffer)-1);
        if (n < 0) {
            FatalError("Reading from data socket failed");
        } /* fi */

        if (n == 0) /* If no data, don't continue loop */
            continue;

        /* Convert buffer to character array */
        buffer[sizeof(buffer) - 1] = '\0';
        char* output = (char*)malloc((n + 1) * sizeof(char));
        if (output == NULL) {
            FatalError("Memory allocation failed\n");
        }

        strcpy(output, buffer);

        /* Write data to log */
        if (n > 0) {
            printf("Activity detected on the server. Recording incident in log.\n");
        }
        if (customOuput == 1) { /* if custom user input */
            logToFile(output, logName, 1);
        }
        else { /* if no custom output or if output value fails */
            logToFile(output, "log.txt", 1);
        } /* esle */

        /* free character array */
        free(output);
    } /* elihw */
    close(server_socket_fd);
    return 0;
}

/* Displays an error message to the command line */
void FatalError(const char *ErrorMsg) {
    fprintf(stderr, "ERROR: %s\n", ErrorMsg);
    exit(EXIT_FAILURE);
}

/* Prints out the available command flags */
void PrintUsage() {
    printf("Usage: SSHoney -p <port_no> -o <log_file>\n");
    printf("Options:\n");
    printf("-p\t\t\tSpecify the server port number\n");
    printf("-o\t\t\tSpecify the log output file\n");
    printf("-h\t\t\tDisplay this usage information\n");
}
