/*********************************************************************/
/* SSHoney.c: A SSH Honeypot                                         */
/* Name: Thomas Jordan                                               */
/* Version: 1.3                                                      */
/*********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define BUF_SIZE (256 * 1024)    /* https://github.com/openssh/openssh-portable/blob/master/packet.c */

/* Displays an error message to the command line */
void FatalError(const char *ErrorMsg);

/* Prints out the available command flags */
void PrintUsage();

/* Logs server activity into a file */
void logToFile(const char* input, char logName[], int mode);

int main(int argc, char *argv[]) {
    /**************************/
    /* Command line arguments */
    /**************************/
    int server_socket_fd,       /* socket file descriptor for service */
    data_socket_fd,             /* socket file descriptor for data */
    port_no;                    /* port number */
    int argumentCounter = 1;    /* tracks argv */
    int customOuput = 0;        /* if user specifies output file */
    char *logName;              /* log file name */

    /* Check if input is valid */
    if (argc > 4) {
        printf("Invalid input, enter -h for help\n");
        exit(0);
    }

    /* -h option */
    if (strcmp(argv[argumentCounter], "-h") == 0) {
        PrintUsage();
        exit(0);
    }
    /* -p option */
   if (strcmp(argv[argumentCounter], "-p") == 0) {
        argumentCounter++; /* Go to next argument */
        if (argumentCounter > argc) {
            FatalError("Please specify a port number\n");
        } /* fi */
        port_no = atoi(argv[argumentCounter]);
        if (port_no < 0 || port_no > 65535) { /* Sanity check port number */
            FatalError("Invalid port number");
        } /* fi */
    }
    else {
        FatalError("Invalid input, enter -h for help");
    }

    /* -o option */
    if (strcmp(argv[argumentCounter], "-o") == 0) {
        argumentCounter++; /* Go to next argument */
        customOuput = 1;
        if (argumentCounter > argc) {
            FatalError("Please specify a output log name");
        } /* fi */
        *logName = argv;
        assert(logName); /* Check if pointer was created successfully */
        logToFile("", logName, 0);
    }

    /********************************************************************/
    /* Set up socket and begin listening for connections                */
    /********************************************************************/
    socklen_t client_len; /* length of client address */
    struct sockaddr_in
    server_addr, /* server address (this host) */
    client_addr; /* client address we connect with */
    char buffer[BUF_SIZE]; /* message buffer */

    /* create a socket */
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0)
    {
        fprintf(stderr, "%s: service socket creation failed\n", argv[0]);
        exit(3);
    }
    printf("%s: preparing the server address...\n", argv[0]);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_no);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    /* bind socket to server address */
    printf("%s: assigning the server name to the socket...\n", argv[0]);
    if (bind(server_socket_fd, (struct sockaddr*)&server_addr,
                                sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "%s: binding the server to a socket failed\n", argv[0]);
        exit(4);
    }
    printf("%s: listening on port %d...\n", argv[0], port_no);
    if (listen(server_socket_fd, 5) < 0) /* max 5 clients in backlog */
    {
        fprintf(stderr, "%s: listening on socket failed\n", argv[0]);
        exit(5);
    }
    /* Setup connection */
    client_len = sizeof(client_addr);
    data_socket_fd = accept(server_socket_fd, (struct sockaddr*)&client_addr,
        &client_len);
    if (data_socket_fd < 0) {
        fprintf(stderr, "%s: data socket creation (accept) failed\n", argv[0]);
        exit(6);
    }
    /*****************************************************************/
    /* After a successful connection, serve client requests here...  */
    /*****************************************************************/
    int running = 1;
    while (running == 1) {
        /* Read data from packet */
        memset(buffer, 0, sizeof(buffer));
        int n = read(data_socket_fd, buffer, sizeof(buffer)-1);
        if (n < 0) {
            FatalError("Reading from data socket failed");
        } /* fi */

        /* Write data to log */
        if (n > 0) {
            printf("Activity detected on the server.\n");
        }
        if (customOuput == 0) { /* if no custom output */
            logToFile(n, "log.txt", 1);
        } else if (customOuput == 1) { /* if custom user input */
            logToFile(n, logName, 1);
        }

    }
    close(server_socket_fd);
    return 0;
}

/* Displays an error message to the command line */
void FatalError(const char *ErrorMsg) {
    fprintf(stderr, "ERROR: %s\n", ErrorMsg);
}

/* Prints out the available command flags */
void PrintUsage() {
    printf("Usage: SSHoney -p <port_no> -o <log_file>\n");
    printf("Options:\n");
    printf("-p\t\t\tSpecify the server port number\n");
    printf("-o\t\t\tSpecify the log output file\n");
    printf("-h\t\t\tDisplay this usage information\n");
}

void logToFile(const char* input, char logName[], int mode) {
    FILE* file = fopen("log.txt", "a");  /* Appends information to file */

    /* Get the current time */
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    assert(tm); /* Did this variable get created correctly */

    if (mode == 0) { /* Init mode */
        fprintf(file, "Timestamp: %s | Server started.\n", asctime(tm));
    } /* fi */
    if (mode == 1) { /* Logging mode */
        if (file != NULL) {
            fprintf(file, "Timestamp: %s | Input: %s\n", asctime(tm), input);
            fclose(file);  /* Exit from file */
        } /* fi */
        else { /* Sanity check that file write succeeded */
            FatalError("Error reading to log file.");
        } /* esle */
    } /* fi */
    else { /* Check that mode was valid */
        FatalError("Enter a valid input mode");
    } /* esle */
}


