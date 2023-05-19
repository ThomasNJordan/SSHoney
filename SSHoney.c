/*********************************************************************/
/* SSHoney.c: A SSH Honeypot                                         */
/* Name: Thomas Jordan												 */
/* Version: 1.0											             */
/*********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>`

#define BUF_SIZE = (256 * 1024)    /* https://github.com/openssh/openssh-portable/blob/master/packet.c */

/* Displays an error message to the command line */
void FatalError(const char *Program, const char *ErrorMsg);

/* Prints out the available command flags */
void PrintUsage();

int main(int argc, char *argv[]) {
    /**************************/
    /* Command line arguments */
    /**************************/
    int server_socket_fd, /* socket file descriptor for service */
    data_socket_fd, /* socket file descriptor for data */
    port_no; /* port number */

    /* Check if input is valid */
    if (argc < 2) {
        printf("Invalid input, enter -h for help\n");
        exit(0);
    }

    /* -h option */
    if (strcmp(argv[1], "-h") == 0) {
        PrintUsage();
    }
    /* -p option */
   if (strcmp(argv[1], "-p") == 0) {
        port_no = atoi(argv[2]);
        if (port_no <= 2000) {
            fprintf(stderr, "%s: invalid port number %d, should be greater 2000\n",
            argv[0], port_no);
        }
    }
    else {
        printf("Invalid input, enter -h for help\n");
        exit(0);
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
        memset(buffer, 0, sizeof(buffer));
        int n = read(data_socket_fd, buffer, sizeof(buffer)-1);
        if (n < 0) {
            fprintf(stderr, "%s: reading from data socket failed\n", argv[0]);
            exit(7);
        }

        /* Define message behavior */
        if (strcmp(buffer, "PRINT") == 0) {
            memset(buffer, 0, sizeof(buffer));
            printf("%s: Sending response: OK.\n", argv[0]);
            char ret[] = "OK\n";
            strcat(ret, "Available DIP Operations:\n");
            strcat(ret, "Age Image\n");
            strcat(ret, "Convert image to Black and White\n");
            strcat(ret, "Make a negative of the image\n");
            strcat(ret, "Flip the image vertically\n");
            strcat(ret, "Mirror the iamge horizontally\n");
            strcat(ret, "Sharpen the Image\n");
            strcat(ret, "Exchange Red and Blue");

            write(data_socket_fd, ret, sizeof(buffer) - 1);
        } /* fi */
        else if (strcmp(buffer, "AUTOTEST") == 0) {
            memset(buffer, 0, sizeof(buffer));
            /* If AutoTest() fails, return value */
            AutoTest();
            printf("%s: Sending response: OK.", argv[0]);
            char ret[] = "OK";
            int bytes_written = write(data_socket_fd, ret, sizeof(buffer) - 1);
            if (bytes_written < 0 ) {
                FatalError(argv[0], "Error writing to socket");
            }
        } /* esle */
        else if (strcmp(buffer, "CLOSE") == 0) {
            memset(buffer, 0, sizeof(buffer));
            printf("%s: Sending response: OK.", argv[0]);
            char ret[] = "OK";
            
            int bytes_written = write(data_socket_fd, ret, sizeof(buffer) - 1);
            if (bytes_written < 0 ) {
                FatalError(argv[0], "Error writing to socket");
            }

            close(data_socket_fd);
            running = 0;
        } /* esle */
        else {
            write(data_socket_fd, "Unknown request", sizeof(buffer)-1); 
        }

        if (n < 0) {
            FatalError(argv[0], "Writing to socket failed");
            exit(8);
        }
    }
    close(server_socket_fd);
    return 0;
}

