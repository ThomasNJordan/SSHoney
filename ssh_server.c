/*********************************************************************/
/* ssh.c: Manage dummy ssh session                                   */
/* Name: Thomas Jordan                                               */
/* Last Modified: 5/24/2023                                          */
/*********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh2.h>
#include "ssh_server.h"

int authenticate_password(LIBSSH2_SESSION *session, const char *password) {
    /* TODO: Implement "authentication" logic. */
    return 0;
}

int start_ssh_server() {
    LIBSSH2_LISTENER *listener = NULL;
    LIBSSH2_SESSION *session = NULL;
    int rc;

    /* Initialize the libssh2 library */
    rc = libssh2_init(0);
    if (rc != 0) {
        printf("Failed to initialize libssh2\n");
        return -1;
    }

    /* Create a new SSH listener object */
    listener = libssh2_channel_forward_listen_ex(NULL, 0, NULL, 0, 1);
    if (listener == NULL) {
        printf("Failed to create SSH listener\n");
        libssh2_exit();
        return -1;
    }

    printf("SSH server listening on port %d\n", libssh2_channel_forward_listen_port(listener));

    while (1) {
        /* Accept an incoming SSH connection */
        session = libssh2_session_init();
        if (session == NULL) {
            printf("Failed to create SSH session\n");
            libssh2_channel_forward_cancel(listener);
            libssh2_exit();
            return -1;
        }

        int sock = libssh2_channel_forward_accept(listener);
        if (sock < 0) {
            printf("Failed to accept SSH connection\n");
            libssh2_session_free(session);
            continue;
        }

        printf("Accepted SSH connection\n");

        /* Set up the SSH session */
        libssh2_session_set_blocking(session, 0);
        libssh2_session_handshake(session, sock);

        /* Authenticate the user using password authentication */
        const char *password = "password";  /* Replace with your password retrieval mechanism */
        if (authenticate_password(session, password) != 1) {
            printf("Failed to authenticate user\n");
            libssh2_session_disconnect(session, "Authentication failed");
            libssh2_session_free(session);
            continue;
        }

        printf("User authenticated successfully\n");

        /* Add your server logic here. */

        /* Disconnect and free the SSH session */
        libssh2_session_disconnect(session, "Bye bye");
        libssh2_session_free(session);
    }

    /* Close the SSH listener */
    libssh2_channel_forward_cancel(listener);

    /* Cleanup the libssh2 library */
    libssh2_exit();

    return 0;
}
