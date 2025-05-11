#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "common.h"

void wolfcat_client(struct addrinfo *addrinfo, const char *ca_cert_dir, struct ca_cert *ca_cert) {
    int ret;

    wolfSSL_Init();

    WOLFSSL_CTX *wctx;
    if ((wctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "Error: wolfSSL_CTX_new failed.\n");
        exit(ERR_SSL);
    }

    if (ca_cert_dir) {
        if ((ret = wolfSSL_CTX_load_verify_locations(wctx, NULL, ca_cert_dir)) != SSL_SUCCESS) {
            fprintf(stderr, "Warning: %s: wolfSSL_CTX_load_verify_locations failed loading some certificates (error code = %d).\n", ca_cert_dir, ret);
        }
    }

    for (struct ca_cert *curr = ca_cert; curr; curr = curr->next) {
        if ((ret = wolfSSL_CTX_load_verify_locations(wctx, curr->filename, NULL)) != SSL_SUCCESS) {
            fprintf(stderr, "Error: %s: wolfSSL_CTX_load_verify_locations failed (error code = %d).\n", curr->filename, ret);
            exit(ERR_SSL);
        }
    }

    int sd = socket(addrinfo->ai_family, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Error: couldn't open socket");
        exit(ERR_SOCKET);
    }

    size_t addrlen;
    if (addrinfo->ai_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    } else if (addrinfo->ai_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }

    if (connect(sd, addrinfo->ai_addr, addrlen) < 0) {
        perror("Error: connect");
        exit(ERR_SOCKET);
    }

    WOLFSSL *ssl;
    if ((ssl = wolfSSL_new(wctx)) == NULL) {
        fprintf(stderr, "Error: wolfSSL_new failed.\n");
        exit(ERR_SSL);
    }
    wolfSSL_set_fd(ssl, sd);

    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        wolfssl_handle_error(ssl, ret, "Error: wolfSSL_connect");
        exit(ERR_SSL);
    }

    ret = wolfcat(ssl, addrinfo->ai_addr, addrlen);

    wolfSSL_shutdown(ssl);
    close(sd);
    wolfSSL_CTX_free(wctx);
    wolfSSL_Cleanup();

    exit(ret);
}
