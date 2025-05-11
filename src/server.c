#include <errno.h>
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

void wolfcat_server(struct addrinfo *addrinfo, int keep_open, const char *ca_cert_dir, struct ca_cert *ca_cert, const char *cert, const char *key) {
    int ret;

    wolfSSL_Init();

    WOLFSSL_CTX *wctx;
    if ((wctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
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

    if (wolfSSL_CTX_use_certificate_file(wctx, cert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error: %s: wolfSSL_CTX_use_certificate_file failed.\n", cert);
        exit(ERR_SSL);
    }

    if (wolfSSL_CTX_use_PrivateKey_file(wctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error: %s: wolfSSL_CTX_use_PrivateKey_file failed.\n", key);
        exit(ERR_SSL);
    }

    int sd = socket(addrinfo->ai_family, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Error: couldn't open socket");
        exit(ERR_SOCKET);
    }

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("Error: setsockopt");
        exit(ERR_SOCKET);
    }

    size_t addrlen;
    if (addrinfo->ai_family == AF_INET) {
        addrlen = sizeof(struct sockaddr_in);
    } else if (addrinfo->ai_family == AF_INET6) {
        addrlen = sizeof(struct sockaddr_in6);
    }

    if (bind(sd, addrinfo->ai_addr, addrlen) < 0) {
        perror("Error: bind");
        exit(ERR_SOCKET);
    }

    if (listen(sd, 1) < 0) {
        perror("Error: listen");
        exit(ERR_SOCKET);
    }

    int should_stop = 0;
    while (!should_stop) {
        struct sockaddr client_addr;
        socklen_t client_addrlen = sizeof(struct sockaddr);
        int client_sd = accept(sd, &client_addr, &client_addrlen);
        if (client_sd < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                perror("Error: accept");
                exit(ERR_SOCKET);
            }
        }

        WOLFSSL *ssl;
        if ((ssl = wolfSSL_new(wctx)) == NULL) {
            fprintf(stderr, "Error: wolfSSL_new failed.\n");
            close(client_sd);
            continue;
        }
        wolfSSL_set_fd(ssl, client_sd);

        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            fprintf(stderr, "Error: wolfSSL_accept failed.\n");
        }

        wolfcat(ssl, &client_addr, client_addrlen);

        wolfSSL_shutdown(ssl);

        if (!keep_open)
            should_stop = 1;
    }

    close(sd);
    wolfSSL_CTX_free(wctx);
    wolfSSL_Cleanup();
    exit(0);
}
