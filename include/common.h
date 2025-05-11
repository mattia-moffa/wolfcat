#ifndef COMMON_H
#define COMMON_H

#include <netdb.h>
#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define BUFSIZE 4096

#define ERR_INVALID_ARGS 1
#define ERR_SOCKET 2
#define ERR_IO 3
#define ERR_PROC 4
#define ERR_SSL 5

struct ca_cert {
    char *filename;
    struct ca_cert *next;
};

void wolfcat_client(struct addrinfo *addrinfo, const char *ca_cert_dir, struct ca_cert *ca_cert);
void wolfcat_server(struct addrinfo *addrinfo, int keep_open, const char *ca_cert_dir, struct ca_cert *ca_cert, const char *cert, const char *key);
//int wolfcat(int sd, struct sockaddr *addr, socklen_t addrlen);
int wolfcat(WOLFSSL *ssl, struct sockaddr *addr, socklen_t addrlen);

void wolfssl_perror(int err, const char *prefix);
int wolfssl_handle_error(WOLFSSL *ssl, int ret, const char *prefix);

#endif // COMMON_H
