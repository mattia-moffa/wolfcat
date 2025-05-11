#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "common.h"

#define POLL_STDIN 0
#define POLL_NETOUT 1
#define POLL_NETIN 2
#define POLL_STDOUT 3

void wolfssl_perror(int err, const char *prefix) {
    char error_string[WOLFSSL_MAX_ERROR_SZ];
    wolfSSL_ERR_error_string(err, error_string);
    fprintf(stderr, "%s: %s\n", prefix, error_string);
}

int wolfssl_handle_error(WOLFSSL *ssl, int ret, const char *prefix) {
    int err = wolfSSL_get_error(ssl, ret);
    if (prefix) {
        wolfssl_perror(err, prefix);
    }
    return err;
}

struct thread_arg {
    WOLFSSL *ssl;
    pthread_t *other_thread;
    int result;
};

void *stdin_to_net(void *argp) {
    struct thread_arg *arg = (struct thread_arg *)argp;
    WOLFSSL *ssl = arg->ssl;
    pthread_t other = *arg->other_thread;

    int *result = (int *)malloc(sizeof(*result));

    char buf[BUFSIZE];

    int n, ret;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0 || errno == EINTR) {
        if (errno == EINTR)
            continue;
        if ((ret = wolfSSL_write(ssl, buf, n)) <= 0) {
            wolfssl_handle_error(ssl, ret, "Error: wolfSSL_write");
            arg->result = ERR_SSL;
            goto end;
        }
    }
    if (n < 0) {
        perror("Error: read from stdin");
        arg->result = ERR_IO;
        goto end;
    }

    arg->result = 0;

end:
    pthread_cancel(other);
    return NULL;
}

void *net_to_stdout(void *argp) {
    struct thread_arg *arg = (struct thread_arg *)argp;
    WOLFSSL *ssl = arg->ssl;
    pthread_t other = *arg->other_thread;

    int *result = (int *)malloc(sizeof(*result));

    char buf[BUFSIZE];

    int n;
    while ((n = wolfSSL_read(ssl, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, n) < 0) {
            if (errno == EINTR)
                continue;
            perror("Error: write to stdout");
            arg->result = ERR_IO;
            goto end;
        }
    }
    int err = wolfSSL_get_error(ssl, n);
    if (err != WOLFSSL_ERROR_ZERO_RETURN) {
        wolfssl_perror(err, "Error: wolfSSL_read");
        arg->result = ERR_SSL;
        goto end;
    }

    arg->result = 0;

end:
    pthread_cancel(other);
    return NULL;
}

int wolfcat(WOLFSSL *ssl, struct sockaddr *addr, socklen_t addrlen) {
    pthread_t thread_stdin_to_net, thread_net_to_stdout;
    struct thread_arg arg_stdin_to_net = {
        .ssl = ssl,
        .other_thread = &thread_net_to_stdout,
        .result = 0
    };
    struct thread_arg arg_net_to_stdout = {
        .ssl = ssl,
        .other_thread = &thread_stdin_to_net,
        .result = 0
    };

    if ((errno = pthread_create(&thread_stdin_to_net, NULL, stdin_to_net, &arg_stdin_to_net)) != 0) {
        perror("Error: pthread_create");
        return ERR_PROC;
    }
    if ((errno = pthread_create(&thread_net_to_stdout, NULL, net_to_stdout, &arg_net_to_stdout)) != 0) {
        perror("Error: pthread_create");
        return ERR_PROC;
    }

    pthread_join(thread_stdin_to_net, NULL);
    pthread_join(thread_net_to_stdout, NULL);

    if (arg_stdin_to_net.result) {
        return arg_stdin_to_net.result;
    }
    if (arg_net_to_stdout.result) {
        return arg_net_to_stdout.result;
    }

    return 0;
}

void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s [OPTIONS...] <hostname> <port>\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "<hostname> is an IPv4 address, an IPv6 address or a hostname.\n");
    fprintf(stderr, "<port> is a TCP port number.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Available options:\n");
    fprintf(stderr, "    -h                      Print this help message.\n");
    fprintf(stderr, "    -k                      After a connection is terminated, listen for another\n");
    fprintf(stderr, "                            one. Requires -l.\n");
    fprintf(stderr, "    -l                      Listen for incoming connections (server mode).\n");
    fprintf(stderr, "                            In this mode, <hostname> and <port> identify the\n");
    fprintf(stderr, "                            interface and port to listen on.\n");
    fprintf(stderr, "    --ca-cert <filename>    Use this CA certificate. Use this option multiple\n");
    fprintf(stderr, "                            times to specify multiple certificates.\n");
    fprintf(stderr, "    --ca-cert-dir <dirname> Scan directory  <dirname> for CA certificates.\n");
    fprintf(stderr, "    --cert <filename>       Use this server certificate. Requires -l.\n");
    fprintf(stderr, "    --key <filename>        Use this server private key. Requires -l.\n");
}

void print_usage_and_exit(const char *progname) {
    print_usage(progname);
    exit(ERR_INVALID_ARGS);
}


int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage_and_exit(argv[0]);
    }

    int server_mode = 0;
    int keep_open_mode = 0;
    struct ca_cert *ca_certs = NULL;
    char *ca_cert_dir = NULL;
    char *server_cert = NULL;
    char *server_key = NULL;
    const char *addr_arg = NULL;
    const char *port_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0' && argv[i][1] != '-') {
            for (char *ch = &argv[i][1]; *ch; ch++) {
                if (*ch == 'l') {
                    server_mode = 1;
                } else if (*ch == 'k') {
                    keep_open_mode = 1;
                } else if (*ch == 'h') {
                    print_usage(argv[0]);
                    exit(0);
                } else {
                    fprintf(stderr, "Error: -%c: unrecognized option\n", *ch);
                    print_usage_and_exit(argv[0]);
                }
            }
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strcmp(argv[i], "--ca-cert") == 0) {
                i++;
                if (i >= argc) {
                    fprintf(stderr, "Error: option --ca-cert requires a parameter\n");
                    print_usage_and_exit(argv[0]);
                }
                struct ca_cert *new_cert = (struct ca_cert *)malloc(sizeof(*new_cert));
                new_cert->filename = argv[i];
                new_cert->next = NULL;
                if (!ca_certs) {
                    ca_certs = new_cert;
                } else {
                    struct ca_cert *last;
                    for (last = ca_certs; last->next; last = last->next);
                    last->next = new_cert;
                }
            } else if (strcmp(argv[i], "--ca-cert-dir") == 0) {
                i++;
                if (i >= argc) {
                    fprintf(stderr, "Error: option --ca-cert-dir requires a parameter\n");
                    print_usage_and_exit(argv[0]);
                }
                ca_cert_dir = argv[i];
            } else if (strcmp(argv[i], "--cert") == 0) {
                i++;
                if (i >= argc) {
                    fprintf(stderr, "Error: option --cert requires a parameter\n");
                    print_usage_and_exit(argv[0]);
                }
                server_cert = argv[i];
            } else if (strcmp(argv[i], "--key") == 0) {
                i++;
                if (i >= argc) {
                    fprintf(stderr, "Error: option --key requires a parameter\n");
                    print_usage_and_exit(argv[0]);
                }
                server_key = argv[i];
            } else if (strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                exit(0);
            }
        } else if (!addr_arg) {
            addr_arg = argv[i];
        } else if (!port_arg) {
            port_arg = argv[i];
        } else {
            fprintf(stderr, "Error: %s: unrecognized argument\n", argv[i]);
            print_usage_and_exit(argv[0]);
        }
    }

#define OPTION_DEPENDENCY(opt1, opt2, opt1name, opt2name) \
        if ((opt1) && !(opt2)) { \
            fprintf(stderr, "Error: option " opt1name " requires " opt2name "\n"); \
            print_usage_and_exit(argv[0]); \
        }

    OPTION_DEPENDENCY(keep_open_mode, server_mode, "-k", "-l");

    OPTION_DEPENDENCY(server_cert, server_mode, "--cert", "-l");
    OPTION_DEPENDENCY(server_key, server_mode, "--key", "-l");

    OPTION_DEPENDENCY(server_mode, server_cert, "-l", "--cert");
    OPTION_DEPENDENCY(server_mode, server_key, "-l", "--key");

    OPTION_DEPENDENCY(server_cert, server_key, "--cert", "--key");
    OPTION_DEPENDENCY(server_key, server_cert, "--key", "--cert");

#undef OPTION_DEPENDENCY

    // Parse address
    struct addrinfo *addrinfo;
    int err;
    if ((err = getaddrinfo(addr_arg, port_arg, NULL, &addrinfo)) != 0) {
        fprintf(stderr, "Error: %s: %s\n", addr_arg, gai_strerror(err));
        exit(ERR_INVALID_ARGS);
    }
    if (addrinfo->ai_family != AF_INET && addrinfo->ai_family != AF_INET6) {
        fprintf(stderr, "Error: %s: invalid address family\n", addr_arg);
        exit(ERR_INVALID_ARGS);
    }

    if (server_mode) {
        wolfcat_server(addrinfo, keep_open_mode, ca_cert_dir, ca_certs, server_cert, server_key);
    } else {
        wolfcat_client(addrinfo, ca_cert_dir, ca_certs);
    }

    {
        struct ca_cert *curr = ca_certs;
        while (curr) {
            struct ca_cert *next = curr->next;
            free(curr);
            curr = next;
        }
    }
}
