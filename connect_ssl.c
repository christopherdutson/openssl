#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char** argv) {
    if(argc < 2) {
        printf("Please enter a hostname to connect to.\n");
        return -1;
    }

    // create entire context first
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_client_method(); // version?

    ctx = SSL_CTX_new(method);
    if(ctx == NULL) {
        fprintf(stderr, "Error creating context.\n");
        return -1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // change null to verify callback
    SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs");
    if(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
        fprintf(stderr, "Error setting min proto verson\n");
        return -1;
    }

    // set security level and padding
    int level = 2;     // if I put this above 2, it doesn't accept anything
    SSL_CTX_set_security_level(ctx, level);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    size_t block_size = 64;
    SSL_CTX_set_block_padding(ctx, block_size);

    // SSL object
    SSL* ssl = SSL_new(ctx);
    char* hostname = argv[1];
    if(ssl == NULL) {
        fprintf(stderr, "Error creating ssl object.\n");
        return -1;
    }

    if(SSL_set_tlsext_host_name(ssl, hostname) == 0) {
        fprintf(stderr, "Error setting host name.\n");
    }

    if(SSL_set1_host(ssl, hostname) == 0) {
        fprintf(stderr, "Error: Certificate doesn't match host name.\n");
    }

    // set up socket
    int clientfd, rc;
    struct addrinfo hints, *listp, *p;
    char* port = "443";
    
    /* Get a list of potential server addresses */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;  /* Open a connection */
    hints.ai_flags = AI_NUMERICSERV;  /* ... using a numeric port arg. */
    hints.ai_flags |= AI_ADDRCONFIG;  /* Recommended for connections */
    if ((rc = getaddrinfo(hostname, port, &hints, &listp)) != 0) {
        fprintf(stderr, "getaddrinfo failed (%s:%s): %s\n", hostname, port, gai_strerror(rc));
        return -2;
    }
    
    for (p = listp; p; p = p->ai_next) {
        if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) 
            continue;
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1) 
            break; /* Success */
        if (close(clientfd) < 0) {
            fprintf(stderr, "open_clientfd: close failed: %s\n", strerror(errno));
            return -1;
        } 
    } 

    freeaddrinfo(listp);
    if (!p) return -1;

    int sockopt_flag = 1;
    setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, (char *)&sockopt_flag, sizeof(int));
    
    if(SSL_set_fd(ssl, clientfd) == 0) {
        fprintf(stderr, "Error setting file descriptor to ssl object.\n");
        // return or free?
    }

    if(SSL_connect(ssl) < 1) {
        fprintf(stderr, "Error performing TLS handshake.\n");
        return -1;
    }

    X509* cert;
    cert = SSL_get_peer_certificate(ssl);
    if(cert == NULL) {
        fprintf(stderr, "Can't access valid certificate.\n");
        return X509_V_ERR_APPLICATION_VERIFICATION;
    }

    long verify_result = SSL_get_verify_result(ssl);
    ERR_print_errors_fp(stdout);
    if(X509_V_OK == verify_result) {
        printf("Certificate looks good!\n");
    }
    else {
        fprintf(stderr, "Error: %s\n", X509_verify_cert_error_string(verify_result));
    }

    // clean up
    unsigned long err_message = ERR_peek_error();
    if(err_message == 0) {
        printf("No errors were found!\n");
    } 
    else {
        fprintf(stderr, "Error: %ld should be dealt with.\n", err_message);
    }
    if(SSL_shutdown(ssl) < 0) { // returning 0 here
        fprintf(stderr, "SSL did not shut down correctly.\n");
    }
    close(clientfd);
    X509_free(cert);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}