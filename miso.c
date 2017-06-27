#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <poll.h>

typedef struct {
    
    int code;
    const char *msg;
    
} MISO_ERR;

const MISO_ERR MISO_ERR_NONE = {0, "No errors"},
               MISO_ERR_INIT = {1, "Socket Initialization Failed"},
               MISO_ERR_BIND = {2, "Socket Bind Failed"},
               MISO_ERR_CONN = {3, "Socket Connect Failed"},
               MISO_ERR_OSSL = {4, "SSL Initialization Failed"},
               MISO_ERR_CERT = {5, "SSL Certificate Failed"},
               MISO_ERR_SEND = {6, "Failed to send"},
               MISO_ERR_RECV = {7, "Failed to receive"},
               MISO_ERR_ARRY = {8, "Array populated, should be NULL"};

typedef struct {
    
    int             type;
    int             state;
    int             port;
    struct addrinfo addr;
    int             socket;
    SSL             *ssl;
    SSL_CTX         *context;
    X509            *cert;
    MISO_ERR        error;
    char            *data;
    
} MISO;

int miso_openssl(MISO *m, int init) {
    
    if(!m)
        return -1;
    
    const SSL_METHOD *method;
    
    switch(init) {
        case 1:
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_ssl_algorithms();
            
            break;
            
        case 0:
            method = m->type? TLS_server_method() : TLS_client_method();
            
            if(!method) {
                m->error = MISO_ERR_OSSL;
                return -1;
            }
            
            if(!m->context && method)
                m->context = SSL_CTX_new(method);
            
            if(!m->context) {
                m->error = MISO_ERR_OSSL;
                return -1;
            }
            
            if(m->type) {
            
                int a = SSL_CTX_use_certificate_file(m->context, "cert.pem", SSL_FILETYPE_PEM);
                int b = SSL_CTX_use_PrivateKey_file(m->context, "key.pem", SSL_FILETYPE_PEM);
                
                if(a<1 || b<1) {
                    m->error = MISO_ERR_CERT;
                    return -1;
                }
            }
            break;
            
        case -1:
            if(!m->context)
                SSL_CTX_free(m->context);
            break;
    }
    
    return 0;
}

MISO *miso_new(const char *host, const char *port) {
    
    if(atoi(port) < 1)
        return NULL;
    
    struct addrinfo hints = {
        !host?AI_PASSIVE:0,
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP,
        0,
        NULL,
        NULL,
        NULL
    };
    
    struct addrinfo *result, *current;
    getaddrinfo(host, port, &hints, &result);
    
    MISO *m = (MISO*) malloc(sizeof(MISO));
    *m = (MISO){
        host?0:1,
        0,
        atoi(port),
        hints,
        -1,
        NULL,
        NULL,
        NULL,
        MISO_ERR_NONE,
        NULL,
    };
    
    if(miso_openssl(m, 1) || miso_openssl(m, 0)) {
        freeaddrinfo(result);
        return m;
    }
    
    current = result;
    
    while(current && !m->error.code) {
        
        m->addr = *current;
        printf("current\n");
        
        if((m->socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            m->error = MISO_ERR_INIT;
        }
        else {
            m->error = MISO_ERR_NONE;
            
            if(!host) {
                if(bind(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)<0)
                    m->error = MISO_ERR_BIND;
                else
                    listen(m->socket, 16);
            }
            
            if(host) {
                printf("connect\n");
                if(!connect(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)) {
                    
                    printf("passed\n");
                    m->ssl = SSL_new(m->context);
                    SSL_set_fd(m->ssl, m->socket);
                    
                    if(SSL_connect(m->ssl) != 1) {
                        printf("Error here\n");
                        m->error = MISO_ERR_OSSL;
                    }
                    else {
                        m->cert = SSL_get_peer_certificate(m->ssl);
                        
                        if(!m->cert)
                            m->error = MISO_ERR_CERT;
                    }
                }
                else {
                    m->error = MISO_ERR_CONN;
                }
            }
        }
        
        current = current->ai_next;
    }
    
    freeaddrinfo(result);
    return m;
}

int miso_accept(MISO *s, MISO *c) {
    
    if(s && !s->error.code && !c) {
        
        nfds_t nfd = 1;
        struct pollfd pfd = {
            s->socket,
            POLLIN
        };
        
        poll(&pfd, nfd, 1000);
        
        if(pfd.revents == POLLIN) {
            
            MISO *c = (MISO*) malloc(sizeof(MISO));
            c->socket = accept(s->socket, c->addr.ai_addr, &c->addr.ai_addrlen);
            
            if(c->socket<0) {
                c->error = MISO_ERR_INIT;
                return -1;
            }
            else {
                c->context = NULL;
                c->ssl = SSL_new(s->context);
                SSL_set_fd(c->ssl, c->socket);
                
                if(SSL_accept(c->ssl) <1) {
                    c->error = MISO_ERR_OSSL;
                    return -1;
                }
                else {
                    return 0;
                }
            }
        }
        else {
            return 1;
        }
    }
    
    return -1;
}

int miso_send(MISO *m, char *r) {
    
    if(m && !m->error.code && m->ssl
    && SSL_write(m->ssl, r, strlen(r))<1) {
        
        m->error = MISO_ERR_SEND;
        return -1;
    }
    
    return 0;
}

int miso_recv(MISO *m) {
    
    if(m && !m->error.code && m->ssl) {
        
        int bytes = SSL_pending(m->ssl);
        
        if(bytes) {
            
            if(m->data)
                free(m->data);
            
            m->data = malloc(bytes*sizeof(char));
            
            if(SSL_read(m->ssl, m->data, bytes)<1) {
                m->error = MISO_ERR_RECV;
                return -1;
            }
            else {
                return 1;
            }
        }
        else {
            return 1;
        }
    }
    
    return -1;
}

void miso_del(MISO *m) {
    
    if(m) {
        
        if(m->ssl) {
            while(!SSL_shutdown(m->ssl));
            SSL_free(m->ssl);
        }
        
        if(m->context)
            SSL_CTX_free(m->context);
        
        if(m->socket)
            close(m->socket);
        
        if(m->data)
            free(m->data);
            
        free(m);
    }
}

int miso_error(MISO *m) {
    
    if(m && m->error.code) {
        printf("=== Error ===\n");
        printf("%03d: %s\n", m->error.code, m->error.msg);
        printf("%03d: %s\n", errno, strerror(errno));
        ERR_print_errors_fp(stderr);
    }
    
    return m? m->error.code : -1;
}

int main() {
    
    MISO *m = miso_new("0.71.218.148", "80");
    miso_error(m);
    miso_del(m);
}
