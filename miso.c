/* Minimal Socket (MISO) Wrapper Library */
/* Copyright (c) 2017 Ryan Kerr          */

/* This code is without warranty and is  */
/* only meant for prototyping.           */

#include "miso.h"

const MISO_ERR MISO_ERR_NONE = {0, "No errors"},
               MISO_ERR_DEFT = {1, "Initializing"},
               MISO_ERR_INIT = {1, "Socket Initialization Failed"},
               MISO_ERR_BIND = {2, "Socket Bind Failed"},
               MISO_ERR_CONN = {3, "Socket Connect Failed"},
               MISO_ERR_OSSL = {4, "SSL Initialization Failed"},
               MISO_ERR_CERT = {5, "SSL Certificate Failed"},
               MISO_ERR_SEND = {6, "Failed to send"},
               MISO_ERR_RECV = {7, "Failed to receive"},
               MISO_ERR_ARRY = {8, "Array populated, should be NULL"};

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
    m->error = MISO_ERR_DEFT;
    
    while(current && m->error.code) {
    
        if(MISO_DEBUG)
            printf("[  new  ] Iterating through address results\n");
        
        m->addr = *current;
        
        if((m->socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            m->error = MISO_ERR_INIT;
        }
        else {
            m->error = MISO_ERR_NONE;
            
            int sra = 1;
            setsockopt(m->socket, SOL_SOCKET, SO_REUSEADDR, &sra, sizeof(sra));
            
            if(!host) {
                
                if(MISO_DEBUG)
                    printf("[  new  ] Establishing host socket\n");
                
                if(bind(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)<0)
                    m->error = MISO_ERR_BIND;
                else
                    listen(m->socket, 16);
                
                if(MISO_DEBUG)
                    printf("[  new  ] %s\n", m->error.code?"Establishing socket failed":"Socket success");
            }
            
            if(host) {
                if(MISO_DEBUG)
                    printf("[  new  ] Attempting connection\n");
                
                if(!connect(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)) {
                    
                    if(MISO_DEBUG)
                        printf("[  new  ] Initial connection has succeeded, moving to ssl\n");
                    
                    m->ssl = SSL_new(m->context);
                    SSL_set_fd(m->ssl, m->socket);
                    
                    if(SSL_connect(m->ssl) != 1) {
                        if(MISO_DEBUG)
                            printf("[  new  ] SSL connection has failed to initialize\n");
                        m->error = MISO_ERR_OSSL;
                    }
                    else {
                        if(MISO_DEBUG)
                            printf("[  new  ] Connection succeeded\n");
                        
                        m->cert = SSL_get_peer_certificate(m->ssl);
                        
                        if(!m->cert)
                            m->error = MISO_ERR_CERT;
                        else
                            m->error = MISO_ERR_NONE;
                    }
                }
                else {
                    m->error = MISO_ERR_CONN;
                }
            }
        }
        
        if(MISO_DEBUG)
            printf("[  new  ] %s\n", m->error.code?"An error occurred, connection destroyed":"Socket ready");
        
        if(m->error.code) {
            close(m->socket);
            m->socket = 0;
        }
        
        current = current->ai_next;
    }
    
    int sra = 1;
    if(m->socket)
        setsockopt(m->socket, SOL_SOCKET, SO_REUSEADDR, &sra, sizeof(int));
    
    freeaddrinfo(result);
    return m;
}

int miso_accept(MISO *s, MISO **r) {
    
    if(s && !s->error.code && r) {
        
        nfds_t nfd = 1;
        struct pollfd pfd = {
            s->socket,
            POLLIN
        };
        
        poll(&pfd, nfd, 1000);
        
        if(MISO_DEBUG)
            printf("[  acc  ] Accepting connections\n");
        
        if(pfd.revents == POLLIN) {
            
            if(MISO_DEBUG)
                printf("[  acc  ] Polling success, initializing connection\n");
            
            MISO *c = (MISO*) malloc(sizeof(MISO));
            *r = c;
            c->socket = accept(s->socket, c->addr.ai_addr, &c->addr.ai_addrlen);
            c->data = NULL;
            
            if(c->socket<0) {
                
                if(MISO_DEBUG)
                    printf("[  acc  ] Failed\n");
                miso_del(c);
                r = NULL;
                c->error = MISO_ERR_INIT;
                return -1;
            }
            else {
                if(MISO_DEBUG)
                    printf("[  acc  ] Establishing SSL\n");
                
                c->context = NULL;
                c->ssl = SSL_new(s->context);
                SSL_set_fd(c->ssl, c->socket);
                
                if(SSL_accept(c->ssl) <1) {
                    if(MISO_DEBUG)
                        printf("[  acc  ] Failed\n");
                    miso_del(c);
                    r = NULL;
                    c->error = MISO_ERR_OSSL;
                    return -1;
                }
                else {
                    if(MISO_DEBUG)
                        printf("[  acc  ] Success!\n");
                    c->error = MISO_ERR_NONE;
                    return 0;
                }
            }
        }
        else {
            if(MISO_DEBUG)
                printf("[  acc  ] Polling failed. Skipping\n");
            return 1;
        }
    }
    
    if(MISO_DEBUG)
        printf("[  acc  ] This should never appear\n");
    return -1;
}

int miso_send(MISO *m, char *r) {
    
    if(m && !m->error.code && m->ssl) {
        
        int size = strlen(r);
        char csize[] = {
            (size&0x00FF),
            ((size&0xFF00)>>8)&0x00FF,
            '\0'
        };
        
        if(MISO_DEBUG)
            printf("[  snd  ] Sending 3 initialization bytes (%d)\n", csize);
        int rsize = SSL_write(m->ssl, csize, 3);
        
        if(rsize > 1) {
            
            if(MISO_DEBUG)
                printf("[  snd  ] Sending message (%s)\n", r);
            int fsize = SSL_write(m->ssl, r, strlen(r));
            
            if(fsize < 0) {
                if(MISO_DEBUG)
                    printf("[  snd  ] Send message skipped\n");
                return 1;
            }
            else if(fsize == 0) {
                if(MISO_DEBUG)
                    printf("[  snd  ] Send message failed\n");
                m->error = MISO_ERR_SEND;
                return -1;
            }
            else {
                if(MISO_DEBUG)
                    printf("[  snd  ] Success\n");
                return 0;
            }
        }
        else if(rsize < 0){
            if(MISO_DEBUG)
                printf("[  snd  ] Send bytes skipped\n");
            return 1;
        }
        else {
            if(MISO_DEBUG)
                printf("[  snd  ] Send bytes failed\n");
            m->error = MISO_ERR_SEND;
            return -1;
        }
    }
    
    if(MISO_DEBUG)
        printf("[  snd  ] Invalid socket/message\n");
    
    return -1;
}

int miso_recv(MISO *m) {
    
    if(m && !m->error.code && m->ssl) {
        
        nfds_t nfd = 1;
        struct pollfd pfd = {
            m->socket,
            POLLIN
        };
        
        poll(&pfd, nfd, 1000);
        
        char csize[3];
        int  rsize = 0;
        int  bytes = 0;
        
        if(pfd.revents == POLLIN) {
            if(MISO_DEBUG)
                printf("[  rcv  ] Polling success, reading bytes\n");
            
            rsize = SSL_read(m->ssl, csize, 3);
        }
        else {
            if(MISO_DEBUG)
                printf("[  rcv  ] Polling failed. Skipping\n");
            return 1;
        }
        
        if(!rsize) {
            if(MISO_DEBUG)
                printf("[  rcv  ] Error receiving\n");
            m->error = MISO_ERR_RECV;
            return -1;
        }
        else if(rsize < 0) {
            if(MISO_DEBUG)
                printf("[  rcv  ] Skipping\n");
            return 1;
        }
        else {
            bytes = csize[0] | csize[1]<<8;
            bytes &= 0xFFFF;
        }
        
        if(bytes) {
            
            if(m->data)
                free(m->data);
            
            m->data = malloc(bytes*sizeof(char));
            for(int i=0; i<bytes; i++)
                m->data[i] = '\0';
            
            if(MISO_DEBUG)
                printf("[  rcv  ] Reading message\n");
            if(SSL_read(m->ssl, m->data, bytes)<1) {
                if(MISO_DEBUG)
                    printf("[  rcv  ] Failed to receive message\n");
                m->error = MISO_ERR_RECV;
                return -1;
            }
            else {
                if(MISO_DEBUG)
                    printf("[  rcv  ] Receiving success\n");
                return 0;
            }
            
            m->data[bytes] = '\0';
        }
        else {
            if(MISO_DEBUG)
                printf("[  rcv  ] No bytes to read, skipping\n");
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
            m->ssl = NULL;
        }
        
        if(m->context) {
            SSL_CTX_free(m->context);
            m->context = NULL;
        }
        
        if(m->socket) {
            close(m->socket);
            m->socket = 0;
        }
        
        if(m->data) {
            free(m->data);
            m->data = NULL;
        }
            
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
