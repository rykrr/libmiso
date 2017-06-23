#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <poll.h>

typedef struct {
    
    int code;
    const char *msg;
    
} MISO_ERR;

const MISO_ERR MISO_ERR_NONE = {0, "No errors"},
               MISO_ERR_INIT = {1, "Socket Initialization Failed"},
               MISO_ERR_BIND = {2, "Socket Bind Failed"},
               MISO_ERR_CONN = {3, "Socket Connect Failed"},
               MISO_ERR_OSSL = {4, "SSL Initialization Failed"};

typedef struct {
    
    int             state;
    int             port;
    struct addrinfo addr;
    int             socket;
    SSL_CTX         *context;
    MISO_ERR        error;
    
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
            method = SSLv23_server_method();
            
            if(!method) {
                m->error = MISO_ERR_OSSL;
                return -1;
            }
            break;
            
        case 0:
            if(!m->context)
                m->context = SSL_CTX_new(method);
            
            if(!m->context) {
                m->error = MISO_ERR_OSSL;
                return -1;
            }
            break;
            
        case -1:
            if(!m->context)
                SSL_CTX_free(m->context);
            break;
    }
}

MISO *miso_genmiso(const char *host, const char *port) {
    
    if(atoi(port) < 1)
        return NULL;
    
    struct addrinfo hints = {
        AI_PASSIVE,
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
        0,
        atoi(port),
        hints,
        -1,
        NULL,
        MISO_ERR_NONE,
    };
    
    current = result;
    
    while(current && !m->error.code) {
        
        m->addr = *current;
        
        if((m->socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            m->error = MISO_ERR_INIT;
        }
        else {
            if(!host && bind(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)<0)
                m->error = MISO_ERR_BIND;
            
            else if(host && connect(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)<0)
                m->error = MISO_ERR_CONN;
            
            else
                m->error = MISO_ERR_NONE;
        }
        
        current = current->ai_next;
    }
    
    
    freeaddrinfo(result);
    return m;
}

int miso_accept(MISO *m) {
    
    
}

int misodel(MISO *m) {
    
    if(m)
        free(m);
    
    //if(m->error.code == 0)
        close(m->socket);
}

int main() {
    
}
