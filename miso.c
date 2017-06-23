#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>

typedef struct {
    
    int code;
    const char *msg;
    
} MISO_ERR;

const MISO_ERR MISO_ERR_NONE = {0, "No errors"},
               MISO_ERR_INIT = {1, "Socket Initialization Failed"},
               MISO_ERR_BIND = {2, "Socket Bind Failed"},
               MISO_ERR_OSSL = {3, "SSL Initialization Failed"};

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
            break;
        case 0:
            m->context = SSL_CTX_new(method);
            break;
        case -1:
            break;
    }
}

MISO *miso_genserver(int port) {
    
    if(port < 1)
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
    getaddrinfo(NULL, "9090", &hints, &result);
    
    MISO *m = (MISO*) malloc(sizeof(MISO));
    *m = (MISO){
        0,
        port,
        hints,
        -1,
        NULL,
        MISO_ERR_NONE,
    };
    
    current = result;
    
    while(current && !m->error.code) {
        
        m->addr = *current;
        
        if((m->socket = socket(PF_INET, SOCK_STREAM, 0)) < 0)
            m->error = MISO_ERR_INIT;
        else
            if(bind(m->socket, m->addr.ai_addr, m->addr.ai_addrlen)<0)
                m->error = MISO_ERR_BIND;
            else
                m->error = MISO_ERR_NONE;
        
        current = current->ai_next;
        printf("%d\n", (current && !m->error.code));
        printf("%d\n", m->error.code);
    }
    
    freeaddrinfo(result);
    return m;
}

int miso_listen(MISO *m) {
    
    
}

int misodel(MISO *m) {
    
    if(m)
        free(m);
    
    //if(m->error.code == 0)
        close(m->socket);
}

int main() {
    
    //MISO *m = miso_genserver(1024);
    miso_openssl(NULL, 1);
    //printf("%d\n", m->error);
    //printf("%d: %s\n", m->error.code, m->error.msg);
    //misodel(m);
}
