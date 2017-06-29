/* Minimal Socket (MISO) Wrapper Library */
/* Copyright (c) 2017 Ryan Kerr          */

/* This code is without warranty and is  */
/* only meant for prototyping.           */

#ifndef _LIBMISO_HEADER_
#define _LIBMISO_HEADER_

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

const MISO_ERR MISO_ERR_NONE,// = {0, "No errors"},
               MISO_ERR_DEFT,// = {1, "Initializing"},
               MISO_ERR_INIT,// = {1, "Socket Initialization Failed"},
               MISO_ERR_BIND,// = {2, "Socket Bind Failed"},
               MISO_ERR_CONN,// = {3, "Socket Connect Failed"},
               MISO_ERR_OSSL,// = {4, "SSL Initialization Failed"},
               MISO_ERR_CERT,// = {5, "SSL Certificate Failed"},
               MISO_ERR_SEND,// = {6, "Failed to send"},
               MISO_ERR_RECV,// = {7, "Failed to receive"},
               MISO_ERR_ARRY;// = {8, "Array populated, should be NULL"};

MISO   *miso_new(const char*, const char*);
void    miso_del(MISO*);

int     miso_accept(MISO*, MISO**);
int     miso_error(MISO*);

int     miso_send(MISO*, char*);
int     miso_recv(MISO*);

int     miso_openssl(MISO*, int);

#endif
