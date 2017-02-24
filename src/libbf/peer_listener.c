#include "peer_listener.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
//#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define LISTEN_QUEUE_SIZE 50

static int bind_listener(const uint16_t port)
{
    int sockfd;
    struct addrinfo hints, *listener, *head;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[5];        
    snprintf(port_str, sizeof(port_str), "%04u", port);
    port_str[4] = '\0';

    if(getaddrinfo(NULL, port_str, &hints, &head) < 0)
        goto fail_getaddrinfo;

    for(listener = head; listener; listener = listener->ai_next) {
        if((sockfd = socket(listener->ai_family, listener->ai_socktype, 
            listener->ai_protocol)) < 0) {
            continue;
        }

        int itrue = 1;
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &itrue, sizeof(int)) < 0) {
            close(sockfd);
            continue;
        }

        if(bind(sockfd, listener->ai_addr, listener->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }

        break;
    }

    if(!listener)
        goto fail_bind;

    freeaddrinfo(head);
    return sockfd;

fail_bind:
    printf("fail bind 2\n");
    freeaddrinfo(head);
fail_getaddrinfo:
    printf("fail getaddrinfo\n");
    return -1;
}

static void peer_listen_cleanup(void *arg)
{
    int sockfd = *(int*)arg;
    printf("Closing listener socket %d ....\n", sockfd);
    close(sockfd);
}

static void *peer_listen(void *arg)
{
    int sockfd;
    if((sockfd = bind_listener(*(const uint16_t*)arg)) < 0)
        goto fail_bind;

    if(listen(sockfd, LISTEN_QUEUE_SIZE) < 0)
        goto fail_listen;

    //fcntl(sockfd, F_SETFL, O_NONBLOCK);

    pthread_cleanup_push(peer_listen_cleanup, (void*)&sockfd);

    while(true) {
        printf("Listening for peers...\n");

        struct sockaddr peer;
        socklen_t len = sizeof(peer);
        int peer_sockfd;
        
        /* Cancellation point */
        peer_sockfd = accept(sockfd, &peer, &len);
        if(errno == EAGAIN || errno == EWOULDBLOCK)   
            continue;

        if(peer_sockfd < 0)
            break;
    
        printf("connection accepted!\n");
        //here let a new thread handle the connection to the peer
    }

    pthread_cleanup_pop(0);
    pthread_exit(NULL);

fail_listen:
fail_bind:
    pthread_exit(NULL);
}

int peer_listener_create(pthread_t *thread, const uint16_t *port)
{
    if(pthread_create(thread, NULL, peer_listen, (void*)port))    
        goto fail_create_thread;

    return 0;

fail_create_thread:
    return -1;    
}

