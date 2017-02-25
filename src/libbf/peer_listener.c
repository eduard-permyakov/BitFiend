#include "peer_listener.h"
#include "log.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

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
    log_printf(LOG_LEVEL_INFO, "Successfully bound peer listener socket (fd: %d) on port %hd\n", 
        sockfd, port);
    return sockfd;

fail_bind:
    freeaddrinfo(head);
fail_getaddrinfo:
    return -1;
}

static void peer_listen_cleanup(void *arg)
{
    int sockfd = *(int*)arg;
    log_printf(LOG_LEVEL_INFO, "Closing peer listener socket (fd: %d)\n", sockfd);
    close(sockfd);
}

static void *peer_listen(void *arg)
{
    int sockfd;
    char errbuff[64];

    if((sockfd = bind_listener(*(const uint16_t*)arg)) < 0)
        goto fail_bind;

    if(listen(sockfd, LISTEN_QUEUE_SIZE) < 0)
        goto fail_listen;

    pthread_cleanup_push(peer_listen_cleanup, (void*)&sockfd);

    while(true) {
        log_printf(LOG_LEVEL_INFO, "Listening for incoming peer connections...\n");

        struct sockaddr peer;
        socklen_t len = sizeof(peer);
        int peer_sockfd;
        
        /* Cancellation point */
        peer_sockfd = accept(sockfd, &peer, &len);
        if(errno == EAGAIN || errno == EWOULDBLOCK)   
            continue;

        if(peer_sockfd < 0)
            break;
    
        log_printf(LOG_LEVEL_INFO, "Peer connection accepted\n");
        //here let a new thread handle the connection to the peer
    }

    pthread_cleanup_pop(0);
    pthread_exit(NULL);

fail_listen:
fail_bind:
    if(errno){
        strerror_r(errno, errbuff, sizeof(errbuff));
        log_printf(LOG_LEVEL_ERROR, "%s", errbuff);
    }
    pthread_exit(NULL);
}

int peer_listener_create(pthread_t *thread, const uint16_t *port)
{
    if(pthread_create(thread, NULL, peer_listen, (void*)port))    
        goto fail_create_thread;

    return 0;

fail_create_thread:
    log_printf(LOG_LEVEL_ERROR, "Failed to create peer listener thread\n");
    return -1;    
}

