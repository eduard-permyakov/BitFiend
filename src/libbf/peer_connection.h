#ifndef PEER_CONNECTION_H
#define PEER_CONNECTION_H

#include <pthread.h>
#include "torrent.h"
#include "peer.h"

typedef struct peer_arg {
    bool        has_torrent;
    torrent_t  *torrent; 
    bool        has_sockfd;
    int         sockfd;
    peer_t      peer;
}peer_arg_t;


typedef struct peer_conn {
    pthread_t   thread;
    peer_t      peer;
}peer_conn_t;

int peer_connection_create(pthread_t *thread, peer_arg_t *arg);

#endif
