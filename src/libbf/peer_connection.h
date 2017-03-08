#ifndef PEER_CONNECTION_H
#define PEER_CONNECTION_H

#include <pthread.h>
#include <mqueue.h>
#include "torrent.h"
#include "peer.h"

#define KB                (1 << 10)
#define PEER_REQUEST_SIZE (16 * KB)

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

int  peer_connection_create(pthread_t *thread, peer_arg_t *arg);
void peer_connection_queue_name(pthread_t thread, char *out, size_t len);

#endif
