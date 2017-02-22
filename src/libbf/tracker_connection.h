#ifndef TRACKER_CONNECTION_H
#define TRACKER_CONNECTION_H

#include <pthread.h>
#include <stdint.h>

struct torrent;

typedef struct tracker_arg {
    struct torrent *torrent;    
    uint16_t port;
}tracker_arg_t;

typedef struct tracker_conn {
    pthread_t thread;
    pthread_mutex_t cond_mutex;
    pthread_cond_t sleep_cond;
}tracker_conn_t;

int tracker_connection_create(pthread_t *thread, tracker_arg_t *arg);

#endif
