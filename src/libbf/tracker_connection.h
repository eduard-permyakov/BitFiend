#ifndef TRACKER_CONNECTION_H
#define TRACKER_CONNECTION_H

#include <pthread.h>
#include <stdint.h>

struct torrent;

typedef struct tracker_arg {
    struct torrent *torrent;    
    uint16_t port;
}tracker_arg_t;

int tracker_connection_create(pthread_t *thread, tracker_arg_t *arg);

#endif
