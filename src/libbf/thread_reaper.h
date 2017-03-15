#ifndef THREAD_REAPER_H
#define THREAD_REAPER_H

#include <pthread.h>
#include "list.h"

typedef struct reaper_arg{
    unsigned         reap_interval;
    pthread_mutex_t *torrents_lock;
    list_t          *torrents;
    pthread_mutex_t *unassoc_peer_lock;
    list_t          *unassoc_peers;
}reaper_arg_t;

int thread_reaper_create(pthread_t *thread, reaper_arg_t *arg);

#endif
