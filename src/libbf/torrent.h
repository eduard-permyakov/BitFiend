#ifndef TORRENT_H
#define TORRENT_H

#include <pthread.h>
#include "list.h"

typedef enum {
    TORRENT_STATE_LEECHING,
    TORRENT_STATE_SEEDING,
    TORRENT_STATE_PAUSED
}torrent_state_t;

typedef struct torrent {
    pthread_mutex_t     torrent_lock;
    list_t             *peices;
    list_t             *files;
    list_t             *peer_connections;
    unsigned            priority;
    torrent_state_t     state;
    float               progress;           /* [0-1] */
    float               upspeed;            /* bits/sec */
    float               downspeed;          /* bits/sec */
    unsigned            uploaded;           /* bytes */ 
    unsigned            downloaded;         /* bytes */
    bool                completed;
    char                info_hash[20];
    char                local_peer_id[20];
    const char         *announce;
    pthread_t           tracker_thread;
    pthread_mutex_t     tracker_cond_mutex;
    pthread_cond_t      tracker_cond_sleep;
}torrent_t;

torrent_t  *torrent_new(void);
void        torrent_free(torrent_t *torrent);
unsigned    torrent_left_to_download(torrent_t *torrent);

#endif
