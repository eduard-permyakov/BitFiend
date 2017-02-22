#ifndef TORRENT_H
#define TORRENT_H

#include <pthread.h>
#include "list.h"
#include "tracker_connection.h"
#include "bencode.h"

#define DEFAULT_PRIORITY 3

typedef enum {
    TORRENT_STATE_LEECHING,
    TORRENT_STATE_SEEDING,
    TORRENT_STATE_PAUSED
}torrent_state_t;

typedef struct torrent {
    pthread_mutex_t     torrent_lock;
    list_t             *pieces;
    unsigned            piece_len;
    list_t             *files;
    list_t             *peer_connections;
    unsigned            priority;           /* [0-6] */
    torrent_state_t     state;
    float               progress;           /* [0-1] */
    float               upspeed;            /* bits/sec */
    float               downspeed;          /* bits/sec */
    unsigned            uploaded;           /* bytes */ 
    unsigned            downloaded;         /* bytes */
    bool                completed;
    char                info_hash[20];
    char               *announce;
    char               *comment;
    char               *created_by;
    uint32_t            create_date;
    tracker_conn_t      tracker_conn;
}torrent_t;

torrent_t  *torrent_init(bencode_obj_t *meta);
void        torrent_free(torrent_t *torrent);
unsigned    torrent_left_to_download(torrent_t *torrent);

#endif
