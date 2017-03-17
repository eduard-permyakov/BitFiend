#ifndef TORRENT_H
#define TORRENT_H

#include <pthread.h>
#include "list.h"
#include "tracker_connection.h"
#include "bencode.h"

#define DEFAULT_PRIORITY 3
#define DEFAULT_MAX_PEERS 50

typedef enum {
    TORRENT_STATE_LEECHING,
    TORRENT_STATE_SEEDING,
    TORRENT_STATE_PAUSED
}torrent_state_t;

typedef enum {
    PIECE_STATE_NOT_REQUESTED,
    PIECE_STATE_REQUESTED,
    PIECE_STATE_HAVE
}piece_state_t;

typedef struct torrent {
    dict_t             *pieces;
    unsigned            piece_len;
    list_t             *files;
    char                info_hash[20];
    char               *name;
    char               *announce;
    char               *comment;
    char               *created_by;
    uint32_t            create_date;
    pthread_t           tracker_thread;
    unsigned            max_peers;
    struct {
    torrent_state_t     state;
    char               *piece_states;
    unsigned            pieces_left;
    list_t             *peer_connections;
    unsigned            priority;           /* [0-6] */
    bool                completed;
    }sh;
    pthread_mutex_t     sh_lock;
}torrent_t;

torrent_t     *torrent_init(bencode_obj_t *meta, const char *name, const char *destdir);
void           torrent_free(torrent_t *torrent);
unsigned char *torrent_make_bitfield(const torrent_t *torrent);
bool           torrent_sha1_verify(const torrent_t *torrent, unsigned index);
/* sh_lock of torrent is taken in this function */
int            torrent_next_request(torrent_t *torrent, unsigned char *peer_have_bf, unsigned *out);
/* sh_lock of torrent is taken in this function */
int            torrent_complete(torrent_t *torrent);

/* sh_lock of torrent is taken in this function */
unsigned       torrent_left_to_download(torrent_t *torrent);
unsigned       torrent_downloaded(torrent_t *torrent);
unsigned       torrent_uploaded(torrent_t *torrent);

#endif
