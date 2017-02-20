#include "bitfiend.h"
#include "list.h"
#include "byte_str.h"
#include "peer_id.h"
#include "peer_listener.h"

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

typedef enum {
    TORRENT_STATE_LEECHING,
    TORRENT_STATE_SEEDING,
    TORRENT_STATE_PAUSED
}torrent_state_t;

struct torrent {
    pthread_mutex_t torrent_lock;
    list_t *peices;
    list_t *files;
    list_t *peer_connections;
    //tracker_conn_t *tracker;
    unsigned priority;
    torrent_state_t state;
    float progress;     // [0-1]
    float upspeed;      // bytes/sec
    float downspeed;    // bytes/sec
};

typedef struct downloaded_file {
    unsigned size; 
    char *path;
    unsigned char MD5[16]; //Optional
}downloaded_file_t;



static pthread_t s_peer_listener;
static const uint16_t s_port = 6889;

static byte_str_t *s_peer_id;
static list_t *s_torrents;



int bitfiend_init(void)
{
    printf("bitfiend init\n");

    s_peer_id = peer_id_get_new();
    s_torrents = list_init();

    if(peer_listener_create(&s_peer_listener, &s_port))
        goto fail_start_listener;
    
    return BITFIEND_SUCCESS;

fail_start_listener:
    return BITFIEND_FAILURE;
}

int bitfiend_shutdown(void)
{
    printf("bitfiend shutdown\n");

    byte_str_free(s_peer_id);
    list_free(s_torrents);

    if(pthread_cancel(s_peer_listener))
        goto fail_stop_listener;

    void *ret;
    pthread_join(s_peer_listener, &ret);

    return BITFIEND_SUCCESS;

fail_stop_listener:
    return BITFIEND_FAILURE;
}

torrent_t *bitfiend_add_torrent(const char *metafile)
{

}

int bitfiend_start_torrent(torrent_t *torrent)
{

}

int bitfiend_pause_torrent(torrent_t *torrent)
{

}

int bitfiend_set_priority(torrent_t *torrent)
{

}

int bitfiend_remove_torrent(torrent_t *torrent)
{

}

