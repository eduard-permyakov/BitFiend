#include "bitfiend.h"
#include "list.h"
#include "peer_id.h"
#include "peer_listener.h"

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>



static pthread_t         s_peer_listener;
static const uint16_t    s_port = 6889; 
static list_t           *s_torrents;



int bitfiend_init(void)
{
    printf("bitfiend init\n");

    peer_id_create(g_local_peer_id);
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

