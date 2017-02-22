#include "bitfiend.h"
#include "list.h"
#include "peer_id.h"
#include "peer_listener.h"
#include "bencode.h"
#include "torrent.h"
#include "torrent_file.h"

#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_t         s_peer_listener;
static const uint16_t    s_port = 6889; 
static pthread_mutex_t   s_torrents_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t           *s_torrents; 

int bitfiend_init(void)
{
    printf("bitfiend init\n");

    peer_id_create(g_local_peer_id);

    s_torrents = list_init();

#if 0 //temp comment out
    if(peer_listener_create(&s_peer_listener, &s_port))
        goto fail_start_listener;
#endif
    
    return BITFIEND_SUCCESS;

fail_start_listener:
    return BITFIEND_FAILURE;
}

static int shutdown_torrent(torrent_t *torrent)
{
    printf("shutdown torrent: %p\n", torrent);
    if(pthread_cancel(torrent->tracker_conn.thread))
        goto fail_stop_tracker;
    pthread_cond_signal(&torrent->tracker_conn.sleep_cond);

    void *ret;
    pthread_join(torrent->tracker_conn.thread, &ret);

    torrent_free(torrent);
    return BITFIEND_SUCCESS;

fail_stop_tracker:
    return BITFIEND_FAILURE;
}

int bitfiend_shutdown(void)
{
    printf("bitfiend shutdown\n");

    int ret = BITFIEND_SUCCESS;

    if(pthread_cancel(s_peer_listener))
        ret = BITFIEND_FAILURE;

    void *tret;
    pthread_join(s_peer_listener, &tret);

    printf("torrents size: %u\n", list_get_size(s_torrents));
    pthread_mutex_lock(&s_torrents_lock);
    const unsigned char *entry;
    FOREACH_ENTRY(entry, s_torrents) {
        shutdown_torrent(*(torrent_t**)entry);
    }
    list_free(s_torrents);
    pthread_mutex_unlock(&s_torrents_lock);

    return ret;
}

torrent_t *bitfiend_add_torrent(const char *metafile)
{
    printf("bitfiend add torrent\n");
    bencode_obj_t *obj = torrent_file_parse(metafile);
    if(!obj)
        goto fail_parse;

    printf("here\n");
    torrent_t *torrent = torrent_init(obj);
    extern void print_torrent(torrent_t *torrent);
    print_torrent(torrent);

    bencode_free_obj_and_data_recursive(obj);
    if(!torrent)
        goto fail_create;

    tracker_arg_t *arg = malloc(sizeof(tracker_arg_t));
    arg->torrent = torrent;
    arg->port = s_port;
    if(tracker_connection_create(&torrent->tracker_conn.thread, arg))
        goto fail_create;

    pthread_mutex_lock(&s_torrents_lock);
    list_add(s_torrents, (unsigned char*)&torrent, sizeof(torrent_t*));
    pthread_mutex_unlock(&s_torrents_lock);

    return torrent;
    
fail_create:
    printf("fail create\n");
fail_parse:
    return NULL;
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

