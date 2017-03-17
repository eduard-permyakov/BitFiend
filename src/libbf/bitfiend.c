#include "bitfiend.h"
#include "list.h"
#include "peer_id.h"
#include "peer_listener.h"
#include "bencode.h"
#include "torrent.h"
#include "torrent_file.h"
#include "log.h" 
#include "peer_connection.h"
#include "thread_reaper.h"

#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>

static pthread_t         s_peer_listener;
static pthread_t         s_reaper;
static const uint16_t    s_port = 6889; 
static pthread_mutex_t   s_torrents_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t           *s_torrents; 
/* Threads for incoming peer connections which have been created but not yet associated
 * with a particular torrent, which can't be done until after handshaking. Store their handles 
 * here for now, until a torrent_t associates with it and removes the handle from this list */
static pthread_mutex_t   s_unassoc_peerthreads_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t           *s_unassoc_peerthreads;

static bool              s_shutdown = false;
static FILE             *s_logfile;

int bitfiend_init(const char *logfile)
{
    s_logfile = fopen(logfile, "a");
    if(!s_logfile)
        return BITFIEND_FAILURE;

    log_set_lvl(LOG_LEVEL_DEBUG);    
    log_set_logfile(s_logfile);

    peer_id_create(g_local_peer_id);

    s_torrents = list_init();
    s_unassoc_peerthreads = list_init();

    if(peer_listener_create(&s_peer_listener, &s_port))
        goto fail_init;

    reaper_arg_t *arg = malloc(sizeof(reaper_arg_t));    
    if(!arg)
        goto fail_init;
    arg->reap_interval = 5;
    arg->torrents = s_torrents;
    arg->torrents_lock = &s_torrents_lock;
    arg->unassoc_peers = s_unassoc_peerthreads;
    arg->unassoc_peer_lock = &s_unassoc_peerthreads_lock;
    if(thread_reaper_create(&s_reaper, arg)){
        free(arg);
        goto fail_init;
    }
    
    log_printf(LOG_LEVEL_INFO, "BitFiend init successful\n");
    return BITFIEND_SUCCESS;

fail_init:
    log_printf(LOG_LEVEL_ERROR, "BitFiend init error\n");
    return BITFIEND_FAILURE;
}

static int shutdown_torrent(torrent_t *torrent)
{
    pthread_cancel(torrent->tracker_thread);

    const unsigned char *entry;
    void *tret;
    pthread_join(torrent->tracker_thread, &tret);
    assert(tret == PTHREAD_CANCELED);

    pthread_mutex_lock(&torrent->sh_lock);
    const list_iter_t *iter = list_iter_first(torrent->sh.peer_connections);
    pthread_mutex_unlock(&torrent->sh_lock);

    while(iter){
        peer_conn_t *conn = *(peer_conn_t**)(list_iter_get_value(iter));
        void *ret;

        pthread_cancel(conn->thread);
        /* Interrupt any blocking call the peer thread may be waiting on 
         * While they should time out, this results in consistently fast shutdown of the client */
        pthread_kill(conn->thread, SIGINT);
        pthread_join(conn->thread, &ret); 

        pthread_mutex_lock(&torrent->sh_lock);
        iter = list_iter_next(iter);
        pthread_mutex_unlock(&torrent->sh_lock);
    }

    torrent_free(torrent);
    return BITFIEND_SUCCESS;

fail_stop_peer:
fail_stop_tracker:
    return BITFIEND_FAILURE;
}

int bitfiend_shutdown(void)
{
    int ret = BITFIEND_SUCCESS;
    const unsigned char *entry;
    void *tret;

    /* Thread join order matters here.
     * First, join the peer_listener so no new unassociated peers can be added.
     * Next, join unassociated peers, after which a torrent's peer_connections
     * list can only grow if its' tracker_thread gives it peers.
     * Now, iterate over all torrents. Join the tracker thread first. Now no new peer 
     * threads can be spawned which can touch the torrent. Join the torrent's peers last.
     */

    if(pthread_cancel(s_reaper))
        ret = BITFIEND_FAILURE;
    pthread_join(s_reaper, &tret);

    if(pthread_cancel(s_peer_listener))
        ret = BITFIEND_FAILURE;
    pthread_join(s_peer_listener, &tret);

    size_t listsize;
    pthread_mutex_lock(&s_unassoc_peerthreads_lock);
    listsize = list_get_size(s_unassoc_peerthreads);
    pthread_mutex_unlock(&s_unassoc_peerthreads_lock);
    log_printf(LOG_LEVEL_DEBUG, "Cancelling and joining unassociated peer threads. There are %zu\n",
        listsize);

    const list_iter_t *iter = NULL;
    pthread_t curr;
    do {
        /* Remove one entry at a time from the list head. This is so we are not holding the 
         * list lock while we are joining the thread in the list, since the thread being 
         * joined can also hold the lock and remove an entry from the list  */
        pthread_mutex_lock(&s_unassoc_peerthreads_lock);
        iter = list_iter_first(s_unassoc_peerthreads);
        if(iter){
            curr = *(pthread_t*)list_iter_get_value(iter);
            list_remove(s_unassoc_peerthreads, (unsigned char*)&curr);
        }
        pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

        if(iter){
            pthread_cancel(curr);
            pthread_join(curr, NULL);
        }

    }while(iter);

    pthread_mutex_lock(&s_unassoc_peerthreads_lock);
    list_free(s_unassoc_peerthreads);
    pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

    pthread_mutex_lock(&s_torrents_lock);
    FOREACH_ENTRY(entry, s_torrents) {
        shutdown_torrent(*(torrent_t**)entry);
    }
    list_free(s_torrents);
    pthread_mutex_unlock(&s_torrents_lock);

    if(ret == BITFIEND_SUCCESS)
        log_printf(LOG_LEVEL_INFO, "BitFiend shutdown successful\n");
    else
        log_printf(LOG_LEVEL_INFO, "BitFiend shutdown error\n");

    fclose(s_logfile);

    return ret;
}

bf_htorrent_t *bitfiend_add_torrent(const char *metafile, const char *destdir)
{
    char metacopy[strlen(metafile) + 1];
    strcpy(metacopy, metafile);

    char *saveptr, *token, *next;
    token = strtok_r(metacopy, "/", &saveptr);
    while(next = strtok_r(NULL, "/", &saveptr)) {
        token = next;
    }
    /* Now token points to the filename */
    char *trim = strstr(token, ".torrent");
    if(trim)
        *trim = '\0';

    bencode_obj_t *obj = torrent_file_parse(metafile);
    if(!obj)
        goto fail_parse;

    torrent_t *torrent = torrent_init(obj, token, destdir);

    //extern void print_torrent(torrent_t *torrent);
    //print_torrent(torrent);

    bencode_free_obj_and_data_recursive(obj);
    if(!torrent)
        goto fail_create;

    tracker_arg_t *arg = malloc(sizeof(tracker_arg_t));
    arg->torrent = torrent;
    arg->port = s_port;
    if(tracker_connection_create(&torrent->tracker_thread, arg))
        goto fail_create;

    pthread_mutex_lock(&s_torrents_lock);
    list_add(s_torrents, (unsigned char*)&torrent, sizeof(torrent_t*));
    pthread_mutex_unlock(&s_torrents_lock);

    log_printf(LOG_LEVEL_INFO, "Torrent added successfully: %s\n", metafile);
    return torrent;
    
fail_create:
fail_parse:
    log_printf(LOG_LEVEL_ERROR, "Error adding torrent: %s\n", metafile);
    return NULL;
}

int bitfiend_remove_torrent(bf_htorrent_t *torrent)
{
    pthread_mutex_lock(&s_torrents_lock);
    list_remove(s_torrents, (unsigned char*)&torrent);
    pthread_mutex_unlock(&s_torrents_lock);

    shutdown_torrent((torrent_t*)torrent);
}

int bitfiend_stat_torrent(bf_htorrent_t *torrent, bf_stat_t *out)
{
    torrent_t *ptr = (torrent_t*)torrent;

    out->name = ptr->name;
    out->tot_pieces = dict_get_size(ptr->pieces);
    pthread_mutex_lock(&ptr->sh_lock); 
    out->pieces_left = ptr->sh.pieces_left;
    pthread_mutex_unlock(&ptr->sh_lock); 
}

void bitfiend_foreach_torrent(void (*func)(bf_htorrent_t *torrent, void *arg), void *arg)
{
    const unsigned char *entry;

    pthread_mutex_lock(&s_torrents_lock);
    const list_iter_t *iter = list_iter_first(s_torrents);
    pthread_mutex_unlock(&s_torrents_lock);

    while(iter) {
        const list_iter_t *next;

        pthread_mutex_lock(&s_torrents_lock);
        next = list_iter_next(iter);
        pthread_mutex_unlock(&s_torrents_lock);

        torrent_t *torrent = *((torrent_t**)list_iter_get_value(iter));
        func(torrent, arg);

        iter = next;
    }
}

torrent_t *bitfiend_assoc_peer(peer_conn_t *peer, char infohash[20])
{
    const unsigned char *entry;
    torrent_t *ret = NULL;

    pthread_mutex_lock(&s_torrents_lock);
    FOREACH_ENTRY(entry, s_torrents) {
        torrent_t *torrent = *(torrent_t**)entry;

        if(!memcmp(torrent->info_hash, infohash, sizeof(torrent->info_hash))) {

            pthread_mutex_lock(&torrent->sh_lock);
            unsigned num_conns = list_get_size(torrent->sh.peer_connections);
            if(num_conns == torrent->max_peers){
                pthread_mutex_unlock(&torrent->sh_lock);
                ret = NULL;
                break;
            }
            pthread_mutex_unlock(&torrent->sh_lock);

            pthread_mutex_lock(&s_unassoc_peerthreads_lock);
            /* Handle the case if we've already been "chosen" to be joined by the main thread */
            if(!list_contains(s_unassoc_peerthreads, (unsigned char*)&peer->thread)){
                pthread_mutex_unlock(&s_unassoc_peerthreads_lock);
                break;
            }
            list_remove(s_unassoc_peerthreads, (unsigned char*)&peer->thread);
            pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

            pthread_mutex_lock(&torrent->sh_lock);
            list_add(torrent->sh.peer_connections, (unsigned char*)&peer, sizeof(peer_conn_t*));
            ret = torrent;
            pthread_mutex_unlock(&torrent->sh_lock);

            log_printf(LOG_LEVEL_INFO, "Associated incoming peer connection with torrent\n");

            break;
        }
    
    }
    pthread_mutex_unlock(&s_torrents_lock);

    return ret;
}

void bitfiend_add_unassoc_peer(pthread_t thread)
{
    pthread_mutex_lock(&s_unassoc_peerthreads_lock);
    list_add(s_unassoc_peerthreads, (unsigned char*)&thread, sizeof(pthread_t));
    pthread_mutex_unlock(&s_unassoc_peerthreads_lock);
}

int bitfiend_notify_peers_have(torrent_t *torrent, unsigned have_index)
{
    int ret = 0;
    const unsigned char *entry;
    pthread_mutex_lock(&torrent->sh_lock);
        
    FOREACH_ENTRY(entry, torrent->sh.peer_connections) {
        peer_conn_t *conn = *(peer_conn_t**)entry;

        if(pthread_equal(conn->thread, pthread_self()) == 0)
            continue;
        
        char queue_name[64];
        peer_connection_queue_name(conn->thread, queue_name, sizeof(queue_name));
        mqd_t queue = mq_open(queue_name, O_WRONLY | O_NONBLOCK);
        if(queue != (mqd_t)-1) {
            if(mq_send(queue, (char*)&have_index, sizeof(unsigned), 0) && errno != EAGAIN) {
                log_printf(LOG_LEVEL_ERROR, "Failed to send have event to peer threads\n"); 
            }
            mq_close(queue);
        }else{
            ret = -1;
            log_printf(LOG_LEVEL_ERROR, "Could not open queue for sending: %s\n", queue_name);
        }
    }

    pthread_mutex_unlock(&torrent->sh_lock);

    return ret;
}

