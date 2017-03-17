#include "tracker_connection.h"
#include "torrent.h"
#include "byte_str.h"
#include "tracker_announce.h"
#include "peer_id.h"
#include "log.h"
#include "peer_connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h> //temp
#include <unistd.h> //temp

#include <sys/time.h>

#define TRACKER_RETRY_INTERVAL 15

static tracker_announce_request_t *create_tracker_request(const void *arg)
{
    const tracker_arg_t *targ = (tracker_arg_t*)arg;

    tracker_announce_request_t *ret = malloc(sizeof(tracker_announce_request_t));
    if(ret) {

        ret->has = 0;
        memcpy(ret->info_hash, targ->torrent->info_hash, sizeof(ret->info_hash));
        memcpy(ret->peer_id, g_local_peer_id, sizeof(ret->peer_id));
        ret->port = targ->port;
        ret->compact = true;
        SET_HAS(ret, REQUEST_HAS_COMPACT);        

        pthread_mutex_lock(&targ->torrent->sh_lock);
        unsigned num_conns = list_get_size(targ->torrent->sh.peer_connections);
        pthread_mutex_unlock(&targ->torrent->sh_lock);

        ret->numwant = targ->torrent->max_peers - num_conns;
        SET_HAS(ret, REQUEST_HAS_NUMWANT);        

        ret->uploaded = torrent_uploaded(targ->torrent);
        ret->downloaded = torrent_downloaded(targ->torrent);
        ret->left = torrent_left_to_download(targ->torrent);
    }

    return ret;
}

static int create_peer_connection(peer_t *peer, torrent_t *torrent)
{
    peer_conn_t *conn = malloc(sizeof(peer_conn_t));            
    if(!conn)
        return -1;
    conn->peer = *peer;

    peer_arg_t *arg = malloc(sizeof(peer_arg_t));    
    if(!arg) {
        free(conn);
        return -1;
    }
    arg->torrent = torrent;
    arg->has_torrent = true;
    arg->has_sockfd = false;
    arg->peer = *peer;

    if(peer_connection_create(&conn->thread, arg))
        goto fail_create;
    
    pthread_mutex_lock(&torrent->sh_lock);

    unsigned num_conns = list_get_size(torrent->sh.peer_connections);
    if(num_conns == torrent->max_peers) {
        pthread_mutex_unlock(&torrent->sh_lock);
        free(arg);
        free(conn);
        return 0;
    }

    list_add(torrent->sh.peer_connections, (unsigned char*)&conn, sizeof(peer_conn_t*));  
    pthread_mutex_unlock(&torrent->sh_lock);

    return 0;

fail_create:
    log_printf(LOG_LEVEL_ERROR, "Failed to create peer thread\n");
    free(arg);
    free(conn);
    return -1;
}

static void periodic_announce_cleanup(void *arg)
{
    log_printf(LOG_LEVEL_INFO, "Sending one last \"stopped\" event to tracker\n");
    const tracker_arg_t *targ = (tracker_arg_t*)arg;

    tracker_announce_request_t *req = create_tracker_request(arg);
    req->event = TORRENT_EVENT_STOPPED;
    SET_HAS(req, REQUEST_HAS_EVENT);
    
    tracker_announce_resp_t *resp = tracker_announce(targ->torrent->announce, req);

    tracker_announce_request_free(req);
    if(resp)
        tracker_announce_resp_free(resp);
    free(arg);
}

static void *periodic_announce(void *arg)
{
    const tracker_arg_t *targ = (tracker_arg_t*)arg;
    bool completed = false;
    unsigned interval;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(periodic_announce_cleanup, arg);

    pthread_mutex_lock(&targ->torrent->sh_lock);
    completed = targ->torrent->sh.completed;
    pthread_mutex_unlock(&targ->torrent->sh_lock);

    bool started = false;
    while(true) {
        tracker_announce_request_t *req = create_tracker_request(arg);
        tracker_announce_resp_t *resp;

        if(!started){
            req->event = TORRENT_EVENT_STARTED;
            SET_HAS(req, REQUEST_HAS_EVENT);
            started = true;
        }

        pthread_mutex_lock(&targ->torrent->sh_lock);
        bool read_completed = targ->torrent->sh.completed;
        pthread_mutex_unlock(&targ->torrent->sh_lock);

        if(completed == false && read_completed == true) {
            req->event = TORRENT_EVENT_COMPLETED;
            SET_HAS(req, REQUEST_HAS_EVENT);
        }
        completed = read_completed;

        resp = tracker_announce(targ->torrent->announce, req);

        if(resp) {
            //extern void print_tracker_response(tracker_announce_resp_t *resp);
            //print_tracker_response(resp);

            interval = resp->interval;
            log_printf(LOG_LEVEL_DEBUG, "Re-announcing to tracker again in %d seconds\n", interval);

            const unsigned char *entry;
            FOREACH_ENTRY(entry, resp->peers) {
                create_peer_connection(*(peer_t**)entry, targ->torrent);
            }
        }else{
            interval = TRACKER_RETRY_INTERVAL;
            log_printf(LOG_LEVEL_INFO, "Retrying announcing to tracker in %d seconds\n", interval);
        }

        tracker_announce_request_free(req);
        if(resp)
            tracker_announce_resp_free(resp);

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        /* Cancellation point */
        sleep(interval);
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    }
    
    pthread_cleanup_pop(0);
}

int tracker_connection_create(pthread_t *thread, tracker_arg_t *arg)
{
    int rv;
    if(pthread_create(thread, NULL, periodic_announce, (void*)arg))
        goto fail_create_thread;

    return 0;

fail_create_thread:
    return -1;    
}

