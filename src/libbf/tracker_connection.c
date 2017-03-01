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

static tracker_announce_request_t *create_tracker_request(const void *arg)
{
    const tracker_arg_t *targ = (tracker_arg_t*)arg;

    tracker_announce_request_t *ret = malloc(sizeof(tracker_announce_request_t));
    if(ret) {
        pthread_mutex_lock(&targ->torrent->torrent_lock);

        ret->has = 0;
        memcpy(ret->info_hash, targ->torrent->info_hash, sizeof(ret->info_hash));
        memcpy(ret->peer_id, g_local_peer_id, sizeof(ret->peer_id));
        ret->port = targ->port;
        ret->uploaded = targ->torrent->uploaded;
        ret->downloaded = targ->torrent->downloaded;
        ret->left = torrent_left_to_download(targ->torrent);
        ret->compact = true;
        SET_HAS(ret, REQUEST_HAS_COMPACT);        

        pthread_mutex_unlock(&targ->torrent->torrent_lock);
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
    
    pthread_mutex_lock(&torrent->torrent_lock);
    list_add(torrent->peer_connections, (unsigned char*)&conn, sizeof(peer_conn_t*));  
    pthread_mutex_unlock(&torrent->torrent_lock);

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
    bool completed;
    unsigned interval;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(periodic_announce_cleanup, arg);

    pthread_mutex_lock(&targ->torrent->torrent_lock);
    completed = targ->torrent->completed;
    pthread_mutex_unlock(&targ->torrent->torrent_lock);

    tracker_announce_request_t *req = create_tracker_request(arg);
    tracker_announce_resp_t *resp;

    req->event = TORRENT_EVENT_STARTED;
    SET_HAS(req, REQUEST_HAS_EVENT);
    resp = tracker_announce(targ->torrent->announce, req);

    tracker_announce_request_free(req);
    if(resp)
        tracker_announce_resp_free(resp);

    while(true) {
        req = create_tracker_request(arg);  

        pthread_mutex_lock(&targ->torrent->torrent_lock);
        if(completed == false && targ->torrent->completed == true) {
            req->event = TORRENT_EVENT_COMPLETED;
            SET_HAS(req, REQUEST_HAS_EVENT);
        }
        completed = targ->torrent->completed;
        pthread_mutex_unlock(&targ->torrent->torrent_lock);

        resp = tracker_announce(targ->torrent->announce, req);

        if(resp) {
            //temp
            extern void print_tracker_response(tracker_announce_resp_t *resp);
            print_tracker_response(resp);
            interval = resp->interval;

            const unsigned char *entry;
            FOREACH_ENTRY(entry, resp->peers) {
                create_peer_connection(*(peer_t**)entry, targ->torrent);
            }
        }else{
            interval = 15;
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

