#include "tracker_connection.h"
#include "byte_str.h"
#include "tracker_announce.h"
#include "peer_id.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h> //temp

#include <sys/time.h>

static tracker_announce_request_t *create_tracker_request(void *arg)
{
    tracker_arg_t *targ = (tracker_arg_t*)arg;

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

static void *periodic_annouce_cleanup(void *arg)
{
    //send announce with "stopped" event
}

static void *periodic_announce(void *arg)
{
    tracker_arg_t *targ = (tracker_arg_t*)arg;
    bool completed;
    const char *announce;
    unsigned interval;

    pthread_cleanup_push(periodic_annouce_cleanup, arg);

    pthread_mutex_lock(&targ->torrent->torrent_lock);
    completed = targ->torrent->completed;
    announce = targ->torrent->announce;
    pthread_mutex_unlock(&targ->torrent->torrent_lock);

    tracker_announce_request_t *req = create_tracker_request(arg);
    tracker_announce_resp_t *resp;

    req->event = TORRENT_EVENT_STARTED;
    SET_HAS(req, REQUEST_HAS_EVENT);
    resp = tracker_announce(announce, req);

    printf("Received response for tracker announce started event\n");

    free(req);
    free(resp);



    while(true) {
        pthread_testcancel();        

        req = create_tracker_request(arg);  

        pthread_mutex_lock(&targ->torrent->torrent_lock);
        if(completed == false && targ->torrent->completed == true) {
            req->event = TORRENT_EVENT_COMPLETED;
            SET_HAS(req, TORRENT_EVENT_COMPLETED);
        }
        completed = targ->torrent->completed;
        pthread_mutex_unlock(&targ->torrent->torrent_lock);

        resp = tracker_announce(announce, req);

        printf("Received response for periodic tracker annouce\n");

        free(req);
        free(resp);

        //update the peer list of the torrent here
    
        struct timespec wakeup_time;
        struct timeval now;

        gettimeofday(&now, NULL);
        wakeup_time.tv_sec = now.tv_sec + interval;
        wakeup_time.tv_nsec = now.tv_usec * 1000000;

        pthread_mutex_lock(&targ->torrent->tracker_cond_mutex);
        pthread_cond_timedwait(&targ->torrent->tracker_cond_sleep, &targ->torrent->tracker_cond_mutex, 
            &wakeup_time);
        pthread_mutex_unlock(&targ->torrent->tracker_cond_mutex);
    }
    
    pthread_cleanup_pop(0);
    pthread_exit(NULL);
}

int tracker_connection_create(pthread_t *thread, tracker_arg_t *arg)
{
    if(pthread_create(thread, NULL, periodic_announce, (void*)arg));
        goto fail_create_thread;

    return 0;

fail_create_thread:
    return -1;    
}

