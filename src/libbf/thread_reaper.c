#include "thread_reaper.h"
#include "log.h"
#include "torrent.h"
#include "peer_connection.h"

#include <stdlib.h>
#include <unistd.h>

void reap_periodic_cleanup(void *arg)
{
    free(arg);
}

static void *reap_periodic(void *arg)
{
    reaper_arg_t *rarg = (reaper_arg_t*)arg;
    pthread_cleanup_push(reap_periodic_cleanup, arg);{

    while(true) {

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        sleep(rarg->reap_interval);
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        /* Reap unassociated peers */
        pthread_mutex_lock(rarg->unassoc_peer_lock);

        const list_iter_t *iter = list_iter_first(rarg->unassoc_peers);
        while(iter) {
            pthread_t thread = *(pthread_t*)list_iter_get_value(iter);
            iter = list_iter_next(iter);

            void *ret;
            if(pthread_tryjoin_np(thread, &ret) == 0){

                list_remove(rarg->unassoc_peers, (unsigned char*)&thread);
                log_printf(LOG_LEVEL_INFO, "Reaped exited unassociated peer thread\n");  
            }
        }
        pthread_mutex_unlock(rarg->unassoc_peer_lock);

        /* Reap associateed peers */
        pthread_mutex_lock(rarg->torrents_lock);
        const unsigned char *entry;
        FOREACH_ENTRY(entry, rarg->torrents){
            torrent_t *torrent = *(torrent_t**)entry;

            pthread_mutex_lock(&torrent->sh_lock);

            const list_iter_t *iter = list_iter_first(torrent->sh.peer_connections);
            while(iter){
                peer_conn_t *conn = *(peer_conn_t**)list_iter_get_value(iter);
                iter = list_iter_next(iter);

                void *ret;
                if(pthread_tryjoin_np(conn->thread, &ret) == 0) {

                    list_remove(torrent->sh.peer_connections, (unsigned char*)&conn);  
                    log_printf(LOG_LEVEL_ERROR, "Reaped exited peer thread\n");
                }
            }
            pthread_mutex_unlock(&torrent->sh_lock);

        }
        pthread_mutex_unlock(rarg->torrents_lock);
    }

    }pthread_cleanup_pop(0);

}

int thread_reaper_create(pthread_t *thread, reaper_arg_t *arg)
{
    if(pthread_create(thread, NULL, reap_periodic, arg))    
        goto fail_create_thread;

    return 0;

fail_create_thread:
    log_printf(LOG_LEVEL_ERROR, "Failed to create reaper thread\n");
    return -1;    

}

