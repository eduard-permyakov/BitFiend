#include "stats.h"
#include "dict.h"
#include "peer_connection.h"
#include "queue.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include <sys/time.h>

#define SAMPLE_PERIOD_USEC 1000000


typedef enum {
    BW_UPLOAD,
    BW_DOWNLOAD 
}bw_type_t;

typedef struct torr_stat{
    unsigned long  total_up;
    unsigned long  total_down;
    unsigned long  start_time_us;
    /* Keep the number of uploaded/downloaded bytes in the last
     * 'sample interval' for calculating instantaneous rates */
    unsigned long  last_sample_start_us;
    unsigned long  last_sample_up;
    unsigned long  last_sample_down;
    /* These are for the rates of the previous 'sample interval' */
    unsigned long  prev_sample_interval_us;
    unsigned long  prev_sample_up;
    unsigned long  prev_sample_down;
}torr_stat_t;


static dict_t          *s_thread_torr_table;
static pthread_mutex_t  s_thread_torr_table_lock = PTHREAD_MUTEX_INITIALIZER;

static dict_t          *s_torr_stat_table;
static pthread_mutex_t  s_torr_stat_table_lock = PTHREAD_MUTEX_INITIALIZER;


static torr_stat_t *torr_stat_new(void);
static void torr_stat_free(torr_stat_t *torr_stat);
static void torrent_to_key(const torrent_t *torrent, char *out);
static void stats_log(bw_type_t type, unsigned nbytes);
static unsigned long ts_usec(void);


static torr_stat_t *torr_stat_new(void)
{
    torr_stat_t *ret = malloc(sizeof(torr_stat_t));
    if(!ret){
        return NULL;
    }

    ret->total_up = 0UL;
    ret->total_down = 0UL;
    /* Time of registering is taken to be time that torrent has 'started' */
    ret->start_time_us = ts_usec();
    ret->last_sample_start_us = ts_usec();
    ret->last_sample_up = 0;
    ret->last_sample_down = 0;

    return ret;
}

static void torr_stat_free(torr_stat_t *torr_stat)
{
    free(torr_stat); 
}

static void torrent_to_key(const torrent_t *torrent, char *out)
{
    memcpy(out, &torrent, sizeof(torrent_t*));
    out[sizeof(torrent_t*)] = '\0';
}

static void stats_log(bw_type_t type, unsigned nbytes)
{
    unsigned char *val;
    torrent_t *torrent = NULL;
    
    char thread_key[64];
    peer_connection_queue_name(pthread_self(), thread_key, sizeof(thread_key)); 

    /* Fetch the torrent for this thread */
    pthread_mutex_lock(&s_thread_torr_table_lock);
    if(val = dict_get(s_thread_torr_table, thread_key)){
        torrent = *(torrent_t**)val;
    }
    pthread_mutex_unlock(&s_thread_torr_table_lock);

    /* There is no torrent associated with this thread until after handshaking */
    if(!torrent)
        return;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    /* And update the thread's stats */
    pthread_mutex_lock(&s_torr_stat_table_lock);

    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);

    if(type == BW_UPLOAD){
        stat->total_up += nbytes;
        stat->last_sample_up += nbytes;
    }else {
        stat->total_down += nbytes;
        stat->last_sample_down += nbytes;
    }

    unsigned long curr = ts_usec();
    unsigned long diff;
    if((diff = curr - stat->last_sample_start_us) > SAMPLE_PERIOD_USEC) {
        stat->prev_sample_interval_us = diff;
        stat->prev_sample_up = stat->last_sample_up;
        stat->prev_sample_down = stat->last_sample_down;

        stat->last_sample_start_us = curr;
        stat->last_sample_up = 0;
        stat->last_sample_down = 0;
    }

    pthread_mutex_unlock(&s_torr_stat_table_lock);
}

static unsigned long ts_usec(void)
{
    struct timeval tv; 
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000ul + tv.tv_usec);
}

int stats_init(void)
{
    s_thread_torr_table = dict_init(256);
    if(!s_thread_torr_table)
        return -1;

    s_torr_stat_table = dict_init(32);
    if(!s_torr_stat_table){
        dict_free(s_thread_torr_table);
        return -1;
    }

    return 0;
}

void stats_shutdown(void)
{
    dict_free(s_thread_torr_table); 

    const char *key;
    const unsigned char *val;
    FOREACH_KEY_AND_VAL(key, val, s_torr_stat_table){
        torr_stat_free(*(torr_stat_t**)val);
    }

    dict_free(s_torr_stat_table);
}

void stats_register(pthread_t thread, const torrent_t *torrent)
{
    char thread_key[64];
    /* The thread queue name is already a unique string representation of the thread id */
    peer_connection_queue_name(thread, thread_key, sizeof(thread_key)); 
    
    /* Add thread:torrent mapping */
    pthread_mutex_lock(&s_thread_torr_table_lock);
    dict_add(s_thread_torr_table, thread_key, (unsigned char*)&torrent, sizeof(torrent_t*));
    pthread_mutex_unlock(&s_thread_torr_table_lock);

    log_printf(LOG_LEVEL_INFO, "Registered thread for torrent: %s\n", torrent->name);
}

void stats_unregister(pthread_t thread, const torrent_t *torrent)
{
    char thread_key[64];
    /* The thread queue name is already a unique string representation of the thread id */
    peer_connection_queue_name(thread, thread_key, sizeof(thread_key)); 

    /* Remove thread:torrent mapping */
    pthread_mutex_lock(&s_thread_torr_table_lock);
    dict_remove(s_thread_torr_table, thread_key);
    pthread_mutex_unlock(&s_thread_torr_table_lock);   

    log_printf(LOG_LEVEL_INFO, "Unregistered thread for torrent: %s\n", torrent->name);
}

void stats_add_entry(const torrent_t *torrent)
{
    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    /* Add torrent:stat mapping */
    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = torr_stat_new();        
    dict_add(s_torr_stat_table, torrent_key, (unsigned char*)&stat, sizeof(torrent_t*));
    pthread_mutex_unlock(&s_torr_stat_table_lock);
}

void stats_remove_entry(const torrent_t *torrent)
{
    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    /* Add torrent:stat mapping */
    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = torr_stat_new();        
    dict_remove(s_torr_stat_table, torrent_key);
    pthread_mutex_unlock(&s_torr_stat_table_lock);
}

ssize_t stats_send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t ret = send(sockfd, buf, len, flags);
    if(ret > 0){
        stats_log(BW_UPLOAD, ret);
    }
    return ret;
}

ssize_t stats_recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t ret = recv(sockfd, buf, len, flags);
    if(ret > 0){
        stats_log(BW_DOWNLOAD, ret);
    }
    return ret;
}

double stats_up_instrate(const torrent_t *torrent)
{
    unsigned long tot_bits = 0;
    unsigned long tot_usecs;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    tot_bits = stat->prev_sample_up * CHAR_BIT;
    tot_usecs = stat->prev_sample_interval_us;
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    return tot_bits/(tot_usecs/1000000.0f);
}

double stats_up_avgrate(const torrent_t *torrent)
{
    unsigned long tot_bits;
    unsigned long tot_usecs;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    tot_bits = stat->total_up * CHAR_BIT;
    tot_usecs = (ts_usec() - stat->start_time_us);
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    assert(tot_usecs > 0);
    return ((double)tot_bits)/(tot_usecs/1000000);
}

unsigned long stats_up_total(const torrent_t *torrent)
{
    unsigned long ret;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    ret = stat->total_up;
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    return ret;
}

double stats_down_instrate(const torrent_t *torrent)
{
    unsigned long tot_bits = 0;
    unsigned long tot_usecs;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    tot_bits = stat->prev_sample_down * CHAR_BIT;
    tot_usecs = stat->prev_sample_interval_us;
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    return tot_bits/(tot_usecs/1000000.0f);
}

double stats_down_avgrate(const torrent_t *torrent)
{
    unsigned long tot_bits;
    unsigned long tot_usecs;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    tot_bits = stat->total_down * CHAR_BIT;
    tot_usecs = (ts_usec() - stat->start_time_us);
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    assert(tot_usecs > 0);
    return ((double)tot_bits)/(tot_usecs/1000000);
}

unsigned long stats_down_total(const torrent_t *torrent)
{
    unsigned long ret;

    char torrent_key[sizeof(torrent_t*) + 1];
    torrent_to_key(torrent, torrent_key);

    pthread_mutex_lock(&s_torr_stat_table_lock);
    torr_stat_t *stat = *(torr_stat_t**)dict_get(s_torr_stat_table, torrent_key);
    ret = stat->total_down;
    pthread_mutex_unlock(&s_torr_stat_table_lock);

    return ret;
}

