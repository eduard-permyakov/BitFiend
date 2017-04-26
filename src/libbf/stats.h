#ifndef STATS_H 
#define STATS_H 

#include <pthread.h>
#include <sys/types.h>
#include "torrent.h"

int           stats_init(void);
void          stats_shutdown(void);

/* Add/remove torrent:stats mapping */
void          stats_add_entry(const torrent_t *torrent);
void          stats_remove_entry(const torrent_t *torrent);

/* Add/remove thread:torrent mapping */
void          stats_register(pthread_t thread, const torrent_t *torrent);
void          stats_unregister(pthread_t thread, const torrent_t *torrent);

/* Wrappers around send/recv to update appropriate stats for torrent */
ssize_t       stats_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t       stats_recv(int sockfd, void *buf, size_t len, int flags);

double        stats_up_instrate(const torrent_t *torrent);    /* bits/sec */
double        stats_up_avgrate(const torrent_t *torrent);     /* bits/sec */
unsigned long stats_up_total(const torrent_t *torrent);       /* bytes */
double        stats_down_instrate(const torrent_t *torrent);  /* bits/sec */
double        stats_down_avgrate(const torrent_t *torrent);   /* bits/sec*/
unsigned long stats_down_total(const torrent_t *torrent);     /* bytes */

#endif

