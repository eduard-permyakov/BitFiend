/*    
 *  This file is part of BitFiend. 
 *  Copyright (C) 2017 Eduard Permyakov 
 *
 *  BitFiend is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BitFiend is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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

