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

#ifndef THREAD_REAPER_H
#define THREAD_REAPER_H

#include <pthread.h>
#include "list.h"

typedef struct reaper_arg{
    unsigned         reap_interval;
    pthread_mutex_t *torrents_lock;
    list_t          *torrents;
    pthread_mutex_t *unassoc_peer_lock;
    list_t          *unassoc_peers;
}reaper_arg_t;

int thread_reaper_create(pthread_t *thread, reaper_arg_t *arg);

#endif
