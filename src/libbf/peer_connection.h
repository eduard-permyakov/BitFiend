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

#ifndef PEER_CONNECTION_H
#define PEER_CONNECTION_H

#include <pthread.h>
#include <mqueue.h>
#include "torrent.h"
#include "peer.h"

#define KB                (1 << 10)
#define PEER_REQUEST_SIZE (16 * KB)

typedef struct peer_arg {
    bool        has_torrent;
    torrent_t  *torrent; 
    bool        has_sockfd;
    int         sockfd;
    peer_t      peer;
}peer_arg_t;


typedef struct peer_conn {
    pthread_t   thread;
    peer_t      peer;
}peer_conn_t;

int  peer_connection_create(pthread_t *thread, peer_arg_t *arg);
void peer_connection_queue_name(pthread_t thread, char *out, size_t len);

#endif
