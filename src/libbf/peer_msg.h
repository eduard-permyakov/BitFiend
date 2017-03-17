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

#ifndef PEER_MSG_H
#define PEER_MSG_H

#include "byte_str.h"
#include "torrent.h"
#include <stdint.h>

typedef enum {
    MSG_CHOKE           = 0,
    MSG_UNCHOKE         = 1,
    MSG_INTERESTED      = 2,
    MSG_NOT_INTERESTED  = 3,
    MSG_HAVE            = 4,
    MSG_BITFIELD        = 5,
    MSG_REQUEST         = 6,
    MSG_PIECE           = 7,
    MSG_CANCEL          = 8,
    MSG_PORT            = 9,
    MSG_KEEPALIVE,
    MSG_MAX
}msg_type_t;

typedef struct request_msg{
    uint32_t index;
    uint32_t begin;
    uint32_t length;
}request_msg_t;

typedef struct piece_msg{
    uint32_t index;
    uint32_t begin;
    size_t blocklen;
}piece_msg_t;

typedef struct peer_msg {
    msg_type_t type;
    union{
        uint32_t have;
        byte_str_t *bitfield;
        request_msg_t request;
        piece_msg_t piece;
        unsigned listen_port;
    }payload;
}peer_msg_t;

int  peer_send_buff(int sockfd, const char *buff, size_t len);
int  peer_recv_buff(int sockfd, char *buff, size_t len);
int  peer_send_handshake(int sockfd, char infohash[20]);
int  peer_recv_handshake(int sockfd, char outhash[20], char outpeerid[20], bool peer_id);
int  peer_msg_send(int sockfd, peer_msg_t *msg, const torrent_t *torrent);
int  peer_msg_recv(int sockfd, peer_msg_t *out, const torrent_t *torrent);
bool peer_msg_buff_nonempty(int sockfd);

#endif
