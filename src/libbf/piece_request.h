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

#ifndef PIECE_REQUEST_H
#define PIECE_REQUEST_H

#include <stddef.h>
#include <stdbool.h>
#include "list.h"
#include "torrent.h"

#include <sys/types.h>

typedef struct block_request {
    list_t  *filemems;
    off_t    begin;
    size_t   len;
    bool     completed; 
}block_request_t;

typedef struct piece_request {
    unsigned piece_index;
    list_t  *block_requests;
    unsigned blocks_left;
}piece_request_t;

piece_request_t *piece_request_create(const torrent_t *torrent, unsigned index);
void             piece_request_free(piece_request_t *request);
block_request_t *piece_request_block_at(piece_request_t *request, off_t offset);

#endif
