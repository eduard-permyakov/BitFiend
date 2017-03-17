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

#include "piece_request.h"
#include "dl_file.h"
#include "peer_connection.h"

#include <stdlib.h>
#include <assert.h>

static void skip_until_index(const list_iter_t **iter, off_t *offset, unsigned index, const torrent_t *torrent)
{
    size_t skip = torrent->piece_len * index;
    while(skip > 0) {
        dl_file_t *file = *((dl_file_t**)list_iter_get_value(*iter));
        assert(file);
        filemem_t mem;        
        dl_file_getfilemem(file, &mem);

        /* This is the last file to skip*/
        if(mem.size > skip) {
            *offset = skip;
            return;
        }else{
            skip -= mem.size;
            *iter = list_iter_next(*iter);
        }
    }
}

static block_request_t *next_block_request(const list_iter_t **iter, off_t *offset, size_t *left, 
                                           size_t piecelen)
{
    if(!*iter || *left == 0)
        return NULL;

    block_request_t *ret = malloc(sizeof(block_request_t));    
    ret->begin = piecelen - *left;
    ret->completed = false;
    ret->len = 0;
    if(!ret)
        return NULL;
    ret->filemems = list_init();
    if(!ret->filemems){
        free(ret);
        return NULL;
    }

    unsigned curr_size = 0;

    do {
        dl_file_t *file = *((dl_file_t**)list_iter_get_value(*iter));
        assert(file);
        filemem_t  mem; 
        dl_file_getfilemem(file, &mem);

        mem.mem = ((char*)mem.mem + *offset);
        mem.size -= *offset;

        if(mem.size > PEER_REQUEST_SIZE - curr_size){
            mem.size = PEER_REQUEST_SIZE - curr_size;
            *offset += mem.size;
        }else{
            *iter = list_iter_next(*iter);
            *offset = 0;
        }

        *left -= mem.size;
        list_add(ret->filemems, (unsigned char*)&mem, sizeof(filemem_t));
        curr_size += mem.size;


    }while(curr_size < PEER_REQUEST_SIZE && *iter != NULL);

    ret->len = curr_size;
    return ret;
}

piece_request_t *piece_request_create(const torrent_t *torrent, unsigned index)
{
    piece_request_t *ret = malloc(sizeof(piece_request_t)); 
    if(!ret)
        return NULL;

    ret->block_requests = list_init();
    if(!ret->block_requests)
        goto fail_alloc_list;

    ret->piece_index = index;

    const list_iter_t *iter = list_iter_first(torrent->files);
    assert(iter);
    block_request_t   *block;
    size_t             left = torrent->piece_len;
    off_t              offset = 0; /* How many bytes at the start of the file 
                                    * at the iterator have already been 'consumed' */
    skip_until_index(&iter, &offset, index, torrent);

    while(block = next_block_request(&iter, &offset, &left, torrent->piece_len)) {
        list_add(ret->block_requests, (unsigned char*)&block, sizeof(block_request_t*));
    }

    ret->blocks_left = list_get_size(ret->block_requests);
    return ret;

fail_alloc_entry: ;
    const unsigned char *entry;
    FOREACH_ENTRY(entry, ret->block_requests) {
        free(*(filemem_t**)entry);  
    }
fail_alloc_list:
    free(ret);
    return NULL;
}

void piece_request_free(piece_request_t *request)
{
    const unsigned char *entry;
    FOREACH_ENTRY(entry, request->block_requests) {
        block_request_t *br = *(block_request_t**)entry;
        list_free(br->filemems); /* The filemems are copied into the list, 
                                  * no additional heap freeing necessary */
        free(br);
    }
    free(request);
}

block_request_t *piece_request_block_at(piece_request_t *request, off_t offset)
{
    const unsigned char *entry;
    FOREACH_ENTRY(entry, request->block_requests) {
        block_request_t *req = *(block_request_t**)entry;
    
        if(req->begin == offset)
            return req;
    }
    return NULL;
}

