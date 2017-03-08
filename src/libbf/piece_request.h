#ifndef PIECE_REQUEST_H
#define PIECE_REQUEST_H

#include <stddef.h>
#include <stdbool.h>
#include "list.h"
#include "torrent.h"

typedef struct block_request {
    list_t  *filemems;
    bool     completed; 
}block_request_t;

typedef struct piece_request {
    unsigned piece_index;
    list_t  *block_requests;
    unsigned blocks_left;
}piece_request_t;

piece_request_t *piece_request_create(const torrent_t *torrent, unsigned index);
void             piece_request_free(piece_request_t *request);

#endif
