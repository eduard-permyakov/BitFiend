#ifndef BITFIEND_H 
#define BITFIEND_H

#include "torrent.h"
//TODO change api to return void pointer

enum{
    BITFIEND_FAILURE = -1,
    BITFIEND_SUCCESS
};

int         bitfiend_init(void);
int         bitfiend_shutdown(void);

torrent_t   *bitfiend_add_torrent(const char *metafile);
int         bitfiend_start_torrent(torrent_t *torrent);
int         bitfiend_pause_torrent(torrent_t *torrent);
int         bitfiend_set_priority(torrent_t *torrent);
int         bitfiend_remove_torrent(torrent_t *torrent);

#endif
