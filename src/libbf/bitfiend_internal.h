#ifndef BITFIEND_INTERNAL_H
#define BITFIEND_INTERNAL_H

#include "torrent.h"
#include <pthread.h>

torrent_t *bitfiend_assoc_peer(peer_conn_t *peer, char infohash[20]);
void       bitfiend_add_unassoc_peer(pthread_t thead);
int        bitfiend_notify_peers_have(torrent_t *torrent, unsigned have_index);

#endif
