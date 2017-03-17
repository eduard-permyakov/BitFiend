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

#ifndef BITFIEND_H 
#define BITFIEND_H

#define LIBBF_VER_MAJOR 0
#define LIBBF_VER_MINOR 1
#define LIBBF_VER_PATCH 0

enum{
    BITFIEND_FAILURE = -1,
    BITFIEND_SUCCESS
};

typedef struct bf_stat {
    const char *name;
    unsigned    tot_pieces;
    unsigned    pieces_left; 
}bf_stat_t;

typedef void bf_htorrent_t;

int            bitfiend_init(const char *logfile);
int            bitfiend_shutdown(void);

bf_htorrent_t *bitfiend_add_torrent(const char *metafile, const char *destdir);
int            bitfiend_remove_torrent(bf_htorrent_t *torrent);
int            bitfiend_stat_torrent(bf_htorrent_t *torrent, bf_stat_t *out);

void           bitfiend_foreach_torrent(void (*func)(bf_htorrent_t *torrent, void *arg), void *arg); 

#endif
