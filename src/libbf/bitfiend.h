#ifndef BITFIEND_H 
#define BITFIEND_H

#define LIBBF_VER_MAJOR 0
#define LIBBF_VER_MINOR 1

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
