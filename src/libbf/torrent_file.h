#ifndef TORRENT_FILE_H
#define TORRENT_FILE_H

#include "bencode.h"

bencode_obj_t *torrent_file_parse(const char *path);

#endif
