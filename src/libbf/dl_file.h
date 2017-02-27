#ifndef DL_FILE_H
#define DL_FILE_H

#include <stddef.h>

typedef struct dl_file dl_file_t;

dl_file_t  *dl_file_create_and_open(size_t size, const char *path);
int         dl_file_close_and_free(dl_file_t *file);
int         dl_file_write(size_t offset, const unsigned char *data, size_t len);

#endif
