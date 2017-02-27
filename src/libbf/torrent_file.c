#include "torrent_file.h"

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>


typedef struct torrent_file{
    int fd;
    size_t size;
    unsigned char *data;
}torrent_file_t;

static torrent_file_t *torrent_file_open(const char *path)
{
    unsigned char *mem; 
    int fd;
    struct stat stats; 

    fd = open(path, O_RDWR);
    if(fd < 0)
        goto fail_open;
    fstat(fd, &stats);

    mem = mmap(NULL, stats.st_size, PROT_READ, MAP_SHARED, fd, 0); 
    if(!mem)
        goto fail_map;
    
    torrent_file_t *file = malloc(sizeof(torrent_file_t));   
    if(!file)
        goto fail_alloc;

    file->fd = fd;
    file->size = stats.st_size;
    file->data = mem;

    return file;

fail_alloc:
    munmap(file->data, file->size);
fail_map:
    close(fd);
fail_open:
    return NULL;
}

static int torrent_file_close_and_free(torrent_file_t *file)
{
    if(munmap(file->data, file->size))
        goto fail;

    if(!close(file->fd))
        goto fail;

    free(file);
    return 0;

fail:
    free(file);
    return -1;
}

bencode_obj_t *torrent_file_parse(const char *path)
{
    torrent_file_t *file;
    bencode_obj_t *ret;

    file = torrent_file_open(path);
    if(!file)
        goto fail_open;

    const char *endptr;
    ret = bencode_parse_object(file->data, &endptr);
    assert(endptr = file->data + file->size);

    torrent_file_close_and_free(file);
    return ret;

fail_open:
    return NULL;
}

