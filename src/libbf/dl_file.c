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

#include "dl_file.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct dl_file {
    pthread_mutex_t file_lock;
    size_t size; 
    unsigned char *data;
    char path[];  
};

dl_file_t  *dl_file_create_and_open(size_t size, const char *path)
{
    unsigned char *mem; 
    int fd;
    struct stat stats; 
    char errbuff[64];

    char newpath[512];
    strcpy(newpath, path);
    strcat(newpath, ".incomplete");

    fd = open(path, O_CREAT | O_RDWR, 0777);
    if(fd < 0)
        goto fail_open;

    if(ftruncate(fd, size))
        goto fail_truncate;

    fstat(fd, &stats);
    assert(stats.st_size == size); //temp

    mem = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); 
    if(!mem)
        goto fail_map;
    
    dl_file_t *file = malloc(sizeof(dl_file_t) + strlen(newpath) + 1);   
    if(!file)
        goto fail_alloc;

    pthread_mutex_init(&file->file_lock, NULL);
    file->size = size;
    file->data = mem;
    memcpy(file->path, newpath, strlen(newpath));
    file->path[strlen(newpath)] = '\0';

    rename(path, newpath);

    close(fd);
    log_printf(LOG_LEVEL_INFO, "Successfully (created and) opened file at: %s\n", path);
    return file;

fail_alloc:
    munmap(mem, stats.st_size);
fail_map:
fail_truncate:
    close(fd);
fail_open:
    log_printf(LOG_LEVEL_ERROR, "Unable to (create and) open file at:%s\n", path);
    return NULL;
}

int dl_file_close_and_free(dl_file_t *file)
{
    int ret = 0;
    if(munmap(file->data, file->size))
        ret = -1;

    pthread_mutex_destroy(&file->file_lock);
    free(file);

    return ret;
}

void dl_file_getfilemem(const dl_file_t *file, filemem_t *out)
{
    out->mem = file->data;
    out->size = file->size;
}

int dl_file_complete(dl_file_t* file)
{
    char *trim;
    char oldpath[512];
    strncpy(oldpath, file->path, sizeof(oldpath));
    trim = strstr(file->path, ".incomplete");
    assert(trim && trim > file->path);

    *trim = '\0'; 
    rename(oldpath, file->path);
}

