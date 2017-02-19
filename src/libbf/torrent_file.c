#include "torrent_file.h"
#include "sha1.h"
#include "tracker_announce.h" //temp

#include <stdlib.h>
#include <stdio.h> //temp
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

    fd = open(path, O_RDONLY);
    if(fd < 0)
        goto fail_open;
    fstat(fd, &stats);

    mem = mmap(NULL, stats.st_size, PROT_READ, MAP_PRIVATE, fd, 0); 
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
fail_map:
    close(fd);
fail_open:
    return NULL;
}

static int torrent_file_close_and_free(torrent_file_t *file)
{
    if(!munmap(file->data, file->size))
        return -1;

    if(!close(file->fd))
        return -1;

    free(file);

    return 0;
}

bencode_obj_t *torrent_file_parse(const char *path)
{
    torrent_file_t *file;
    bencode_obj_t *ret;

    file = torrent_file_open(path);
    if(!file)
        return NULL;

    const char *endptr;
    ret = bencode_parse_object(file->data, &endptr);
    assert(endptr = file->data + file->size);

    torrent_file_close_and_free(file);
    
    return ret;
}

int main(void)
{
    bencode_obj_t *out = torrent_file_parse("/home/eduard/Downloads/ubuntu-16.10-desktop-amd64.iso.torrent");
    if(out)
        printf("Torrent file successfully parsed!\n");

    const char *key;
    const unsigned char *val;
    extern void print_obj(bencode_obj_t *obj);

    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        printf("        Key: %s\n        ", key);
        print_obj((bencode_obj_t*)val);
    }

    // here get data for announcement
    tracker_announce_request_t *req = malloc(sizeof(tracker_announce_request_t));
    assert(req);

    req->has = 0; 
    bencode_obj_t *info_dic = NULL;
    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        if(!strcmp(key, "info")) {
            info_dic = (bencode_obj_t*)val;
            memcpy(req->info_hash, info_dic->sha1, DIGEST_LEN);
            for(int i = 0; i < 20; i++) {
                printf("%02X", info_dic->sha1[i]);
            }
            printf("\n");
            break;
        }
    }
    memcpy(req->peer_id, "-bf0000-125kdpsk15na", 20);
    req->port = 6881;
    req->uploaded = 0;
    req->downloaded = 0;
    req->event = TORRENT_EVENT_STARTED;
    SET_HAS(req, REQUEST_HAS_EVENT);
    req->compact = true;
    SET_HAS(req, REQUEST_HAS_COMPACT);

    FOREACH_KEY_AND_VAL(key, val, info_dic->data.dictionary) {
        if(!strcmp(key, "length")) {
            req->left = ((bencode_obj_t*)val)->data.integer;
            break;
        }
    }

    char *url;
    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        if(!strcmp(key, "announce")) {
            url = BYTE_STR_AS_NULL_TERM_ASCII(((bencode_obj_t*)val)->data.string);
        }
    }

    tracker_announce(url, req);
}
