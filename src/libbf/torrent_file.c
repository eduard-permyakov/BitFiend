#include "torrent_file.h"
#include "sha1.h"
#include "tracker_announce.h" //temp
#include "peer_id.h" //temp

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
    torrent_file_close_and_free(file);
    return NULL;
}

void tracker_callback(byte_str_t *resp)
{
    printf("Tracker response received!\n");
    
    bencode_obj_t *obj;
    const char *endptr;
    obj = bencode_parse_object(resp->str, &endptr);
    assert(obj);

    const char *key;
    const unsigned char *val;
    extern void print_obj(bencode_obj_t *obj);

    FOREACH_KEY_AND_VAL(key, val, obj->data.dictionary) {
        printf("        Key: %s\n        ", key);
        print_obj(*((bencode_obj_t**)val));
    }

    bencode_free_obj_and_data_recursive(obj);
    byte_str_free(resp);
}

int main(void)
{
    bencode_obj_t *out = torrent_file_parse("/home/eduard/Downloads/ubuntu.torrent");
    if(out)
        printf("Torrent file successfully parsed!\n");

    const char *key;
    const unsigned char *val;
    extern void print_obj(bencode_obj_t *obj);

    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        printf("        Key: %s\n        ", key);
        print_obj(*((bencode_obj_t**)val));
    }

    // here get data for announcement
    tracker_announce_request_t *req = malloc(sizeof(tracker_announce_request_t));
    assert(req);

    req->has = 0; 
    bencode_obj_t *info_dic = NULL;
    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        if(!strcmp(key, "info")) {
            info_dic = *((bencode_obj_t**)val);
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
            req->left = (*((bencode_obj_t**)val))->data.integer;
            break;
        }
    }

    char *url;
    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)out)->data.dictionary) {
        if(!strcmp(key, "announce")) {
            url = (char*)((*((bencode_obj_t**)val))->data.string->str);
        }
    }

    tracker_announce(url, req, tracker_callback);
    bencode_free_obj_and_data_recursive(out);
    free(req);
}
