#include "torrent.h"
#include "byte_str.h"
#include "log.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> //temp

static list_t *create_piece_list(byte_str_t *raw)
{
    const unsigned char *entry;
    list_t *ret = list_init();
    if(!ret)
        goto fail_alloc_list;

    assert(raw->size % 20 == 0);
    for(int i = 0; i < raw->size; i += 20) {
        byte_str_t *entry = byte_str_new(20, raw->str + i);
        if(!entry)
            goto fail_alloc_str;
        list_add(ret, (unsigned char*)&entry, sizeof(byte_str_t*));
    }

    return ret;

fail_alloc_str:
    FOREACH_ENTRY(entry, ret) {
        byte_str_free(*(byte_str_t**)entry);
    }   
    list_free(ret);
fail_alloc_list:
    return NULL;
}

static void populate_from_info_dic(torrent_t *ret, dict_t *info)
{
    const char *key;
    const unsigned char *val;

    FOREACH_KEY_AND_VAL(key, val, info) {
        if(!strcmp(key, "pieces")) {
            ret->pieces = create_piece_list((*(bencode_obj_t**)val)->data.string);
        }

        if(!strcmp(key, "piece length")) {
            ret->piece_len = (*(bencode_obj_t**)val)->data.integer;
        }
    }
}

torrent_t *torrent_init(bencode_obj_t *meta)
{
    torrent_t *ret = malloc(sizeof(torrent_t));
    if(!ret)
        goto fail_alloc;

    const char *key;
    const unsigned char *val;

    memset(ret, 0, sizeof(*ret));
    FOREACH_KEY_AND_VAL(key, val, meta->data.dictionary) {

        if(!strcmp(key, "info")) {
            bencode_obj_t *info_dic = *((bencode_obj_t**)val);
            memcpy(ret->info_hash, info_dic->sha1, DIGEST_LEN);

            populate_from_info_dic(ret, info_dic->data.dictionary);
        }

        if(!strcmp(key, "announce")) {
            byte_str_t *bstr = (*(bencode_obj_t**)val)->data.string;
            ret->announce = malloc(bstr->size + 1);      
            memcpy(ret->announce, bstr->str, bstr->size);
            ret->announce[bstr->size] = '\0';
        }

        if(!strcmp(key, "comment")) {
            byte_str_t *bstr = (*(bencode_obj_t**)val)->data.string;
            ret->comment = malloc(bstr->size + 1);      
            memcpy(ret->comment, bstr->str, bstr->size);
            ret->comment[bstr->size] = '\0';
        }

        if(!strcmp(key, "created by")) {
            byte_str_t *bstr = (*(bencode_obj_t**)val)->data.string;
            ret->created_by = malloc(bstr->size + 1);      
            memcpy(ret->created_by, bstr->str, bstr->size);
            ret->created_by[bstr->size] = '\0';
        }

        if(!strcmp(key, "creation date")) {
            ret->create_date = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "announce-list")) {
            log_printf(LOG_LEVEL_WARNING, "Ignoring announce-list key in metainfo file\n");
            //TODO
        }

        if(!strcmp(key, "encoding")) {
            log_printf(LOG_LEVEL_WARNING, "Ignoring encoding key in metainfo file\n");
            //assert(0);
            //TODO
        }

    }

    pthread_mutex_init(&ret->torrent_lock, NULL); 
    //TODO: populate files list with data from info dic
    ret->files = list_init();
    ret->peer_connections = list_init();
    ret->priority = DEFAULT_PRIORITY;
    ret->state = TORRENT_STATE_LEECHING;
    ret->progress = 0.0f;
    ret->upspeed = 0.0f;
    ret->downspeed = 0.0f;
    ret->uploaded = 0;  
    ret->downloaded = 0;
    ret->completed = false;
    
    return ret;

fail_alloc:
    return NULL;
}

void torrent_free(torrent_t *torrent)
{
    const unsigned char *entry;

    pthread_mutex_destroy(&torrent->torrent_lock);

    FOREACH_ENTRY(entry, torrent->pieces){
        byte_str_free(*(byte_str_t**)entry);
    }
    list_free(torrent->pieces);

    FOREACH_ENTRY(entry, torrent->files){
        //TODO
    }
    list_free(torrent->files);

    FOREACH_ENTRY(entry, torrent->peer_connections) {
        //TODO
    }
    list_free(torrent->peer_connections);

    if(torrent->announce) 
        free(torrent->announce);

    if(torrent->comment)    
        free(torrent->comment);

    if(torrent->created_by)
        free(torrent->created_by);

    free(torrent);
}

unsigned torrent_left_to_download(torrent_t *torrent)
{
    return 0;
}

//temp
void print_torrent(torrent_t *torrent)
{
    printf("TORRENT DETAILS:\n");
    printf("\tpieces: %p, size: %u\n", torrent->pieces, list_get_size(torrent->pieces));
    printf("\tpiece len: %u\n", torrent->piece_len);
    printf("\tfiles: %p, size: %u\n", torrent->files, list_get_size(torrent->files));
    printf("\tpeer connections: %p, size: %u\n", torrent->peer_connections, 
        list_get_size(torrent->peer_connections));
    printf("\tpriority: %u\n", torrent->priority);
    printf("\tstate: %d\n", torrent->state);
    printf("\tprogress: %f\n", torrent->progress);
    printf("\tupspeed: %f\n", torrent->upspeed);
    printf("\tdownspeed: %f\n", torrent->downspeed);
    printf("\tcompleted: %hhd\n", torrent->completed); 
    printf("\tinfo hash: ");
    for(int i = 0; i < 20; i++) {
        printf("%02X", (unsigned char)torrent->info_hash[i]); 
    }
    printf("\n");
    printf("\tannounce: %s\n", torrent->announce);
    printf("\tcomment: %s\n", torrent->comment);
    printf("\tcreated by: %s\n", torrent->created_by);
    printf("\tcreate date: %u\n", torrent->create_date);
}
