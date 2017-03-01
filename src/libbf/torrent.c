#include "torrent.h"
#include "byte_str.h"
#include "log.h"
#include "dl_file.h"
#include "peer_connection.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> //temp
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

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

static int populate_files_from_list(torrent_t *torrent, list_t *files, 
                                    const char *destdir, const char *name)
{
    const unsigned char *entry;
    const char *key;
    const unsigned char *val;

    assert(name);

    char path[256];
    strcpy(path, destdir);
    strcat(path, "/");
    strcat(path, name);
    log_printf(LOG_LEVEL_INFO, "Creating directory: %s\n", path);
    mkdir(path, 0777);

    FOREACH_ENTRY(entry, files) {

        dict_t *filedict = (*(bencode_obj_t**)entry)->data.dictionary;
        unsigned len;

        char path[256];
        strcpy(path, destdir);
        strcat(path, "/");
        strcat(path, name);
        strcat(path, "/");

        FOREACH_KEY_AND_VAL(key, val, filedict) {
            if(!strcmp(key, "length")) {
                len = (*(bencode_obj_t**)val)->data.integer;
            }

            if(!strcmp(key, "path")) {
                int i = 0;
                list_t *pathlist = (*(bencode_obj_t**)val)->data.list;
                const unsigned char *path_entry;
            
                FOREACH_ENTRY(path_entry, pathlist) {
                    char *str = (char*)(*(bencode_obj_t**)path_entry)->data.string->str;
                    strcat(path, str);

                    if(i < list_get_size(pathlist) - 1) {
                        mkdir(path, 0777);
                        strcat(path, "/");
                    }
                    i++;
                }
            }

        }

        dl_file_t *file = dl_file_create_and_open(len, path);
        if(file)
            list_add(torrent->files, (unsigned char*)&file, sizeof(dl_file_t*));
        else
            return -1;
    }
}

static int populate_from_info_dic(torrent_t *torrent, dict_t *info, const char *destdir)
{
    int ret = 0;
    char errbuff[64];

    const char *key;
    const unsigned char *val;

    bool multifile = false;
    const char *name = NULL;
    unsigned len;

    FOREACH_KEY_AND_VAL(key, val, info) {
        if(!strcmp(key, "name")) {
            name = (char*)(*(bencode_obj_t**)val)->data.string->str;
        }
    }

    FOREACH_KEY_AND_VAL(key, val, info) {
        if(!strcmp(key, "pieces")) {
            torrent->pieces = create_piece_list((*(bencode_obj_t**)val)->data.string);
        }

        if(!strcmp(key, "piece length")) {
            torrent->piece_len = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "length")) {
            len = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "files")) {
            multifile = true;

            list_t *files = (*(bencode_obj_t**)val)->data.list;
            if(populate_files_from_list(torrent, files, destdir, name))
                ret = -1;
        }
    }

    if(!multifile) {
        char path[256]; 
        strcpy(path, destdir);
        strcat(path, "/");
        strcat(path, name);

        dl_file_t *file = dl_file_create_and_open(len, path);
        if(file)
            list_add(torrent->files, (unsigned char*)&file, sizeof(dl_file_t*));
        else
            ret = -1;
    }

    if(ret && errno) {
        strerror_r(errno, errbuff, sizeof(errbuff));
        log_printf(LOG_LEVEL_ERROR, "%s\n", errbuff);
    }
    return ret;
}

torrent_t *torrent_init(bencode_obj_t *meta, const char *destdir)
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

            ret->files = list_init();
            populate_from_info_dic(ret, info_dic->data.dictionary, destdir);
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

    pthread_mutex_init(&ret->sh_lock, NULL); 
    ret->sh.peer_connections = list_init();
    ret->sh.priority = DEFAULT_PRIORITY;
    ret->sh.state = TORRENT_STATE_LEECHING;
    ret->sh.progress = 0.0f;
    ret->sh.upspeed = 0.0f;
    ret->sh.downspeed = 0.0f;
    ret->sh.uploaded = 0;  
    ret->sh.downloaded = 0;
    ret->sh.completed = false;
    
    return ret;

fail_alloc:
    return NULL;
}

void torrent_free(torrent_t *torrent)
{
    const unsigned char *entry;

    pthread_mutex_destroy(&torrent->sh_lock);

    FOREACH_ENTRY(entry, torrent->pieces){
        byte_str_free(*(byte_str_t**)entry);
    }
    list_free(torrent->pieces);

    FOREACH_ENTRY(entry, torrent->files){
        dl_file_close_and_free(*(dl_file_t**)entry); 
    }
    list_free(torrent->files);

    FOREACH_ENTRY(entry, torrent->sh.peer_connections) {
        free(*(peer_conn_t**)entry);
    }
    list_free(torrent->sh.peer_connections);

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
    printf("\tpeer connections: %p, size: %u\n", torrent->sh.peer_connections, 
        list_get_size(torrent->sh.peer_connections));
    printf("\tpriority: %u\n", torrent->sh.priority);
    printf("\tstate: %d\n", torrent->sh.state);
    printf("\tprogress: %f\n", torrent->sh.progress);
    printf("\tupspeed: %f\n", torrent->sh.upspeed);
    printf("\tdownspeed: %f\n", torrent->sh.downspeed);
    printf("\tcompleted: %hhd\n", torrent->sh.completed); 
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
