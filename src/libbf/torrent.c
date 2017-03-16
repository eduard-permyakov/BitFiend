#include "torrent.h"
#include "byte_str.h"
#include "log.h"
#include "dl_file.h"
#include "peer_connection.h"
#include "lbitfield.h"
#include "piece_request.h"
#include "sha1.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> //temp
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

static dict_t *create_piece_dict(byte_str_t *raw);
static int     populate_files_from_list(torrent_t *torrent, list_t *files, 
                                        const char *destdir, const char *name);
static int     populate_from_info_dic(torrent_t *torrent, dict_t *info, const char *destdir);


static dict_t *create_piece_dict(byte_str_t *raw)
{
    assert(raw->size % 20 == 0);
    dict_t *ret = dict_init(raw->size / 20);
    if(!ret)
        goto fail_alloc_dict;

    for(uint32_t i = 0; i < raw->size; i += 20) {
        byte_str_t *entry = byte_str_new(20, raw->str + i);
        if(!entry)
            goto fail_alloc_str;
        char key[9];
        dict_key_for_uint32((i/20), key, sizeof(key));
        dict_add(ret, key, (unsigned char*)&entry, sizeof(byte_str_t*));
    }

    return ret;

fail_alloc_str: ;
    const char *key;
    const unsigned char *val;
    FOREACH_KEY_AND_VAL(key, val, ret){
        byte_str_free(*(byte_str_t**)val);
    }
    dict_free(ret);
fail_alloc_dict:
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

        char path[512];
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
            torrent->pieces = create_piece_dict((*(bencode_obj_t**)val)->data.string);
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

    assert(ret->announce);

    pthread_mutex_init(&ret->sh_lock, NULL); 
    ret->max_peers = DEFAULT_MAX_PEERS;
    ret->sh.peer_connections = list_init();
    ret->sh.piece_states = malloc(dict_get_size(ret->pieces));
    memset(ret->sh.piece_states, PIECE_STATE_NOT_REQUESTED, dict_get_size(ret->pieces));
    ret->sh.pieces_left = dict_get_size(ret->pieces);
    ret->sh.priority = DEFAULT_PRIORITY;
    ret->sh.state = TORRENT_STATE_LEECHING;
    ret->sh.completed = false;

    return ret;

fail_alloc:
    return NULL;
}

void torrent_free(torrent_t *torrent)
{
    const char *key;
    const unsigned char *entry;

    pthread_mutex_destroy(&torrent->sh_lock);

    FOREACH_KEY_AND_VAL(key, entry, torrent->pieces){
        byte_str_free(*(byte_str_t**)entry);
    }
    dict_free(torrent->pieces);
    if(torrent->sh.piece_states)
        free(torrent->sh.piece_states);

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

unsigned char *torrent_make_bitfield(const torrent_t *torrent)
{
    unsigned num_pieces = dict_get_size(torrent->pieces);
    unsigned len = LBITFIELD_NUM_BYTES(num_pieces);
    unsigned char *ret = calloc(len, 1);

    if(!ret)
        return ret;

    for(int i = 0; i < num_pieces; i++) {
        if(torrent->sh.piece_states[i] == PIECE_STATE_HAVE)
            LBITFIELD_SET(i, ret);
    }
    return ret;
}


bool torrent_sha1_verify(const torrent_t *torrent, unsigned index)
{
    assert(index < dict_get_size(torrent->pieces));

    char key[9];
    dict_key_for_uint32((uint32_t)index, key, sizeof(key));
    byte_str_t *piece_hash = *(byte_str_t**)dict_get(torrent->pieces, key);
        
    piece_request_t *pr = piece_request_create(torrent, index);        
    sha1_context_t *ctx = sha1_context_init();

    const unsigned char *entry;
    FOREACH_ENTRY(entry, pr->block_requests){
        block_request_t *br = *(block_request_t**)entry;

        const unsigned char *mementry;
        FOREACH_ENTRY(mementry, br->filemems){
            filemem_t fmem = *(filemem_t*)mementry;

            sha1_update(ctx, fmem.mem, fmem.size);
        }
    }
    unsigned char sha1_digest[DIGEST_LEN];
    sha1_finish(ctx, sha1_digest);

    sha1_context_free(ctx);
    piece_request_free(pr);
    return (memcmp(piece_hash->str, sha1_digest, DIGEST_LEN) == 0);
}

/* TODO: Eventually add keeping of piece frequency in the torrent and change piece selection to 
 * use rarest first algorithm. Also add more fine-grained locking for piece states */
int torrent_next_request(torrent_t *torrent, unsigned char *peer_have_bf, unsigned *out)
{
    unsigned nr, r;
    bool has_nr = false, has_r = false;
    unsigned ret;

    pthread_mutex_lock(&torrent->sh_lock); 
    for(int i = 0; i < dict_get_size(torrent->pieces); i++){

        if(torrent->sh.piece_states[i] == PIECE_STATE_REQUESTED && 
           LBITFIELD_ISSET(i, peer_have_bf)) {
            r = i;
            has_r = true;
        }

        if(torrent->sh.piece_states[i] == PIECE_STATE_NOT_REQUESTED &&
           LBITFIELD_ISSET(i, peer_have_bf)) {
            nr = i;
            has_nr = true;
            break;
        }
    }

    if(!has_nr && !has_r){
        pthread_mutex_unlock(&torrent->sh_lock); 
        return -1;
    }

    ret = has_nr ? nr : r;
    torrent->sh.piece_states[ret] = PIECE_STATE_REQUESTED;

    pthread_mutex_unlock(&torrent->sh_lock); 

    log_printf(LOG_LEVEL_INFO, "Requesting piece: %u\n", has_nr ? nr : r);

    *out = ret; 
    return 0;
}

int torrent_complete(torrent_t *torrent)
{
    pthread_mutex_lock(&torrent->sh_lock);
    torrent->sh.completed = true;
    torrent->sh.state = TORRENT_STATE_SEEDING;
    pthread_mutex_unlock(&torrent->sh_lock);

    const unsigned char *entry;
    FOREACH_ENTRY(entry, torrent->files){
        dl_file_t *file = *(dl_file_t**)entry;
        dl_file_complete(file);
    }
    log_printf(LOG_LEVEL_INFO, "Torrent completed!\n");

    //TODO: send an immediate "completed" event to the tracker at this point
}

unsigned torrent_left_to_download(torrent_t *torrent)
{
    //TODO
    unsigned ret;
    pthread_mutex_lock(&torrent->sh_lock);
    ret = torrent->sh.pieces_left * PEER_REQUEST_SIZE;
    pthread_mutex_unlock(&torrent->sh_lock);
    return ret;
}

unsigned torrent_downloaded(torrent_t *torrent)
{
    //TODO
    return 0;
}

unsigned torrent_uploaded(torrent_t *torrent)
{
    //TOD
    return 0;
}

//temp
void print_torrent(torrent_t *torrent)
{
    printf("TORRENT DETAILS:\n");
    printf("\tpieces: %p, size: %u\n", torrent->pieces, dict_get_size(torrent->pieces));
    printf("\tpiece len: %u\n", torrent->piece_len);
    printf("\tfiles: %p, size: %u\n", torrent->files, list_get_size(torrent->files));
    printf("\tpeer connections: %p, size: %u\n", torrent->sh.peer_connections, 
        list_get_size(torrent->sh.peer_connections));
    printf("\tpriority: %u\n", torrent->sh.priority);
    printf("\tstate: %d\n", torrent->sh.state);
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
