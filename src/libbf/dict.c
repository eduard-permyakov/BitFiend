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

#include "dict.h"

#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h> 
#include <limits.h>
#include <assert.h>

#define FOREACH_ENTRY_IN_BIN(_entry, _dict_ptr, _bin) \
    for(dict_entry_t *_entry = _dict_ptr->bins[_bin]; _entry; _entry = _entry->next)

#define FOREACH_ENTRY_AND_PREV_IN_BIN(_entry, _prev, _dict_ptr, _bin) \
    for(dict_entry_t *_entry = _dict_ptr->bins[_bin], *_prev = NULL; _entry; \
    _prev = _entry, _entry = _entry->next)

#define SET_TO_LAST_ENTRY(entry_ptr, dict_ptr, bin) \
    do { \
        entry_ptr = dict_ptr->bins[bin]; \
        while(entry_ptr->next) \
            entry_ptr = entry_ptr->next; \
    }while(0)
    

typedef struct dict_entry{
    struct dict_entry *next;
    char *key;
    size_t size;
    unsigned char value[];    
}dict_entry_t;

struct dict{
    unsigned size;
    unsigned binsize;
    dict_entry_t **bins;
};

// DICT ENTRY START

static dict_entry_t *dict_entry_init(const char *key, void *value, size_t size)
{
    dict_entry_t *ret = malloc(sizeof(dict_entry_t) + size);
    if(ret) {
        ret->key = malloc(strlen(key) + 1);
        if(!ret->key) {
            free(ret);
            return NULL;
        }
        memcpy(ret->key, key, strlen(key) + 1);
        ret->size = size;
        ret->next = NULL;
        memcpy(ret->value, value, size);
    }
    return ret;
}

static void dict_entry_free(dict_entry_t *entry)
{
    free(entry->key);
    free(entry);
}

// DICT ENTRY END

static unsigned hashf(size_t binsize, const char *key)
{
    long sum = 0;
    const char *cursor = key;
    size_t keylen = strlen(key);

    /* Sum string as sequence of integers */
    while(cursor < key + keylen) {
        int tmp = 0;
        int len =  (cursor + sizeof(int) > key + keylen) ? (key + keylen - cursor) : sizeof(int);
        memcpy(&tmp, cursor, len); 
        sum += tmp; 
        cursor += len;
    }
    
    return abs(sum) % binsize;
}

dict_t *dict_init(size_t binsize)
{
    dict_t *ret = malloc(sizeof(dict_t));
    if(ret) {
        ret->size = 0;
        ret->binsize = binsize;
        ret->bins = calloc(binsize, sizeof(dict_entry_t*));
        if(!ret->bins) {
            free(ret);
            ret = NULL; 
        }
    }
    return ret;
}

void dict_free(dict_t *dict)
{
    for(unsigned i = 0; i < dict->binsize; i++){
        FOREACH_ENTRY_AND_PREV_IN_BIN(entry, prev, dict, i) {
            if(prev){
                dict_entry_free(prev);
            }
            if(!entry->next){
                dict_entry_free(entry);
                break;
            }
        }
    }
    free(dict->bins);
    free(dict);
}

int dict_add(dict_t *dict, const char *key, unsigned char *data, size_t size)
{
    unsigned hash = hashf(dict->binsize, key);
    dict_entry_t *entry = dict_entry_init(key, data, size);

    if(!entry)
        return -1;

    if(dict_get(dict, key)){
        dict_remove(dict, key);
    }

    if(!dict->bins[hash]) {
        dict->bins[hash] = entry;
    }else{
        dict_entry_t *curr;
        SET_TO_LAST_ENTRY(curr, dict, hash);
        curr->next = entry;
    }
    dict->size++;
    return 0;
}

unsigned char *dict_get(dict_t *dict, const char *key)
{
    unsigned hash = hashf(dict->binsize, key);
    FOREACH_ENTRY_IN_BIN(entry, dict, hash) {
        if(!strcmp(entry->key, key))
            return entry->value;
    }
    return NULL;
}

void *dict_remove(dict_t *dict, const char *key)
{
    unsigned hash = hashf(dict->binsize, key);
    FOREACH_ENTRY_AND_PREV_IN_BIN(entry, prev, dict, hash) {

        if(!strcmp(entry->key, key)) {
            if(prev)
                prev->next = entry->next; 
            else if(entry->next)
                dict->bins[hash] = entry->next;
            else 
                dict->bins[hash] = NULL;

            dict_entry_free(entry);
            dict->size--;
            break;
        }
    }
}

void dict_rehash(dict_t *dict, size_t newsize)
{
    dict_entry_t **newbins;    
    newbins = calloc(newsize, sizeof(dict_entry_t*));

    for(unsigned i = 0; i < dict->binsize; i++) {
        FOREACH_ENTRY_AND_PREV_IN_BIN(entry, prev, dict, i) {
            if(prev)
                prev->next = NULL; /*This node at the end of a new bin*/
            
            unsigned hash = hashf(newsize, entry->key);
            if(!newbins[hash]){
                newbins[hash] = entry;
            }else {
                dict_entry_t *last = newbins[hash];                
                while(last->next)
                    last = last->next;
                    
                last->next = entry;
            }
        }
    }

    free(dict->bins);
    dict->binsize = newsize;
    dict->bins = newbins;
}

unsigned dict_get_size(dict_t *dict)
{
    return dict->size;
}

const dict_iter_t *dict_iter_first(const dict_t *dict)
{
    for(unsigned i = 0; i < dict->binsize; i++) {
        FOREACH_ENTRY_IN_BIN(entry, dict, i) {
            return entry;
        }
    }
    return NULL;
}

const dict_iter_t *dict_iter_next(dict_t *dict, const dict_iter_t *iter)
{
    if(((dict_entry_t*)iter)->next)
        return ((dict_entry_t*)iter)->next;
    
    unsigned hash = hashf(dict->binsize, dict_iter_get_key(iter));

    for(unsigned i = hash + 1; i < dict->binsize; i++) {
        FOREACH_ENTRY_IN_BIN(entry, dict, i) {
            return entry;
        }
    }
    return NULL;
}

const unsigned char *dict_iter_get_value(const dict_iter_t *iter)
{
    return ((dict_entry_t*)iter)->value;
}

const char *dict_iter_get_key(const dict_iter_t *iter)
{
    return ((dict_entry_t*)iter)->key;
}

void dict_key_for_uint32(uint32_t key, char *out, size_t len)
{
    char base = 'a';
    size_t num_nybbles = sizeof(uint32_t) * CHAR_BIT / 4;
    assert(len >= num_nybbles + 1);
    int i;
    for(i = 0; i < num_nybbles; i++) {
        out[i] = base + ((key >> (i*4)) & 0xF);
        assert(out[i] >= 'a' && out[i] < ('a' + 16));
    }
    out[i] = '\0';
}

void *dict_dump(dict_t *dict)
{
    for(unsigned i = 0; i < dict->binsize; i++) {
        printf("%4d: ", i);
        FOREACH_ENTRY_IN_BIN(entry, dict, i) {
            printf("[%s]", entry->key);
            if(entry->next)
                printf("-->");
            else
                printf("-->[0]");
        }
        printf("\n");
    }
}
