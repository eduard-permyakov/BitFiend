#include "bencode.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


static bencode_obj_t *bencode_parse_string(const char *benc, const char **endptr);
static bencode_obj_t *bencode_parse_int(const char *benc, const char **endptr);
static bencode_obj_t *bencode_parse_dict(const char *benc, const char **endptr);
static bencode_obj_t *bencode_parse_list(const char *benc, const char **endptr);
void print_obj(bencode_obj_t *obj); //TEMP


static bencode_obj_t *bencode_obj_create(void)
{
    bencode_obj_t *ret = malloc(sizeof(bencode_obj_t));
    memset(ret->sha1, 0, DIGEST_LEN);
    return ret;
}

static void *bencode_obj_free(bencode_obj_t *obj)
{
    free(obj);
}

void bencode_free_obj_and_data_recursive(bencode_obj_t *obj)
{
    switch(obj->type) {
        case BENCODE_TYPE_STRING:
            byte_str_free(obj->data.string);
            free(obj);
            break;
        case BENCODE_TYPE_INT:
            free(obj);
            break;
        case BENCODE_TYPE_LIST: {
            const unsigned char *entry;

            FOREACH_ENTRY(entry, obj->data.list) {
                bencode_free_obj_and_data_recursive(*((bencode_obj_t**)entry));
            }
    
            list_free(obj->data.list);
            free(obj);
            break;
        }
        case BENCODE_TYPE_DICT: {
            const char *key;
            const unsigned char *val;

            FOREACH_KEY_AND_VAL(key, val, obj->data.dictionary) {
                bencode_free_obj_and_data_recursive(*((bencode_obj_t**)val));
            }

            dict_free(obj->data.dictionary);
            free(obj);
            break;
        }
    }
}

bencode_obj_t *bencode_parse_object(const char *benc, const char **endptr)
{
    if(isdigit(benc[0]))
        return bencode_parse_string(benc, endptr);
    else if (benc[0] == 'i')
        return bencode_parse_int(benc, endptr);
    else if(benc[0] == 'l')
        return bencode_parse_list(benc, endptr);
    else if(benc[0] == 'd')
        return bencode_parse_dict(benc, endptr);

    return NULL;
}

static bencode_obj_t *bencode_parse_string(const char *benc, const char **endptr)
{
    long strl;
    bencode_obj_t *ret;
    *endptr = benc;

    strl =  strtol(benc, (char**)endptr, 10);
    assert(**endptr == ':');
    (*endptr)++;

    ret = bencode_obj_create();
    assert(ret);
    
    ret->type = BENCODE_TYPE_STRING; 
    ret->data.string = byte_str_new(strl, *endptr);
    assert(ret->data.string);

    *endptr += strl;
    return ret;
}

static bencode_obj_t *bencode_parse_int(const char *benc, const char **endptr)
{
    long i;
    bencode_obj_t *ret;
    *endptr = benc;

    assert(*benc == 'i');
    benc++;

    i = strtol(benc, (char**)endptr, 10);
    assert(**endptr == 'e');
    (*endptr)++;
    
    ret = bencode_obj_create();
    assert(ret);

    ret->type = BENCODE_TYPE_INT;
    ret->data.integer = i;
    return ret;
}

static bencode_obj_t *bencode_parse_dict(const char *benc, const char **endptr)
{
    bencode_obj_t *ret;
    const char * const start = benc;

    assert(*benc == 'd');    
    *endptr = benc + 1;

    ret = bencode_obj_create();
    ret->type = BENCODE_TYPE_DICT;
    ret->data.dictionary = dict_init(16);
    assert(ret->data.dictionary);

    while(**endptr != 'e') {
        benc = *endptr;
        bencode_obj_t *key = bencode_parse_string(benc, endptr);
        assert(key);
        assert(*endptr > benc);

        benc = *endptr;
        bencode_obj_t *value = bencode_parse_object(benc, endptr);
        assert(value);
        assert(*endptr > benc);
        
        dict_add(ret->data.dictionary, (char*)key->data.string->str, 
            (unsigned char*)&value, sizeof(value));

        bencode_free_obj_and_data_recursive(key);
    }

    assert(**endptr == 'e');
    (*endptr)++;

    if(!strncmp(start - strlen("info"), "info", strlen("info"))) {
        assert(start[0] == 'd');
        assert(start[*endptr - start - 1] == 'e');
        printf("sha1 computed!\n");
        sha1_compute(start, *endptr - start, ret->sha1);
    }

    return ret;
}

static bencode_obj_t *bencode_parse_list(const char *benc, const char **endptr)
{
    bencode_obj_t *ret;
    
    assert(*benc == 'l');
    *endptr = benc + 1;

    ret = bencode_obj_create();
    assert(ret);
    ret->type = BENCODE_TYPE_LIST;
    ret->data.list = list_init();
    assert(ret->data.list);

    while(**endptr != 'e') {
        benc = *endptr;
        bencode_obj_t *elem= bencode_parse_object(benc, endptr);
        assert(elem);

        list_add(ret->data.list, (unsigned char*)&elem, sizeof(elem));
    }

    assert(**endptr == 'e');
    (*endptr)++;

    return ret;
}

// TEST BEGIN

void print_obj(bencode_obj_t *obj)
{
    switch(obj->type) {
        case BENCODE_TYPE_INT:
            printf("Int: %ld\n", obj->data.integer);
            break;
        case BENCODE_TYPE_DICT: {

            const char *key;
            const unsigned char *val;

            printf("Dict: \n");
            FOREACH_KEY_AND_VAL(key, val, obj->data.dictionary) {
                printf("Key: %s\n", key);
                print_obj(*((bencode_obj_t**)val));
            }
            break;
        }
        case BENCODE_TYPE_LIST: {
            const unsigned char *entry;
            printf("List: \n");
            FOREACH_ENTRY(entry, obj->data.list) {
                printf("            ");
                print_obj(*((bencode_obj_t**)entry));
            }
            break;
        }
        case BENCODE_TYPE_STRING:
            printf("String: %p\n", obj->data.string);
            break;
    }
}
