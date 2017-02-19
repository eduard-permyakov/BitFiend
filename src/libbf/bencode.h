#ifndef BENCODE_H
#define BENCODE_H

#include "byte_str.h"
#include "list.h"
#include "dict.h"
#include "sha1.h"

#include <stdint.h>

typedef enum {
    BENCODE_TYPE_STRING,
    BENCODE_TYPE_INT,
    BENCODE_TYPE_LIST,
    BENCODE_TYPE_DICT
}bencode_type_t;

typedef struct bencode_obj {
    bencode_type_t type; 
    union {
        byte_str_t *string;
        int64_t integer;
        list_t *list;  
        dict_t *dictionary;
    }data;
    unsigned char sha1[DIGEST_LEN];
}bencode_obj_t;

bencode_obj_t   *bencode_parse_object(const char *benc, const char **endptr);
void            bencode_free_obj_and_data_recursive(bencode_obj_t *obj);

#endif
