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
