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

#ifndef DICT_H
#define DICT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct dict dict_t;

dict_t         *dict_init(size_t size);
void            dict_free(dict_t *dict);
int             dict_add(dict_t *dict, const char *key, unsigned char *data, size_t size);
unsigned char  *dict_get(dict_t *dict, const char *key);
void           *dict_remove(dict_t *dict, const char *key);
void            dict_rehash(dict_t *dict, size_t newsize);
unsigned        dict_get_size(dict_t *dict);

/* Gives a unique 8-char ascii string for each uint32_t, allowing to use uint32_t as keys,
 * should not be mixed with arbitrary string keys in a single dict */
void            dict_key_for_uint32(uint32_t key, char *out, size_t len);

typedef void dict_iter_t;

const dict_iter_t   *dict_iter_first(const dict_t *dict);
const dict_iter_t   *dict_iter_next(dict_t *dict, const dict_iter_t *iter);
const char          *dict_iter_get_key(const dict_iter_t *iter);
const unsigned char *dict_iter_get_value(const dict_iter_t *iter);

#define FOREACH_KEY_AND_VAL(_key, _val, _dict_ptr) \
    for(const dict_iter_t *_iter = dict_iter_first(_dict_ptr); \
        _iter \
        && (_key = dict_iter_get_key(_iter)) \
        && (_val = dict_iter_get_value(_iter)); \
        _iter = dict_iter_next(_dict_ptr, _iter))

#endif
