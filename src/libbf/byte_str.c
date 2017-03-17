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

#include "byte_str.h"

#include <stdlib.h>
#include <string.h>

byte_str_t *byte_str_new(size_t size, const unsigned char *str)
{
    byte_str_t *ret;
    ret = malloc(sizeof(byte_str_t) + size + 1);
    if(ret) {
        memcpy(ret->str, str, size);
        /* NULL-terminate all data so this type is suitable for
         * storing ASCII data also 
         */
        ret->str[size] = '\0';
        ret->size = size;
    }
    return ret;
}

void byte_str_free(byte_str_t *str)
{
    free(str);
}

