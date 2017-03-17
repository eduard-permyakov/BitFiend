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

#ifndef DL_FILE_H
#define DL_FILE_H

#include <stddef.h>

typedef struct dl_file dl_file_t;

typedef struct filemem {
    void *mem;        
    size_t size;
}filemem_t;

dl_file_t  *dl_file_create_and_open(size_t size, const char *path);
int         dl_file_close_and_free(dl_file_t *file);
void        dl_file_getfilemem(const dl_file_t *file, filemem_t *out);
int         dl_file_complete(dl_file_t *file);

#endif
