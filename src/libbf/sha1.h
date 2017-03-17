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

#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>

#define DIGEST_LEN 20

typedef struct sha1_context sha1_context_t;

sha1_context_t *sha1_context_init(void);
void            sha1_context_free(sha1_context_t *ctx);
void            sha1_update(sha1_context_t *ctx, const char *msg, size_t len);
void            sha1_finish(sha1_context_t *ctx, char digest[DIGEST_LEN]);

int             sha1_compute(const char *msg, size_t len, char digest[DIGEST_LEN]);

#endif
