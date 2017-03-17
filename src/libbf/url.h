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

#ifndef URL_H
#define URL_H

#include <stdint.h>

typedef enum
{
	PROTOCOL_UNKNOWN = -1,
	PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
	PROTOCOL_UDP
}protocol_t;

typedef struct url{
	protocol_t protocol;	
	char *hostname;
	char *path;	
	uint16_t port;
}url_t;

url_t 	*url_from_str(const char *str);
void	url_free(url_t *url);	

#endif
