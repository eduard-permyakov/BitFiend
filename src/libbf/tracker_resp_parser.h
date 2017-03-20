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

#ifndef TRACKER_RESP_PARSER_H
#define TRACKER_RESP_PARSER_H

#include "tracker_announce.h"
#include "byte_str.h"
#include "list.h"

tracker_announce_resp_t *tracker_resp_parse_bencode(const byte_str_t *raw);
list_t                  *tracker_resp_parse_peerlist(const char *buff, size_t len);

#endif
