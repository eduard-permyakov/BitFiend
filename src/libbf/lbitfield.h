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

#ifndef LBITFIELD_H 
#define LBITFIELD_H

#include <limits.h>

/* Most significant bit of the first byte in the buffer is at index 0
 *
 *  *-+-+-+-+-+-+-+-* *-+-+-- ...      
 *  |0|1|2|3|4|5|6|7| |8|9|10 ...     
 *  *-+-+-+-+-+-+-+-* *-+-+-- ...   
 *  byte 0            byte 1
 *
 */

#define LBITFIELD_NUM_BYTES(_len) (((_len)/CHAR_BIT) + ((_len) % CHAR_BIT ? 1 : 0))
#define LBITFIELD_ISSET(_index, _buff) !!((_buff)[(_index)/CHAR_BIT] & (1 << (CHAR_BIT-((_index) % CHAR_BIT)-1)))

#define LBITFIELD_SET(_index, _buff) \
    do { \
        ((_buff)[(_index)/CHAR_BIT] |= (1 << (CHAR_BIT-((_index) % CHAR_BIT)-1))); \
    }while(0)

#define LBITFIELD_CLR(_index, _buff) \
    do { \
        ((_buff)[(_index)/CHAR_BIT] &= ~(1 << (CHAR_BIT-((_index) % CHAR_BIT)-1))); \
    }while(0)   

#endif
