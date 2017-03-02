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
#define LBITFIELD_ISSET(_index, _buff) !!((_buff)[(_index)/CHAR_BIT] & (CHAR_BIT-((_index) % CHAR_BIT)))

#define LBITFIELD_SET(_index, _buff) \
    do { \
        ((_buff)[(_index)/CHAR_BIT] |= (CHAR_BIT-((_index) % CHAR_BIT))); \
    }while(0)

#define LBITFIELD_CLR(_index, _buff) \
    do { \
        ((_buff)[(_index)/CHAR_BIT] &= ~(CHAR_BIT-((_index) % CHAR_BIT))); \
    }while(0)   

#endif
