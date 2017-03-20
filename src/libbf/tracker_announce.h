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

#ifndef TRACKER_ANNOUNCE_H
#define TRACKER_ANNOUNCE_H

#include "list.h"
#include "byte_str.h"
#include "peer.h"
#include <stddef.h>

typedef enum {
    TORRENT_EVENT_NONE      = 0,
    TORRENT_EVENT_COMPLETED = 1,
    TORRENT_EVENT_STARTED   = 2,
    TORRENT_EVENT_STOPPED   = 3
}torrent_event_t;

enum {
    REQUEST_HAS_IP                  = (1 << 0),
    REQUEST_HAS_NUMWANT             = (1 << 1),
    REQUEST_HAS_NO_PEER_ID          = (1 << 2),
    REQUEST_HAS_COMPACT             = (1 << 3),
    REQUEST_HAS_KEY                 = (1 << 4),
    REQUEST_HAS_TRACKER_ID          = (1 << 5)
};

enum {
    RESPONSE_HAS_FAILURE_REASON     = (1 << 0),
    RESPONSE_HAS_WARNING_MESSAGE    = (1 << 1),
    RESPONSE_HAS_MIN_INTERVAL       = (1 << 2),
    RESPONSE_HAS_TRACKER_ID         = (1 << 3)
};

#define SET_HAS(_ptr, _has) ((_ptr)->has |= (_has))
#define CLR_HAS(_ptr, _has) ((_ptr)->has &= ~(_has))
#define HAS(_ptr, _has) !!((_ptr)->has & (_has))

typedef struct tracker_announce_request {
    char            has;
    char            info_hash[20]; 
    char            peer_id[20];
    struct          sockaddr_in ip;
    uint16_t        port;
    unsigned long   uploaded;
    unsigned long   downloaded;  
    unsigned long   left;
    torrent_event_t event;
    unsigned        numwant;
    bool            no_peer_id;
    bool            compact;
    char           *key;
    char           *tracker_id;
}tracker_announce_request_t;

typedef struct tracker_announce_resp {
    char            has;
    unsigned        interval;
    char           *tracker_id;
    unsigned        complete;
    unsigned        incomplete;
    list_t         *peers;
    char           *failure_reason;
    char           *warning_message;
    int64_t         min_interval;
}tracker_announce_resp_t;

tracker_announce_resp_t *tracker_announce(const char *urlstr, tracker_announce_request_t *request);
void                     tracker_announce_request_free(tracker_announce_request_t *req);
void                     tracker_announce_resp_free(tracker_announce_resp_t *resp);

#endif
