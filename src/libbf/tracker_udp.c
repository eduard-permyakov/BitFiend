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

#include "tracker_udp.h"
#include "log.h"
#include "tracker_resp_parser.h"

#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <endian.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#define PROT_ID_MAGIC           0x41727101980
#define CONN_EXPIRE_TIME_SEC    60
#define CONN_EXPIRED(_time)     (time(NULL) > (_time) + CONN_EXPIRE_TIME_SEC)
#define MAX_RECV_BUFF_SZ        2048

typedef struct __attribute__ ((packed)) conn_req {
    uint64_t protocol_id;
    uint32_t action;
    uint32_t transaction_id;
}conn_req_t;

typedef struct __attribute__ ((packed)) conn_resp {
    uint32_t action;
    uint32_t transaction_id;
    uint64_t connection_id;
}conn_resp_t;

typedef struct __attribute__ ((packed)) ipv4_req {
    uint64_t connection_id; 
    uint32_t action;
    uint32_t transaction_id;
    char     info_hash[20];
    char     peer_id[20];
    uint64_t downloaded;
    uint64_t left;
    uint64_t uploaded;
    uint32_t event;
    uint32_t ip;
    uint32_t key; 
    uint32_t num_want;
    uint16_t port;
}ipv4_req_t;

typedef struct __attribute__ ((packed)) ipv4_resp_hdr {
    uint32_t action; 
    uint32_t transaction_id;
    uint32_t interval;
    uint32_t leechers;
    uint32_t seeders;
}ipv4_resp_hdr_t;

typedef struct __attribute__ ((packed)) ipv4_err_resp_hdr {
    uint32_t action; 
    uint32_t transaction_id;
    char     message[];
}ipv4_err_resp_hdr_t;

typedef enum tracker_action {
    TRACKER_ACTION_CONNECT  = 0,
    TRACKER_ACTION_ANNOUNCE = 1,
    TRACKER_ACTION_SCRAPE   = 2,
    TRACKER_ACTION_ERROR    = 3
}tracker_action_t;

static int  tracker_send_dgram(int sockfd, const char *buff, size_t len);
static int  tracker_recv_dgram(int sockfd, char *buff, size_t max, size_t *dgram_size, time_t timeout);
static int  tracker_udp_tryconnect(int sockfd, uint32_t trans_id, 
                                   conn_resp_t *out, size_t *outlen, time_t timeout);
static int  tracker_udp_tryannounce(int sockfd, ipv4_req_t *req, char *out, 
                                    size_t *outlen, time_t timeout);
static void fill_announce_dgram(tracker_announce_request_t *req, ipv4_req_t *out, 
                                uint64_t conn_id, uint32_t trans_id);


static inline time_t timeout(int n)
{
    return 15 * pow(2, n);
}

static inline uint32_t new_transaction_id(void)
{
    unsigned int seed = time(NULL);
    return rand_r(&seed);
}

static int tracker_send_dgram(int sockfd, const char *buff, size_t len)
{
    ssize_t sent = send(sockfd, buff, len, 0);
    if(sent < 0)
        return -1;

    assert(sent == len);
    return 0;
}

static int tracker_recv_dgram(int sockfd, char *buff, size_t max, size_t *dgram_size, time_t timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    ssize_t nb = recv(sockfd, buff, max, 0);
    if(nb < 0)
        return -1;

    *dgram_size = nb;
    return 0;
}

static int tracker_udp_tryconnect(int sockfd, uint32_t trans_id, 
                                  conn_resp_t *out, size_t *outlen, time_t timeout)
{
    conn_req_t req;
    req.protocol_id = htobe64(PROT_ID_MAGIC);
    req.action = htonl(TRACKER_ACTION_CONNECT);
    req.transaction_id = trans_id;
    assert(sizeof(req) == sizeof(uint64_t) + sizeof(uint32_t)*2);

    if(tracker_send_dgram(sockfd, (char*)&req, sizeof(req)))
        return -1;

    if(tracker_recv_dgram(sockfd, (char*)out, sizeof(conn_resp_t), outlen, timeout))
        return -1;

    return 0;
}

static void fill_announce_dgram(tracker_announce_request_t *req, ipv4_req_t *out, 
                               uint64_t conn_id, uint32_t trans_id)
{
    out->connection_id = conn_id;
    out->action = htonl(TRACKER_ACTION_ANNOUNCE);
    out->transaction_id = trans_id;
    memcpy(out->info_hash, req->info_hash, sizeof(out->info_hash));
    memcpy(out->peer_id, req->peer_id, sizeof(out->peer_id));
    out->downloaded = htonl(req->downloaded);
    out->left = htonl(req->left);
    out->uploaded = htonl(out->uploaded);
    out->event = htonl(req->event);
    out->ip = 0; //TODO
    out->key = 0;
    out->num_want = htonl(req->numwant);
    out->port = htons(req->port);
}

static int tracker_udp_tryannounce(int sockfd, ipv4_req_t *req, 
                                   char *out, size_t *outlen, time_t timeout)
{
    if(tracker_send_dgram(sockfd, (char*)req, sizeof(*req)))
        return -1;

    if(tracker_recv_dgram(sockfd, out, MAX_RECV_BUFF_SZ, outlen, timeout))
        return -1;

    return 0;
}

tracker_announce_resp_t *tracker_udp_announce(int sockfd, tracker_announce_request_t *req)
{
    tracker_announce_resp_t *ret = NULL;
    int n = 0;

    uint32_t trans_id = new_transaction_id();

    time_t conn_time;
    conn_resp_t conn_resp;
    size_t dgram_len;

reconnect:
    while(tracker_udp_tryconnect(sockfd, trans_id, &conn_resp, &dgram_len, timeout(n++))) {
        if(n == 8)
            goto fail;
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            goto fail;
        log_printf(LOG_LEVEL_WARNING, "Didn't get a connect response from the UDP tracker. Retrying...\n");
    }
    conn_time = time(NULL);

    assert(dgram_len == sizeof(conn_resp));
    log_printf(LOG_LEVEL_DEBUG, "UDP Tracker: Connection successful [Connection Id:0x%lx]\n", 
        conn_resp.connection_id);

    ipv4_req_t ann_req;
    assert(sizeof(ipv4_req_t) == 98);
    fill_announce_dgram(req, &ann_req, conn_resp.connection_id, trans_id);

    union{
        ipv4_resp_hdr_t     header;
        ipv4_err_resp_hdr_t err_header;
        char                all[MAX_RECV_BUFF_SZ];
    }ann_resp;

    while(tracker_udp_tryannounce(sockfd, &ann_req, ann_resp.all, &dgram_len, timeout(n++))) {
        if(n == 8)
            goto fail;
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            goto fail;
        if(CONN_EXPIRED(conn_time))
            goto reconnect;
        log_printf(LOG_LEVEL_WARNING, "Didn't get an announce response from the UDP tracker. Retrying...\n");
    }

    if(dgram_len < 20){
        log_printf(LOG_LEVEL_ERROR, "Invalid datagram size from tracker\n");
        goto fail;
    }

    if(ntohl(ann_resp.header.action) == TRACKER_ACTION_ERROR){
        log_printf(LOG_LEVEL_ERROR, "Error response returned: %.*s\n", dgram_len - sizeof(ipv4_err_resp_hdr_t),
            ann_resp.err_header.message);
        goto fail;
    }

    if(ann_resp.header.transaction_id != trans_id){
        log_printf(LOG_LEVEL_ERROR, "Invalid transaction id from tracker\n");
        goto fail;
    }

    log_printf(LOG_LEVEL_DEBUG, "UDP Tracker: Announce successful, dgram size: %zu\n", dgram_len);

    ret = malloc(sizeof(tracker_announce_resp_t));
    if(!ret)
        goto fail;

    ret->has = 0; 
    ret->interval = ntohl(ann_resp.header.interval);
    ret->complete = ntohl(ann_resp.header.seeders);
    ret->incomplete = ntohl(ann_resp.header.leechers);
    ret->peers = tracker_resp_parse_peerlist(ann_resp.all + sizeof(ann_resp.header), 
        dgram_len - sizeof(ann_resp.header));

    return ret;

fail:
    log_printf(LOG_LEVEL_ERROR, "UDP Tracker: Announcement failed\n");
    return NULL;
}

