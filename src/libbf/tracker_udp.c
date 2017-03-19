#include "tracker_udp.h"
#include "log.h"

#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <endian.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>

#define PROT_ID_MAGIC 0x41727101980

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
    uint32_t left;
    uint64_t uploaded;
    uint32_t event;          //0 = none, 1 = completed, 2 = started, 3 = stopped
    uint32_t ip;             //0 = default
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

typedef enum tracker_action {
    TRACKER_ACTION_CONNECT  = 0,
    TRACKER_ACTION_ANNOUNCE = 1,
    TRACKER_ACTION_SCRAPE   = 2,
    TRACKER_ACTION_ERROR    = 3
}tracker_action_t;

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

static int tracker_udp_tryconnect(int sockfd, conn_resp_t *out, size_t *outlen, time_t timeout)
{
    conn_req_t req;
    req.protocol_id = htobe64(PROT_ID_MAGIC);
    req.action = htonl(TRACKER_ACTION_CONNECT);
    req.transaction_id = htonl(new_transaction_id());
    assert(sizeof(req) == sizeof(uint64_t) + sizeof(uint32_t)*2);

    if(tracker_send_dgram(sockfd, (char*)&req, sizeof(req)))
        return -1;

    if(tracker_recv_dgram(sockfd, (char*)out, sizeof(conn_resp_t), outlen, timeout))
        return -1;

    return 0;
}

static int tracker_udp_tryannounce(int sockfd, conn_resp_t *out, size_t *outlen, time_t timeout)
{
    return 0;
}

tracker_announce_resp_t *tracker_udp_announce(int sockfd, tracker_announce_request_t *req)
{
    tracker_announce_resp_t *ret = NULL;
    int n = 0;

    conn_resp_t conn_resp;
    size_t dgram_len;

    while(tracker_udp_tryconnect(sockfd, &conn_resp, &dgram_len, timeout(n++))) {
        if(n == 8)
            goto fail_connect;
        log_printf(LOG_LEVEL_WARNING, "Didn't get a connect response from the UDP tracker. Retrying...\n");
    }

    assert(dgram_len == sizeof(conn_resp));
    log_printf(LOG_LEVEL_DEBUG, "UDP Tracker: Connection successful\n");

    union{
        ipv4_resp_hdr_t header;
        char all[2048];
    }ann_resp;

    while(tracker_udp_tryannounce(sockfd, &ann_resp, &dgram_len, timeout(n++))) {
        if(n == 8)
            goto fail_connect;
        log_printf(LOG_LEVEL_WARNING, "Didn't get an announce response from the UDP tracker. Retrying...\n");
    }

    log_printf(LOG_LEVEL_DEBUG, "UDP Tracker: Announce successful\n");
    
    return ret;

fail_connect:
    return NULL;
}

