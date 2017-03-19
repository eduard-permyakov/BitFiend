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

#include "tracker_announce.h"
#include "url.h"
#include "tracker_udp.h"
#include "tracker_http.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h> 

static int tracker_connect(url_t *url);

static int tracker_connect(url_t *url)
{
    struct addrinfo hints, *tracker, *head;;
    int sockfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = url->protocol == PROTOCOL_HTTP ?  SOCK_STREAM : SOCK_DGRAM;

    char port[6];
    int n = snprintf(port, sizeof(port), "%hu", url->port);
    port[n] = '\0';

    int rv;
    if(rv = getaddrinfo(url->hostname, port, &hints, &head))
        goto fail_getaddrinfo;

    for(tracker = head; tracker; tracker = tracker->ai_next) {
        if((sockfd = socket(tracker->ai_family, tracker->ai_socktype, 
            tracker->ai_protocol)) < 0) {
            continue;
        }

        if(connect(sockfd, tracker->ai_addr, tracker->ai_addrlen) < 0) {
            close(sockfd);
            continue;
        }

        break;
    }
    
    if(!tracker){
        log_printf(LOG_LEVEL_ERROR, "Unable to connect to tracker: %s\n", url->hostname);
        goto fail_connect;
    }

    freeaddrinfo(head);
    errno = 0;
    log_printf(LOG_LEVEL_INFO, "Successfully connected (socket fd: %d) to tracker: %s\n", 
        sockfd, url->hostname);
    return sockfd;

fail_connect:
    freeaddrinfo(head);
fail_getaddrinfo:
    return -1;
}

tracker_announce_resp_t *tracker_announce(const char *urlstr, tracker_announce_request_t *request)
{
    int sockfd;
    tracker_announce_resp_t *ret;
    char errbuff[64];

    log_printf(LOG_LEVEL_INFO, "Announcing to tracker: %s\n", urlstr);

    url_t *url = url_from_str(urlstr);
    if(!url)
        goto fail_parse_url;

    if(url->protocol == PROTOCOL_HTTPS){
        log_printf(LOG_LEVEL_ERROR, "No support for HTTPS tracker protocol\n");
        goto fail_protocol;
    }

    if((sockfd = tracker_connect(url)) < 0)
        goto fail_connect;

    if(url->protocol == PROTOCOL_UDP) {
        ret = tracker_udp_announce(sockfd, request);
    }else if(url->protocol == PROTOCOL_HTTP) {
        ret = tracker_http_announce(sockfd, url, request);
    }

    close(sockfd);
    url_free(url);
    return ret;

fail_connect:
fail_protocol:
    url_free(url);
fail_parse_url:
    if(errno) {
        strerror_r(errno, errbuff, sizeof(errbuff));
        log_printf(LOG_LEVEL_ERROR, "%s\n", errbuff);
    }
    return NULL;
}

void tracker_announce_request_free(tracker_announce_request_t *req)
{
    if(HAS(req, REQUEST_HAS_TRACKER_ID))
        free(req->tracker_id);
        
    if(HAS(req, REQUEST_HAS_KEY))
        free(req->key);
    
    free(req);
}

void tracker_announce_resp_free(tracker_announce_resp_t *resp)
{
    if(HAS(resp, RESPONSE_HAS_TRACKER_ID))
        free(resp->tracker_id);

    if(HAS(resp, RESPONSE_HAS_FAILURE_REASON))
        free(resp->failure_reason);

    if(HAS(resp, RESPONSE_HAS_WARNING_MESSAGE))
        free(resp->warning_message);

    const unsigned char *entry;
    FOREACH_ENTRY(entry, resp->peers) {
        peer_t *peer = *((peer_t**)entry);
        free(peer);
    }
    list_free(resp->peers);

    free(resp);
}

//TEMP

void print_tracker_response(tracker_announce_resp_t *resp)
{
    printf("TRACKER RESPONSE:\n");
    printf("\tinterval: %u\n", resp->interval); 
    if(HAS(resp, RESPONSE_HAS_TRACKER_ID))
        printf("\ttracker_id: %s\n", resp->tracker_id);
    printf("\tcomplete: %u\n", resp->complete); 
    printf("\tincomplete: %u\n", resp->incomplete); 
    printf("\tpeers: %p, size: %u\n", resp->peers, list_get_size(resp->peers));

    const unsigned char *entry;
    FOREACH_ENTRY(entry, resp->peers) {
        peer_t *peer = *((peer_t**)entry);

        char buff[INET6_ADDRSTRLEN];
        uint16_t port;

        if(peer->addr.sas.ss_family == AF_INET) {
            inet_ntop(AF_INET, &peer->addr.sa_in.sin_addr, buff, INET_ADDRSTRLEN); 
            port = ntohs(peer->addr.sa_in.sin_port);
        }else{
            inet_ntop(AF_INET6, &peer->addr.sa_in6.sin6_addr, buff, INET6_ADDRSTRLEN);        
            port = ntohs(peer->addr.sa_in6.sin6_port);
        }
        printf("\t\tpeer: %s [port: %u]\n", buff, port); 
    }

    if(HAS(resp, RESPONSE_HAS_FAILURE_REASON))
        printf("\tfailure reason: %s\n", resp->failure_reason);
    if(HAS(resp, RESPONSE_HAS_WARNING_MESSAGE))
        printf("\twarning message: %s\n", resp->warning_message);
}

