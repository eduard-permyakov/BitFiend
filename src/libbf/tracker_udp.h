#ifndef TRACKER_UDP_H
#define TRACKER_UDP_H

#include "tracker_announce.h"
#include <time.h>

tracker_announce_resp_t *tracker_udp_announce(int sockfd, tracker_announce_request_t *req);

#endif
