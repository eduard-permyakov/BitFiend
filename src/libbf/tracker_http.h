#ifndef TRACKER_HTTP_H
#define TRAKCER_HTTP_H

#include "tracker_announce.h"
#include "url.h"

tracker_announce_resp_t *tracker_http_announce(int sockfd, url_t *url, tracker_announce_request_t *req);

#endif
