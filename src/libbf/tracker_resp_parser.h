#ifndef TRACKER_RESP_PARSER_H
#define TRACKER_RESP_PARSER_H

#include "tracker_announce.h"
#include "byte_str.h"

tracker_announce_resp_t *tracker_resp_parse(const byte_str_t *raw);

#endif
