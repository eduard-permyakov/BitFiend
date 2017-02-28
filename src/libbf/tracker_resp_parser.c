#include "tracker_resp_parser.h"
#include "bencode.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h> //temp

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

static list_t *parse_peerlist_str(byte_str_t *raw)
{
    list_t *peers = list_init();
    if(!peers)
        goto fail_alloc;

    assert(raw->size % 6 == 0);
    for(int i = 0; i < raw->size; i+= 6) {

        uint32_t ip;
        memcpy(&ip, raw->str + i, sizeof(uint32_t));

        uint16_t port;
        memcpy(&port, raw->str + i + sizeof(uint32_t), sizeof(uint16_t));

        peer_t *peer = malloc(sizeof(peer_t));
        struct sockaddr_in ipv4;
        peer->addr.sas.ss_family = AF_INET;
        peer->addr.sa_in.sin_addr.s_addr = ip;
        peer->addr.sa_in.sin_port = port;
        memset(peer->addr.sa_in.sin_zero, 0, sizeof(peer->addr.sa_in.sin_zero));

        memset(peer->peer_id, 0, sizeof(peer->peer_id));

        list_add(peers, (unsigned char*)&peer, sizeof(peer));
    }

    return peers;

fail_alloc:
    return NULL;
}

static list_t *parse_peerlist_list(list_t *list)
{    
    list_t *peers = list_init();
    if(!peers)
        goto fail_alloc;

    const unsigned char *entry;
    FOREACH_ENTRY(entry, list) {

        bencode_obj_t *peer_dict = *((bencode_obj_t**)entry);
        peer_t *peer = malloc(sizeof(peer_t));
        bool valid = true;

        const char *key;
        const unsigned char *val;
        FOREACH_KEY_AND_VAL(key, val, peer_dict->data.dictionary) {

            if(!strcmp(key, "peer id") || !strcmp(key, "id")) {
                memcpy(peer->peer_id, (*(bencode_obj_t**)val)->data.string->str, sizeof(peer->peer_id));
            }

            if(!strcmp(key, "ip")) {
                char *ipstr = (char*)(*(bencode_obj_t**)val)->data.string->str;
                struct addrinfo hint, *res = NULL; 

                memset(&hint, 0, sizeof(hint));
                hint.ai_family = PF_UNSPEC;
                hint.ai_flags = AI_NUMERICHOST;

                int ret = getaddrinfo(ipstr, NULL, &hint, &res);
                if(!ret) {
                    peer->addr.sas.ss_family = res->ai_family;
                    memcpy(&peer->addr.sas, res->ai_addr, sizeof(struct sockaddr));
                    freeaddrinfo(res);
                }else{
                    valid = false;
                    break;
                }
            }

            if(!strcmp(key, "port")) {
                uint16_t port = (uint16_t)(*(bencode_obj_t**)val)->data.integer;

                if(peer->addr.sas.ss_family = AF_INET) {
                    peer->addr.sa_in.sin_port = htons(port);
                }else{
                    peer->addr.sa_in6.sin6_port = htons(port);
                }
            }
        }

        if(valid)
            list_add(peers, (unsigned char*)&peer, sizeof(peer_t*));
        else
            free(peer);

    }
    return peers;

fail_alloc:
    return NULL;
}

tracker_announce_resp_t *tracker_resp_parse(const byte_str_t *raw)
{
    const char *endptr;
    bencode_obj_t *obj = bencode_parse_object(raw->str, &endptr);
    if(!obj)
        goto fail_parse;

    tracker_announce_resp_t *ret = malloc(sizeof(tracker_announce_resp_t));
    if(!ret)
        goto fail_alloc;
    memset(ret, 0, sizeof(*ret));

    assert(obj->type == BENCODE_TYPE_DICT);
    const char *key;
    const unsigned char *val;

    FOREACH_KEY_AND_VAL(key, val, obj->data.dictionary) {
        if(!strcmp(key, "failure reason")) {
            char *str = (char*)(*(bencode_obj_t**)val)->data.string->str;
            ret->failure_reason =  malloc(strlen(str) + 1);
            memcpy(ret->failure_reason, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_FAILURE_REASON);
        }

        if(!strcmp(key, "warning message")) {
            char *str = (char*)(*(bencode_obj_t**)val)->data.string->str;
            ret->warning_message =  malloc(strlen(str) + 1);
            memcpy(ret->warning_message, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_WARNING_MESSAGE);
        }

        if(!strcmp(key, "interval")) {
            ret->interval = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "min interval")) {
            ret->min_interval = ((bencode_obj_t*)val)->data.integer;
            SET_HAS(ret, RESPONSE_HAS_MIN_INTERVAL);
        }

        if(!strcmp(key, "tracker id")) {
            char *str = (char*)(*(bencode_obj_t**)val)->data.string->str;
            ret->tracker_id =  malloc(strlen(str) + 1);
            memcpy(ret->tracker_id, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_TRACKER_ID);
        }

        if(!strcmp(key, "complete")) {
            ret->complete = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "incomplete")) {
            ret->incomplete = (*(bencode_obj_t**)val)->data.integer;
        }

        if(!strcmp(key, "peers")) {
            if((*(bencode_obj_t**)val)->type == BENCODE_TYPE_STRING) {
                ret->peers = parse_peerlist_str((*(bencode_obj_t**)val)->data.string);
            }else {
                ret->peers = parse_peerlist_list((*(bencode_obj_t**)val)->data.list);
            }
        }

        if(!strcmp(key, "peers_ipv6")) {
            //TODO
            assert(0);
        }
    }

    bencode_free_obj_and_data_recursive(obj);
    return ret;

fail_alloc:
    bencode_free_obj_and_data_recursive(obj);
fail_parse:
    return NULL;
}

