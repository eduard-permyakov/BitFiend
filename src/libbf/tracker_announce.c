#include "tracker_announce.h"
#include "url.h"
#include "bencode.h"

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


static bool is_valid_url_char(const unsigned char c)
{
    return isdigit(c) || isalpha(c) || (c == '.') || (c == '-') || (c == '_') || (c == '~');
}

static int print_url_encoded_char(char *out, size_t n, unsigned char c)
{
    return snprintf(out, n, "%%%1X%1X", (c >> 4), (c & 0xF));
}

static int print_url_encoded_str(char *out, size_t n, const unsigned char *orig, size_t olen)
{
    int written = 0;
    for(const unsigned char *i = orig; i < orig + olen; i++) {
        if(is_valid_url_char(*i))
            written += snprintf(out + written, n - written, "%1c", (char)(*i));
        else
            written += print_url_encoded_char(out + written, n - written, *i);
    }
    return written;
}

static char *build_http_request(const char *urlstr, tracker_announce_request_t *request)
{
    int written = 0;
    char buff[512];

    written += snprintf(buff, sizeof(buff), "GET %s", urlstr);

    written += snprintf(buff + written, sizeof(buff) - written, "?info_hash=");
    written += print_url_encoded_str(buff + written, sizeof(buff) - written, request->info_hash, 20);

    written += snprintf(buff + written, sizeof(buff) - written, "&peer_id=");
    written += print_url_encoded_str(buff + written, sizeof(buff) - written, request->peer_id, 20);

    written += snprintf(buff + written, sizeof(buff) - written, "&port=%hu", request->port);
    written += snprintf(buff + written, sizeof(buff) - written, "&uploaded=%lu", request->uploaded);
    written += snprintf(buff + written, sizeof(buff) - written, "&downloaded=%lu", request->downloaded);
    written += snprintf(buff + written, sizeof(buff) - written, "&downloaded=%lu", request->downloaded);
    written += snprintf(buff + written, sizeof(buff) - written, "&left=%lu", request->left);

    if(HAS(request, REQUEST_HAS_COMPACT)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&compact=%1hhu", !!(request->compact));
    }

    if(HAS(request, REQUEST_HAS_NO_PEER_ID)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&no_peer_id=%1hhu", !!(request->no_peer_id));
    }

    if(HAS(request, REQUEST_HAS_EVENT)) {
        char *event_str;
        switch(request->event) {
            case TORRENT_EVENT_STARTED:
                event_str = "started";      break;
            case TORRENT_EVENT_COMPLETED:
                event_str = "completed";    break;
            case TORRENT_EVENT_STOPPED:
                event_str = "stopped";      break;
            default:
                assert(0);
        }
        written += snprintf(buff + written, sizeof(buff) - written, "&event=%s", event_str);
    }

#if 0 //TODO
    if(HAS(request, REQUEST_HAS_IP)) {
    }
#endif

    if(HAS(request, REQUEST_HAS_NUMWANT)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&numwant=%u", request->numwant);
    }

    if(HAS(request, REQUEST_HAS_KEY)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&key=%s", request->key);
    }

    if(HAS(request, REQUEST_HAS_TRACKER_ID)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&trackerid=%s", request->tracker_id);
    }

    written += snprintf(buff + written, sizeof(buff) - written, " HTTP/1.0\r\n\r\n");

    assert(written < sizeof(buff));
    buff[written] = '\0';

    char *ret = malloc(written + 1);
    if(ret){
        strcpy(ret, buff);
    }
    return ret;
}

static int tracker_connect(url_t *url)
{
    struct addrinfo hints, *tracker, *head;;
    int sockfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port[5];
    snprintf(port, sizeof(port), "%u", url->port);
    port[sizeof(port)-1] = '\0';

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
    
    if(!tracker)
        goto fail_connect;

    free(head);
    return sockfd;

fail_connect:
    free(head);
fail_getaddrinfo:
    return -1;
}

static byte_str_t *content_from_tracker_resp(char *buff, size_t len)
{
    char *line,*saveptr;
    char *token, *saveptrtok;
    unsigned cont_len;

    line = strtok_r(buff, "\n", &saveptr);
    if(strncmp(line, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK")))
        goto fail_parse;

    line = strtok_r(NULL, "\n", &saveptr);
    if(strncmp(line, "Content-Length:", strlen("Content-Length:")))
        goto fail_parse;
    token = strtok_r(line, ":", &saveptrtok);
    token = strtok_r(NULL, ":", &saveptrtok);
    cont_len = strtoul(token, NULL, 0);

    line = strtok_r(NULL, "\n", &saveptr);
    if(strncmp(line, "Content-Type: text/plain", strlen("Content-Type: text/plain")))
        goto fail_parse;

    line = strtok_r(NULL, "\n", &saveptr);
    if(strncmp(line, "Pragma", strlen("Pragma")))
        goto fail_parse;

    line = strtok_r(NULL, "\n", &saveptr);
    if(strlen(line) != 1)
        goto fail_parse;

    byte_str_t *ret = byte_str_new(cont_len, line + strlen(line) + 1);
    return ret;

fail_parse:
    return NULL; 
}

static int tracker_sendall(int sockfd, const char *buff, size_t len)
{
    ssize_t tot_sent = 0;
    while(tot_sent < len) {
        ssize_t sent = send(sockfd, buff, len - tot_sent, 0);
        if(sent < 0)
            return -1;

        tot_sent += sent;
        buff += sent;
    }
    return 0;
}

static int tracker_recv_resp(int sockfd, byte_str_t **outcont)
{
    char buff[2048];
    size_t tot_recv = 0;
    ssize_t nb;

    do {
        nb = recv(sockfd, buff + tot_recv, sizeof(buff) - tot_recv, 0);
        if(nb < 0)
            return -1;

        tot_recv += nb;
    }while(nb > 0);

    *outcont = content_from_tracker_resp(buff, tot_recv);
    
    return 0;
}

static list_t *parse_peerlist(byte_str_t *raw)
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
        peer->ip.sin_family = AF_INET;
        peer->ip.sin_addr.s_addr = ip;
        peer->ip.sin_port = port;
        memset(peer->ip.sin_zero, 0, sizeof(peer->ip.sin_zero));

        memset(peer->peer_id, 0, sizeof(peer->peer_id));

        list_add(peers, (unsigned char*)&peer, sizeof(peer));
    }

    return peers;

fail_alloc:
    return NULL;
}

static tracker_announce_resp_t *parse_tracker_response(const byte_str_t *raw)
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

    FOREACH_KEY_AND_VAL(key, val, ((bencode_obj_t*)obj)->data.dictionary) {
        if(!strcmp(key, "failure reason")) {
            char *str = (char*)((bencode_obj_t*)val)->data.string->str;
            ret->failure_reason =  malloc(strlen(str) + 1);
            memcpy(ret->failure_reason, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_FAILURE_REASON);
        }

        if(!strcmp(key, "warning message")) {
            char *str = (char*)((bencode_obj_t*)val)->data.string->str;
            ret->warning_message =  malloc(strlen(str) + 1);
            memcpy(ret->warning_message, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_WARNING_MESSAGE);
        }

        if(!strcmp(key, "interval")) {
            ret->interval = ((bencode_obj_t*)val)->data.integer;
        }

        if(!strcmp(key, "min interval")) {
            ret->min_interval = ((bencode_obj_t*)val)->data.integer;
            SET_HAS(ret, RESPONSE_HAS_MIN_INTERVAL);
        }

        if(!strcmp(key, "tracker id")) {
            char *str = (char*)((bencode_obj_t*)val)->data.string->str;
            ret->tracker_id =  malloc(strlen(str) + 1);
            memcpy(ret->tracker_id, str, strlen(str) + 1); 
            SET_HAS(ret, RESPONSE_HAS_TRACKER_ID);
        }

        if(!strcmp(key, "complete")) {
            ret->complete = ((bencode_obj_t*)val)->data.integer;
        }

        if(!strcmp(key, "incomplete")) {
            ret->incomplete = ((bencode_obj_t*)val)->data.integer;
        }

        if(!strcmp(key, "peers")) {
            if(((bencode_obj_t*)val)->type == BENCODE_TYPE_STRING) {
                ret->peers = parse_peerlist(((bencode_obj_t*)val)->data.string);
            }else {
                //TODO: parse peers in dictionary format
                assert(0);
            }
        }
    }

    bencode_free_obj_and_data_recursive(obj);
    return ret;

fail_alloc:
fail_parse:
    return NULL;
}

tracker_announce_resp_t *tracker_announce(const char *urlstr, tracker_announce_request_t *request)
{
    int sockfd;
    byte_str_t *raw;
    tracker_announce_resp_t *ret;

    url_t *url = url_from_str(urlstr);
    if(!url)
        goto fail_parse_url;

    char *request_str = build_http_request(urlstr, request);

    printf("HTTP REQUEST:%s\n", request_str);

    if((sockfd = tracker_connect(url)) < 0)
        goto fail_connect;

    if(tracker_sendall(sockfd, request_str, strlen(request_str)) < 0)
        goto fail_send;

    if(tracker_recv_resp(sockfd, &raw) < 0)
        goto fail_recv;

    ret = parse_tracker_response(raw);
    if(!ret)
        goto fail_parse;

    url_free(url);
    free(request_str);
    byte_str_free(raw); 

    return ret;

fail_parse:
    byte_str_free(raw);
fail_recv:
fail_send:
    close(sockfd);
fail_connect:
    url_free(url);
fail_parse_url:
    free(request_str);
    return NULL;
}

void tracker_announce_request_free(tracker_announce_request_t *req)
{

}

void tracker_announce_resp_free(tracker_announce_resp_t *resp)
{

}

