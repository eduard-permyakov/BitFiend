#include "tracker_http.h"
#include "log.h"
#include "tracker_resp_parser.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h> 

static bool        is_valid_url_char(const unsigned char c);
static int         print_url_encoded_char(char *out, size_t n, unsigned char c);
static int         print_url_encoded_str(char *out, size_t n, const unsigned char *orig, size_t olen);
static char       *build_http_request(url_t *url, tracker_announce_request_t *request);
static byte_str_t *content_from_chunked(char *buff);
static byte_str_t *content_from_tracker_resp(char *buff, size_t len);
static int         tracker_sendall(int sockfd, const char *buff, size_t len);
static int         tracker_recv_resp(int sockfd, byte_str_t **outcont);


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

static char *build_http_request(url_t *url, tracker_announce_request_t *request)
{
    int written = 0;
    char buff[512];

    written += snprintf(buff, sizeof(buff), "GET /%s", url->path);

    written += snprintf(buff + written, sizeof(buff) - written, "?info_hash=");
    written += print_url_encoded_str(buff + written, sizeof(buff) - written, request->info_hash, 20);

    written += snprintf(buff + written, sizeof(buff) - written, "&peer_id=");
    written += print_url_encoded_str(buff + written, sizeof(buff) - written, request->peer_id, 20);

    written += snprintf(buff + written, sizeof(buff) - written, "&port=%hu", request->port);
    written += snprintf(buff + written, sizeof(buff) - written, "&uploaded=%lu", request->uploaded);
    written += snprintf(buff + written, sizeof(buff) - written, "&downloaded=%lu", request->downloaded);
    written += snprintf(buff + written, sizeof(buff) - written, "&left=%lu", request->left);

    if(HAS(request, REQUEST_HAS_COMPACT)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&compact=%1hhu", !!(request->compact));
    }

    if(HAS(request, REQUEST_HAS_NO_PEER_ID)) {
        written += snprintf(buff + written, sizeof(buff) - written, "&no_peer_id=%1hhu", 
            !!(request->no_peer_id));
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

    written += snprintf(buff + written, sizeof(buff) - written, " HTTP/1.1\r\n");
    written += snprintf(buff + written, sizeof(buff) - written, "Host: %s\r\n\r\n", url->hostname);

    assert(written < sizeof(buff));
    buff[written] = '\0';

    char *ret = malloc(written + 1);
    if(ret){
        strcpy(ret, buff);
    }
    return ret;
}

static byte_str_t *content_from_chunked(char *buff)
{
    char newbuff[2048];
    char *line,*saveptr;
    size_t chunk_sz;
    size_t newsize = 0;

    line = strtok_r(buff, "\r\n", &saveptr);
    chunk_sz = strtoul(line, (char**)NULL, 16);
    while(chunk_sz > 0) {
        line = strtok_r(NULL, "\r\n", &saveptr);
        memcpy(newbuff + newsize, line, chunk_sz); 
        newsize += chunk_sz;

        line = strtok_r(NULL, "\r\n", &saveptr);
        chunk_sz = strtoul(line, (char**)NULL, 16);
    }

    byte_str_t *ret = byte_str_new(newsize, newbuff);
    return ret;
}

static byte_str_t *content_from_tracker_resp(char *buff, size_t len)
{
    char *line,*saveptr;
    char *token, *saveptrtok;
    unsigned cont_len = 0;
    bool chunked = false;

    line = strtok_r(buff, "\n", &saveptr);
    if(strncmp(line, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK")) &&
       strncmp(line, "HTTP/1.1 200 OK", strlen("HTTP/1.1 200 OK")))
        goto fail_parse;

    do {
        line = strtok_r(NULL, "\n", &saveptr);

        if(!strncmp(line, "Transfer-Encoding: chunked", strlen("Transfer-Encoding: chunked"))){
            chunked = true;
        }

        if(!strncmp(line, "Content-Length:", strlen("Content-Length:"))) {
            token = strtok_r(line, ":", &saveptrtok);
            token = strtok_r(NULL, ":", &saveptrtok);
            cont_len = strtoul(token, NULL, 0);
        }
        
    }while(strlen(line) != 1);

    if(chunked){
        return content_from_chunked(line + strlen(line) + 1);
    }else{
        return byte_str_new(cont_len, line + strlen(line) + 1);
    }

fail_parse:
    log_printf(LOG_LEVEL_ERROR, "Tracker returned non-OK HTTP response\n");
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

    log_printf(LOG_LEVEL_INFO, "Tracker HTTP response received\n");

    *outcont = content_from_tracker_resp(buff, tot_recv);
    if(!*outcont)
        return -1;
    
    return 0;
}

tracker_announce_resp_t *tracker_http_announce(int sockfd, url_t *url, tracker_announce_request_t *req)
{
    tracker_announce_resp_t *ret;
    byte_str_t *raw;
    char *request_str = build_http_request(url, req);
    log_printf(LOG_LEVEL_DEBUG, "%s", request_str);

    if(tracker_sendall(sockfd, request_str, strlen(request_str)))
        goto fail_comm;

    if(tracker_recv_resp(sockfd, &raw))
        goto fail_comm;

    ret = tracker_resp_parse(raw);
    if(!ret)
        goto fail_parse;

    free(request_str);
    byte_str_free(raw); 

    return ret;

fail_parse:
    byte_str_free(raw);
fail_comm:
    free(request_str);
    return NULL;
}

