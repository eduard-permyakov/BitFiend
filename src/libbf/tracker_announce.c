#include "tracker_announce.h"
#include "url.h"
#include "bencode.h"
#include "tracker_resp_parser.h"
#include "log.h"

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h> //temp


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

static int tracker_connect(url_t *url)
{
    struct addrinfo hints, *tracker, *head;;
    int sockfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

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

static byte_str_t *content_from_tracker_resp(char *buff, size_t len)
{
    char *line,*saveptr;
    char *token, *saveptrtok;
    unsigned cont_len = 0;

    line = strtok_r(buff, "\n", &saveptr);
    if(strncmp(line, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK")) &&
       strncmp(line, "HTTP/1.1 200 OK", strlen("HTTP/1.1 200 OK")))
        goto fail_parse;

    do {
        line = strtok_r(NULL, "\n", &saveptr);

        if(!strncmp(line, "Content-Length:", strlen("Content-Length:"))) {
            token = strtok_r(line, ":", &saveptrtok);
            token = strtok_r(NULL, ":", &saveptrtok);
            cont_len = strtoul(token, NULL, 0);
        }
        
    }while(strlen(line) != 1);

    byte_str_t *ret = byte_str_new(cont_len, line + strlen(line) + 1);
    return ret;

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

tracker_announce_resp_t *tracker_announce(const char *urlstr, tracker_announce_request_t *request)
{
    int sockfd;
    byte_str_t *raw;
    tracker_announce_resp_t *ret;
    char errbuff[64];

    log_printf(LOG_LEVEL_INFO, "Announcing to tracker: %s\n", urlstr);

    url_t *url = url_from_str(urlstr);
    if(!url)
        goto fail_parse_url;

    if(url->protocol == PROTOCOL_HTTPS || url->protocol == PROTOCOL_UDP){
        //TODO
        log_printf(LOG_LEVEL_ERROR, "No support for HTTPS or UDP tracker protocols\n");
        goto fail_protocol;
    }

    char *request_str = build_http_request(url, request);
    log_printf(LOG_LEVEL_DEBUG, "%s", request_str);

    if((sockfd = tracker_connect(url)) < 0)
        goto fail_connect;

    if(tracker_sendall(sockfd, request_str, strlen(request_str)) < 0)
        goto fail_send;

    if(tracker_recv_resp(sockfd, &raw) < 0)
        goto fail_recv;

    ret = tracker_resp_parse(raw);
    if(!ret)
        goto fail_parse;

    close(sockfd);
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
    free(request_str);
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
        //assume ipv4
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

