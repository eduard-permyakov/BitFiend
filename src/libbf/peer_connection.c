#include "peer_connection.h"
#include "log.h"
#include "peer_id.h"
#include "bitfiend_internal.h"

#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#define PEER_CONN_TIMEOUT_SEC 5

typedef struct peer_state {
    bool choked;
    bool interested;
}peer_state_t;

typedef struct{
    peer_state_t local;
    peer_state_t remote;
}conn_state_t;

typedef enum{
    MSG_CHOKE           = 0,
    MSG_UNCHOKE         = 1,
    MSG_INTERESTED      = 2,
    MSG_NOT_INTERESTED  = 3,
    MSG_HAVE            = 4,
    MSG_BITFIELD        = 5,
    MSG_REQUEST         = 6,
    MSG_PIECE           = 7,
    MSG_CANCEL          = 8  
}msg_type_t;

static void print_ip(peer_t *peer, char *outbuff, size_t n)
{
    if(peer->addr.sas.ss_family == AF_INET) {
        inet_ntop(AF_INET, &peer->addr.sa_in.sin_addr, outbuff, n); 
    }else{
        inet_ntop(AF_INET6, &peer->addr.sa_in6.sin6_addr, outbuff, n);        
    }
}

static int send_buff(int sockfd, const char *buff, size_t len)
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

static int recv_buff(int sockfd, char *buff, size_t len)
{
    unsigned tot_recv = 0;
    ssize_t nb;

    do {
        nb = recv(sockfd, buff + tot_recv, len - tot_recv, 0);
        if(nb < 0){
            return -1;
        }

        tot_recv += nb;

    }while(nb > 0 && tot_recv < len);

    if(tot_recv == len)
        return 0;
    else
        return -1;
}

static int recv_handshake(int sockfd, char outhash[20], char outpeerid[20], bool peer_id)
{
    const char *pstr = "BitTorrent protocol"; 
    unsigned char pstrlen = strlen(pstr);
    const char reserved[8] = {0};  

    size_t bufflen = 1 + pstrlen + sizeof(reserved) + sizeof(char[20])
       + (peer_id ? sizeof(g_local_peer_id) : 0);

    char buff[bufflen];
    if(recv_buff(sockfd, buff, bufflen))
        return -1;

    off_t off = 0;
    if(buff[off] != pstrlen)
        return -1;
    off++;
    if(strncmp(buff + off, pstr, pstrlen))
        return -1;
    off += pstrlen;

    /*Skip checking the reserved bits for now*/
    off += 8; 

    memcpy(outhash, buff + off, sizeof(char[20]));            
    if(peer_id) {
        off += sizeof(char[20]);
        memcpy(outpeerid, buff + off, sizeof(g_local_peer_id));
    }

    return 0;
}

static int send_handshake(int sockfd, torrent_t *torrent)
{
    const char *pstr = "BitTorrent protocol"; 
    unsigned char pstrlen = strlen(pstr);
    const char reserved[8] = {0};  

    size_t bufflen = 1 + pstrlen + sizeof(reserved) + sizeof(torrent->info_hash)
        + sizeof(g_local_peer_id);
    assert(bufflen == 68);

    off_t off = 0;
    char buff[bufflen];

    buff[0] = pstrlen;
    off++;

    memcpy(buff + off, pstr, pstrlen);
    off += pstrlen;
    assert(off == 20);

    memcpy(buff + off, reserved, sizeof(reserved));
    off += sizeof(reserved);
    assert(off == 28);
    assert(sizeof(torrent->info_hash) == 20);

    memcpy(buff + off, torrent->info_hash, sizeof(torrent->info_hash));
    off += sizeof(torrent->info_hash);

    memcpy(buff + off, g_local_peer_id, sizeof(g_local_peer_id));
    
    return send_buff(sockfd, buff, bufflen);
}

static int peer_connect(peer_arg_t *arg)
{
    int sockfd;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&arg->peer, ipstr, sizeof(ipstr));

    sockfd = socket(arg->peer.addr.sas.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(sockfd < 0)
        return sockfd;

    socklen_t len = 0;
    if(arg->peer.addr.sas.ss_family == AF_INET){
        len = sizeof(arg->peer.addr.sa_in);
    }else if(arg->peer.addr.sas.ss_family == AF_INET6){
        len = sizeof(arg->peer.addr.sa_in6);
    }

    int ret;
    ret = connect(sockfd, &arg->peer.addr.sa, len);
    if(!(ret == 0 || errno == EINPROGRESS))
        goto fail;

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    struct timeval timeout;
    timeout.tv_sec = PEER_CONN_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (select(sockfd + 1, NULL, &fdset, NULL, &timeout) > 0){
        int so_error;
        socklen_t len = sizeof(so_error);

        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error)
            goto fail;
    }else{
        /*Timeout*/
        log_printf(LOG_LEVEL_INFO, "Peer (%s) connection attempt timed out after %u seconds\n", 
            ipstr, PEER_CONN_TIMEOUT_SEC);
        goto fail;
    }

    int opts = fcntl(sockfd, F_GETFL);
    opts &= ~O_NONBLOCK;
    fcntl(sockfd, F_SETFL, opts);

    log_printf(LOG_LEVEL_INFO, "Successfully established connection to peer at: %s (sockfd: %d)\n",
        ipstr, sockfd);
    return sockfd;

fail:
    close(sockfd);
    return -1;
}

static void *peer_connection(void *arg)
{
    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    int sockfd;
    torrent_t *torrent;

    if(parg->has_sockfd) {
        sockfd = parg->sockfd;
    }else{
        sockfd = peer_connect(arg);
    }
    if(sockfd < 0)
        goto fail_connect;

    char peer_id[20];
    char info_hash[20];

    conn_state_t state;
    state.local.choked = true;
    state.local.interested = false;
    state.remote.choked = true;
    state.remote.interested = false;

    //when has torrent - send first, then recv
    //when no torrent, recv first, then send
    if(parg->has_torrent) {
        torrent = parg->torrent;

        if(send_handshake(sockfd, torrent))
            goto fail_handshake;

        if(recv_handshake(sockfd, info_hash, peer_id, true))
            goto fail_handshake;

    }else {
    
        if(recv_handshake(sockfd, info_hash, peer_id, false))
            goto fail_handshake;

        peer_conn_t *conn = malloc(sizeof(peer_conn_t));
        if(!conn)
            goto fail_handshake;
        conn->thread = pthread_self();
        conn->peer = parg->peer;
        torrent = bitfiend_assoc_peer(conn, info_hash);
        if(!torrent){
            free(conn);
            goto fail_handshake;
        }

        if(send_handshake(sockfd, torrent))
            goto fail_handshake;
    }
    log_printf(LOG_LEVEL_INFO, "Handshake with peer %s successful\n", ipstr);

    close(sockfd);
    log_printf(LOG_LEVEL_INFO, "Closed peer (%s) socket connection: %d\n", ipstr, sockfd);
    free(arg);
    pthread_exit(NULL);

fail_handshake:
    close(sockfd);
fail_connect:
    free(arg);
    pthread_exit(NULL);
}

int peer_connection_create(pthread_t *thread, peer_arg_t *arg)
{
    if(pthread_create(thread, NULL, peer_connection, (void*)arg))    
        goto fail_create_thread;

    return 0;

fail_create_thread:
    log_printf(LOG_LEVEL_ERROR, "Failed to create peer connection thread\n");
    return -1;    
}

