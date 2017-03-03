#include "peer_connection.h"
#include "log.h"
#include "bitfiend_internal.h"
#include "peer_msg.h"

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

typedef struct {
    peer_state_t local;
    peer_state_t remote;
}conn_state_t;

static void print_ip(peer_t *peer, char *outbuff, size_t n)
{
    if(peer->addr.sas.ss_family == AF_INET) {
        inet_ntop(AF_INET, &peer->addr.sa_in.sin_addr, outbuff, n); 
    }else{
        inet_ntop(AF_INET6, &peer->addr.sa_in6.sin6_addr, outbuff, n);        
    }
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

static void peer_connection_cleanup(void *arg)
{
    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    if(parg->has_sockfd)
        close(parg->sockfd);
    log_printf(LOG_LEVEL_INFO, "Closed peer connection: %s\n", ipstr);
    free(arg);
}

static void *peer_connection(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(peer_connection_cleanup, arg){

    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    int sockfd;
    torrent_t *torrent;


    if(parg->has_sockfd) {
        sockfd = parg->sockfd;
    }else{
        if((sockfd = peer_connect(arg)) < 0)
            goto fail_connect;

        parg->sockfd = sockfd;
        parg->has_sockfd = true;
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

    if(parg->has_torrent) {
        torrent = parg->torrent;

        if(peer_send_handshake(sockfd, torrent->info_hash))
            goto fail_handshake;

        if(peer_recv_handshake(sockfd, info_hash, peer_id, true))
            goto fail_handshake;

    }else {
    
        if(peer_recv_handshake(sockfd, info_hash, peer_id, false))
            goto fail_handshake;

        peer_conn_t *conn = malloc(sizeof(peer_conn_t));
        if(!conn)
            goto fail_handshake;
        conn->thread = pthread_self();
        conn->peer = parg->peer;
        /* peer_id not set on conn */
        torrent = bitfiend_assoc_peer(conn, info_hash);
        if(!torrent){
            free(conn);
            goto fail_handshake;
        }

        if(peer_send_handshake(sockfd, torrent->info_hash))
            goto fail_handshake;

        if(peer_recv_buff(sockfd, peer_id, sizeof(peer_id))){
            /* Did not receive last 20 bytes, the peer id*/
            /* This was likely the tracker probing us, drop the connection*/
            goto fail_handshake;
        }

    }
    log_printf(LOG_LEVEL_INFO, "Handshake with peer %s (ID: %.*s) successful\n", ipstr, 20, peer_id);

    peer_msg_t curr_msg;
    curr_msg.type = MSG_KEEPALIVE;

    while(true) {
        // 1. send msg
        // 2. receive msg
        // 3. build up next msg to send;
        // 4. test cancel

        //log_printf(LOG_LEVEL_INFO, "Message sent! Type: %d\n", curr_msg.type);

        //if(!peer_msg_recv(sockfd, &curr_msg, torrent)){
        //    log_printf(LOG_LEVEL_DEBUG, "Received message from peer: Type: %d\n", curr_msg.type);
        //}else{
        //    log_printf(LOG_LEVEL_DEBUG, "Failed to receive response\n");
        //}
        //curr_msg.type = MSG_KEEPALIVE;


        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        /* Cancellation point */
        sleep(5);
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    }

    pthread_exit(NULL);

fail_handshake:
fail_connect:
    log_printf(LOG_LEVEL_WARNING, "Aborting peer connection with %s\n", ipstr);
    pthread_exit(NULL);

    }pthread_cleanup_pop(0);
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

