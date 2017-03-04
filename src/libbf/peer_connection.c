#include "peer_connection.h"
#include "log.h"
#include "bitfiend_internal.h"
#include "peer_msg.h"
#include "lbitfield.h"

#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <sys/queue.h>

#define PEER_CONNECT_TIMEOUT_SEC 5
#define PEER_TIMEOUT_SEC         120

typedef struct peer_state {
    bool choked;
    bool interested;
}peer_state_t;

typedef struct {
    peer_state_t local;
    peer_state_t remote;
}conn_state_t;

typedef struct peer_bitfields {
    unsigned char *have;
    unsigned char *wants;
}peer_bitfields_t;

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
    timeout.tv_sec = PEER_CONNECT_TIMEOUT_SEC;
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
            ipstr, PEER_CONNECT_TIMEOUT_SEC);
        goto fail;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

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

static int handshake(int sockfd, peer_arg_t *parg, char peer_id[20], char info_hash[20], torrent_t **out)
{
    if(parg->has_torrent) {
        *out = parg->torrent;

        if(peer_send_handshake(sockfd, (*out)->info_hash))
            return -1;

        if(peer_recv_handshake(sockfd, info_hash, peer_id, true))
            return -1;

    }else {
    
        if(peer_recv_handshake(sockfd, info_hash, peer_id, false))
            return -1;

        peer_conn_t *conn = malloc(sizeof(peer_conn_t));
        if(!conn)
            return -1;
        conn->thread = pthread_self();
        conn->peer = parg->peer;

        /* peer_id not set on conn */
        *out = bitfiend_assoc_peer(conn, info_hash);
        if(!*out){
            free(conn);
            return -1;
        }

        if(peer_send_handshake(sockfd, (*out)->info_hash))
            return -1;

        if(peer_recv_buff(sockfd, peer_id, sizeof(peer_id))){
            /* Did not receive last 20 bytes, the peer id*/
            /* This was likely the tracker probing us, drop the connection*/
            return -1;
        }

    }

    return 0;
}

typedef struct cleanup_arg {
    int sockfd;
    mqd_t queue;
}cleanup_arg_t;

static void peer_connection_cleanup(void *arg)
{
    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    if(parg->has_sockfd){
        shutdown(parg->sockfd, SHUT_RDWR);
        close(parg->sockfd);
    }
    log_printf(LOG_LEVEL_INFO, "Closed peer connection: %s\n", ipstr);
    free(arg);
}

//static void peer_connection_queue_cleanup(void *arg)
//{
//    char queue_name[64];
//    peer_connection_queue_name(pthread_self(), queue_name, sizeof(queue_name));
//    log_printf(LOG_LEVEL_INFO, "Closed queue from receiver: %s\n", queue_name);
//    mq_close(*(mqd_t*)arg);
//    free(arg);
//}

//TODO stop this from accessing stack variable
static void peer_connection_bitfields_cleanup(void *arg)
{
    peer_bitfields_t *bfs = (peer_bitfields_t*)arg;
    free(bfs->have);
    free(bfs->wants);
}

static mqd_t peer_queue_open(int flags)
{
    mqd_t ret;
    char queue_name[64];
    peer_connection_queue_name(pthread_self(), queue_name, sizeof(queue_name));

    struct mq_attr attr;
    attr.mq_flags = O_NONBLOCK; 
    attr.mq_maxmsg = 10; //TODO: get max value for this with getrlimit
    attr.mq_msgsize = sizeof(unsigned);
    attr.mq_curmsgs = 0;

    ret = mq_open(queue_name, flags, 0600, &attr);
    if(ret != (mqd_t)-1)
        log_printf(LOG_LEVEL_INFO, "Successfully opened message queue from receiver thread: %s\n", queue_name);
    else
        log_printf(LOG_LEVEL_ERROR, "Failed to open queue in receiver thread: %s\n", queue_name);

    return ret;
}

static void *peer_connection(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(peer_connection_cleanup, arg){

    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    mqd_t            queue;
    int              sockfd;
    torrent_t       *torrent;
    char             peer_id[20];
    char             info_hash[20];
    peer_bitfields_t bfs;
    conn_state_t     state;

    queue = peer_queue_open(O_RDONLY | O_CREAT);
    if(queue == (mqd_t)-1)
        goto fail;

    //mqd_t *qarg = malloc(sizeof(mqd_t));
    //if(!qarg){
    //    mq_close(queue);
    //    goto fail_queue;
    //}
    //*qarg = queue; 
    //pthread_cleanup_push(peer_connection_queue_cleanup, qarg){

    if(parg->has_sockfd) {
        sockfd = parg->sockfd;
    }else{
        if((sockfd = peer_connect(arg)) < 0)
            goto fail;

        parg->sockfd = sockfd;
        parg->has_sockfd = true;
    }
    if(sockfd < 0)
        goto fail;

    if(handshake(sockfd, parg, peer_id, info_hash, &torrent))
        goto fail;
    log_printf(LOG_LEVEL_INFO, "Handshake with peer %s (ID: %.*s) successful\n", ipstr, 20, peer_id);

    state.local.choked = true;
    state.local.interested = false;
    state.remote.choked = true;
    state.remote.interested = false;

    bfs.have = calloc(LBITFIELD_NUM_BYTES(list_get_size(torrent->pieces)), 1);
    if(!bfs.have)
        goto fail;

    bfs.wants = calloc(LBITFIELD_NUM_BYTES(list_get_size(torrent->pieces)), 1);
    if(!bfs.wants){
        free(bfs.have);
        goto fail;
    }
    //push another cleanup handler for dealloc'ing bitfields

    peer_msg_t send_msg, recv_msg;
    send_msg.type = MSG_KEEPALIVE;

    while(true) {
        // 1. send msg
        // 2. receive msg -- 2 min timeout on this
        // 3. build up next msg to send;
        // 4. test cancel
        if(peer_msg_send(sockfd, &send_msg, torrent))
            goto fail;

        /* Cancellation point, sets cancel state to enabled while waiting for first byte */
        if(peer_msg_waiton_recv(sockfd, &recv_msg, torrent, PEER_TIMEOUT_SEC))
            goto fail;

        log_printf(LOG_LEVEL_DEBUG, "Received message from peer. Type: %d\n", recv_msg.type);

        switch(recv_msg.type) {
            case MSG_CHOKE:
            {
                state.local.choked = true;
                break;
            }
            case MSG_UNCHOKE:
            {
                state.local.interested = false;
                break;
            }
            case MSG_INTERESTED:
            {
                state.remote.interested = true;
                break;
            }
            case MSG_NOT_INTERESTED:
            {
                state.remote.interested = false;
                break;
            }
            case MSG_HAVE:
            {
                LBITFIELD_SET(recv_msg.payload.have, bfs.wants);
                bitfiend_notify_peers_have(torrent, recv_msg.payload.have);
                break;
            }
            case MSG_BITFIELD:
            {
                size_t bitfsize = LBITFIELD_NUM_BYTES(list_get_size(torrent->pieces));
                assert(recv_msg.payload.bitfield->size == bitfsize);
                memcpy(bfs.have, recv_msg.payload.bitfield->str, bitfsize); 
                byte_str_free(recv_msg.payload.bitfield);
                break;
            }
            case MSG_REQUEST:
            {
                break;
            }
            case MSG_PIECE:
            {
                break;
            }
            case MSG_CANCEL:
            {
                break;
            }
            case MSG_PORT:
            {
                break;
            }
            case MSG_MAX:
            {
                break;
            }
            case MSG_KEEPALIVE:
            {
                break;
            }
            default:
                goto fail;
        }
    }

fail:
    log_printf(LOG_LEVEL_WARNING, "Aborting peer connection with %s\n", ipstr);
    }pthread_cleanup_pop(1);
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

void peer_connection_queue_name(pthread_t thread, char *out, size_t len)
{
    assert(len >= strlen("/") + 2*sizeof(pthread_t) + strlen("_queue") + 1);
    size_t plen = 0;
    plen += snprintf(out, len - plen, "/");
    for(unsigned char *cp  = (unsigned char*)thread; 
        cp < ((unsigned char*)thread) + sizeof(pthread_t); cp++) {
        plen += snprintf(out + plen, len - plen, "%02X", *cp);
        if(plen == len) 
            return;
    }
    snprintf(out + plen, len - plen, "_queue");
}
