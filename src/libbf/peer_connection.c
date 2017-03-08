#include "peer_connection.h"
#include "log.h"
#include "bitfiend_internal.h"
#include "peer_msg.h"
#include "lbitfield.h"
#include "list.h"
#include "queue.h"
#include "piece_request.h"

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
    peer_state_t   local;
    peer_state_t   remote;
    unsigned char *peer_have;
    unsigned char *peer_wants;
    unsigned char *local_have;
    size_t         bitlen;
    unsigned       pieces_sent;
    unsigned       pieces_recvd;
    queue_t       *peer_requests;
    list_t        *local_requests;
}conn_state_t;

static conn_state_t *conn_state_init(torrent_t *torrent)
{
    conn_state_t *ret = malloc(sizeof(conn_state_t));
    if(!ret)
        return ret;

    ret->local.choked = true;
    ret->local.interested = false;
    ret->remote.choked = true;
    ret->remote.interested = false;

    ret->bitlen = list_get_size(torrent->pieces);
    unsigned num_bytes = LBITFIELD_NUM_BYTES(ret->bitlen);

    ret->peer_have = malloc(num_bytes);
    if(!ret->peer_have)
        goto fail_peer_have;

    ret->peer_wants = malloc(num_bytes);
    if(!ret->peer_wants)
        goto fail_peer_wants;

    ret->peer_requests = queue_init(sizeof(request_msg_t), 16);
    if(!ret->peer_requests)
        goto fail_peer_reqs;

    ret->local_requests = list_init();
    if(!ret->local_requests)
        goto fail_local_reqs;

    pthread_mutex_lock(&torrent->sh_lock);
    ret->local_have = torrent_make_bitfield(torrent);
    pthread_mutex_unlock(&torrent->sh_lock);
    if(!ret->local_have)
        goto fail_local_have;

    ret->pieces_sent = 0;
    ret->pieces_recvd = 0;

    return ret;

fail_local_have:
    free(ret->local_requests);
fail_local_reqs:
    free(ret->peer_requests);
fail_peer_reqs:
    free(ret->peer_wants);
fail_peer_wants:
    free(ret->peer_have);
fail_peer_have:
    free(ret);
    
    return NULL;
}

static void conn_state_cleanup(void *arg)
{
    conn_state_t *state = (conn_state_t*)arg;
    free(state->peer_have);
    free(state->peer_wants);
    free(state->local_have);
    queue_free(state->peer_requests);

    const unsigned char *entry;
    FOREACH_ENTRY(entry, state->local_requests){
        piece_request_free(*(piece_request_t**)entry);
    }
    list_free(state->local_requests);

    free(state);
}

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

static void service_have_events(int sockfd, mqd_t queue, const torrent_t *torrent, unsigned char *havebf)
{
    uint32_t have;
    peer_msg_t msg;
    msg.type = MSG_HAVE;
    int ret;

    while((ret = mq_receive(queue, (char*)&have, sizeof(uint32_t), 0)) == sizeof(uint32_t)){
        msg.payload.have = have;
        LBITFIELD_SET(have, havebf);
        if(peer_msg_send(sockfd, &msg, torrent))
            break;
        log_printf(LOG_LEVEL_INFO, "event serviced!: have sent to peer: %u\n", have);
    }
}

static void process_piece_msg(conn_state_t *state, piece_msg_t *msg)
{
    /* The block got written to the underlying file(s) already from tcp buffer by the recv routine.
     * Here we check if we've gotten a complete piece so far, verify it by the SHA1 hash if so,
     * and update the torrent state*/

    const unsigned char *entry;
    FOREACH_ENTRY(entry, state->local_requests) {
        piece_request_t *curr = *(piece_request_t**)entry;

        if(curr->piece_index == msg->index) {

            const unsigned char *block;
            FOREACH_ENTRY(block, curr->block_requests) {
                block_request_t *br = *(block_request_t**)block;

                if(br->len == msg->blocklen && br->begin == msg->begin) {
                    br->completed = true;                             
                    curr->blocks_left--;
                    break;     
                }
            }

            if(curr->blocks_left == 0){
                /*We've got the entire piece!*/
            }

        }
    }
}

static void process_msg(peer_msg_t *msg, conn_state_t *state, torrent_t *torrent)
{
    switch(msg->type){
        case MSG_KEEPALIVE:
            break;
        case MSG_CHOKE:
            state->local.choked = true;
            break;
        case MSG_UNCHOKE:
            state->local.choked = false;
            break;
        case MSG_INTERESTED:
            state->remote.interested = true;
            break;
        case MSG_NOT_INTERESTED:
            state->remote.interested = false; 
        case MSG_HAVE:
            LBITFIELD_SET(msg->payload.have, state->peer_have);
            break;
        case MSG_BITFIELD:
            assert(msg->payload.bitfield->size == LBITFIELD_NUM_BYTES(state->bitlen));
            memcpy(state->peer_have, msg->payload.bitfield->str, LBITFIELD_NUM_BYTES(state->bitlen));    
            break;
        case MSG_REQUEST:
            queue_push(state->peer_requests, &msg->payload.request);
            break; 
        case MSG_PIECE:
        {
            process_piece_msg(state, &msg->payload.piece);
            break;
        }
        case MSG_CANCEL:
            /*Remove the request from the request queue */
            break;
        case MSG_PORT:
            //TODO 
            break;
        default:
            break;
    }
}

static void *peer_connection(void *arg)
{
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(peer_connection_cleanup, arg);{

    peer_arg_t *parg = (peer_arg_t*)arg;
    char ipstr[INET6_ADDRSTRLEN];
    print_ip(&parg->peer, ipstr, sizeof(ipstr));

    mqd_t             queue;
    int               sockfd;
    torrent_t        *torrent;
    char              peer_id[20];
    char              info_hash[20];
    conn_state_t     *state;

    /* Init queue for "have" events */
    queue = peer_queue_open(O_RDONLY | O_CREAT | O_NONBLOCK);
    if(queue == (mqd_t)-1)
        goto fail_init;

    /* Init "sockfd" */
    if(parg->has_sockfd) {
        sockfd = parg->sockfd;
    }else{
        if((sockfd = peer_connect(arg)) < 0)
            goto fail_init;

        parg->sockfd = sockfd;
        parg->has_sockfd = true;
    }
    if(sockfd < 0)
        goto fail_init;

    /* Handshake, intializing "torrent" */
    if(handshake(sockfd, parg, peer_id, info_hash, &torrent))
        goto fail_init;
    log_printf(LOG_LEVEL_INFO, "Handshake with peer %s (ID: %.*s) successful\n", ipstr, 20, peer_id);

    /* Init state */
    state = conn_state_init(torrent);
    if(!state)
        goto fail_init;
    pthread_cleanup_push(conn_state_cleanup, state);{

    peer_msg_t send_msg, recv_msg;
    send_msg.type = MSG_KEEPALIVE;

    while(true) {

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        service_have_events(sockfd, queue, torrent, state->local_have);

        while(peer_msg_buff_nonempty(sockfd)) {

            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            pthread_testcancel();
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

            peer_msg_t msg;

            if(peer_msg_recv(sockfd, &msg, torrent))
                goto abort_conn;
            process_msg(&msg, state, torrent);
            if(msg.type == MSG_BITFIELD)
                byte_str_free(msg.payload.bitfield);
        }

    }

abort_conn: ;
    }pthread_cleanup_pop(1);
fail_init: ;
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
