#ifndef PEER_LISTENER_H
#define PEER_LISTENER_H

#include <pthread.h>
#include <stdint.h>

int peer_listener_create(pthread_t *thread, const uint16_t *port);

#endif
