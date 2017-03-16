#include "peer_id.h"
#include "bitfiend.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define LIBBF_CLIENT_ID "gg" //temp spoof for development

char g_local_peer_id[20];

void peer_id_create(char outbuff[20])
{
    int offset = 0;
    unsigned int seed = time(NULL);

    memset(outbuff, 0, 20);
    offset += snprintf(outbuff, 20, "-%.*s%02u%02u-", 2, LIBBF_CLIENT_ID, LIBBF_VER_MAJOR, LIBBF_VER_MINOR); 

    for(int i = 0; i < 12/(sizeof(int32_t)); i++){
        int32_t r = rand_r(&seed);
        memcpy(outbuff + offset, &r, sizeof(r));
        offset += sizeof(r);
    }
}

