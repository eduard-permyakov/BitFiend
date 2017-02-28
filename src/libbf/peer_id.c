#include "peer_id.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

char                        g_local_peer_id[20];

static const char          *s_cli_id = "gg"; //temp spoof for develpment
static const unsigned int   s_major_ver = 0;
static const unsigned int   s_minor_ver = 0;

void peer_id_create(char outbuff[20])
{
    int offset = 0;
    unsigned int seed = time(NULL);

    memset(outbuff, 0, 20);
    offset += snprintf(outbuff, 20, "-%.*s%02u%02u-", 2, s_cli_id, s_major_ver, s_minor_ver); 

    for(int i = 0; i < 12/(sizeof(int32_t)); i++){
        int32_t r = rand_r(&seed);
        memcpy(outbuff + offset, &r, sizeof(r));
        offset += sizeof(r);
    }
}

