#include "peer_id.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static const char *s_cli_id = "bf";
static const unsigned int s_major_ver = 0;
static const unsigned int s_minor_ver = 0;

byte_str_t *peer_id_get_new(void)
{
    unsigned char buff[20] = {0};
    int offset = 0;
    unsigned int seed = time(NULL);

    offset += snprintf(buff, 20, "-%.*s%02u%02u-", 2, s_cli_id, s_major_ver, s_minor_ver); 

    for(int i = 0; i < 12/(sizeof(int32_t)); i++){
        int32_t r = rand_r(&seed);
        memcpy(buff + offset, &r, sizeof(r));
        offset += sizeof(r);
    }

    byte_str_t *ret = byte_str_new(20, buff);
    return ret;
}

