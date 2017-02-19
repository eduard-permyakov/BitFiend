#include "byte_str.h"

#include <stdlib.h>
#include <string.h>

byte_str_t *byte_str_new(size_t size, const unsigned char *str)
{
    byte_str_t *ret;
    ret = malloc(sizeof(byte_str_t) + size + 1);
    if(ret) {
        memcpy(ret->str, str, size);
        ret->str[size] = '\0';
    }
    return ret;
}

void byte_str_free(byte_str_t *str)
{
    free(str);
}

