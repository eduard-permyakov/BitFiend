#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>

#define DIGEST_LEN 20

int sha1_compute(const char *msg, size_t len, char digest[20]);

#endif
