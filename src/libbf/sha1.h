#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>

#define DIGEST_LEN 20

typedef struct sha1_context sha1_context_t;

sha1_context_t *sha1_context_init(void);
void            sha1_context_free(sha1_context_t *ctx);
void            sha1_update(sha1_context_t *ctx, const char *msg, size_t len);
void            sha1_finish(sha1_context_t *ctx, char digest[DIGEST_LEN]);

int             sha1_compute(const char *msg, size_t len, char digest[DIGEST_LEN]);

#endif
