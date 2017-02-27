#include "sha1.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <endian.h>

#define CIRCULAR_SHIFT_32(X, n) (htobe32((be32toh(X) << (n)) | (be32toh(X) >> (32-(n)))))

#define ADD_32(a, b) (htobe32(be32toh(a) + be32toh(b)))

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D)
{
    if     (0  <= t && t <= 19)
        return ((B & C) | ((~B) & D));
    else if(20 <= t && t <= 39)
        return (B ^ C ^ D);
    else if(40 <= t && t <= 59)
        return ((B & C) | (B & D) | (C & D));
    else if(60 <= t && t <= 79)
        return (B ^ C ^ D);
}

static uint32_t K(int t)
{
    if     (0  <= t && t <= 19)
        return htobe32(0x5A827999);
    else if(20 <= t && t <= 39)
        return htobe32(0x6ED9EBA1);
    else if(40 <= t && t <= 59)
        return htobe32(0x8F1BBCDC);
    else if(60 <= t && t <= 79)
        return htobe32(0xCA62C1D6);
}

static void pad_msg_block(char *out, size_t topad, size_t len)
{
    size_t footer_len = 1 + sizeof(uint64_t);

    if(footer_len >= topad) {
        memset(out + 64, 0, topad);
    }else {
        unsigned tozero = topad - footer_len;
        memset(out + 64 - topad, 0x80, 1);
        memset(out + 64 - topad + 1, 0, tozero);

        assert(tozero + 1 + sizeof(uint64_t) == topad);

        uint64_t len64 = htobe64(len * 8);
        assert(out + 64 - topad + tozero + 1 == out + 64 - sizeof(uint64_t));
        memcpy(out + 64 - topad + tozero + 1, &len64, sizeof(uint64_t));
    }
}

static unsigned num_msg_blocks(size_t len)
{
    return (len / 64) + (64 - (len % 64) >= 1 + sizeof(uint64_t) ? 1 : 2);
}

static int block_at_index(const char *msg, size_t len, int i, char out_block[64])
{
    unsigned left = MAX(len - 64 * i, 0);
    const char *next = msg + i * 64;

    if(left < 64) {
        memcpy(out_block, next, left);
        pad_msg_block(out_block, 64 - left, len);
    }else {
        memcpy(out_block, next, 64);
    }
}

int sha1_compute(const char *msg, size_t len, char out_digest[DIGEST_LEN])
{
    const char *block = NULL;

    uint32_t A, B, C, D, E;
    union {
        unsigned char bytes[DIGEST_LEN];
        uint32_t H[5];
    }digest;
    uint32_t W[80];

    digest.H[0] = htobe32(0x67452301);
    digest.H[1] = htobe32(0xEFCDAB89);
    digest.H[2] = htobe32(0x98BADCFE);
    digest.H[3] = htobe32(0x10325476);
    digest.H[4] = htobe32(0xC3D2E1F0);

    uint32_t msg_block[16];
    for(int i = 0; i < num_msg_blocks(len); i++) {
        block_at_index(msg, len, i, (char*)msg_block);

        for(int t = 0; t <= 15; t++) {
            W[t] = msg_block[t];
        }

        for(int t = 16; t <= 79; t++) {
            W[t] = CIRCULAR_SHIFT_32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        A = digest.H[0]; 
        B = digest.H[1]; 
        C = digest.H[2]; 
        D = digest.H[3]; 
        E = digest.H[4];

        for(int t = 0; t <= 79; t++) {
            uint32_t temp = 
                ADD_32(ADD_32(ADD_32(ADD_32(CIRCULAR_SHIFT_32(A, 5), f(t, B, C, D)), E), W[t]), K(t));

            E = D; D = C; C = CIRCULAR_SHIFT_32(B, 30); B = A; A = temp;
        }

        digest.H[0] = ADD_32(digest.H[0], A);
        digest.H[1] = ADD_32(digest.H[1], B);
        digest.H[2] = ADD_32(digest.H[2], C);
        digest.H[3] = ADD_32(digest.H[3], D);
        digest.H[4] = ADD_32(digest.H[4], E);

    }

    memcpy(out_digest, digest.bytes, DIGEST_LEN);
    return 0;
}
