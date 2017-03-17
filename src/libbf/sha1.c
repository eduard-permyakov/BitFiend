/*    
 *  This file is part of BitFiend. 
 *  Copyright (C) 2017 Eduard Permyakov 
 *
 *  BitFiend is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BitFiend is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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

struct sha1_context{
    union {
        unsigned char bytes[DIGEST_LEN];
        uint32_t H[5];
    }digest;
    uint32_t     last_block[16];       
    size_t       incomp_block_sz;
    size_t       tot_len;
};

static uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D);
static uint32_t K(int t);
static void     pad_msg_block(char *msgbuff, size_t topad, size_t len, bool stopbit);
static unsigned num_msg_blocks(size_t len);
static int      next_block(sha1_context_t *ctx, const char *msg, size_t len);


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

static void pad_msg_block(char *msgbuff, size_t topad, size_t len, bool stopbit)
{
    size_t footer_len = 1 + sizeof(uint64_t);
    assert(topad <= 64 && topad >= footer_len);

    unsigned tozero = topad - footer_len;
    memset(msgbuff + (64 - topad), (stopbit ? 0x80 : 0x00), 1);
    memset(msgbuff + (64 - topad) + 1, 0, tozero);

    assert(tozero + 1 + sizeof(uint64_t) == topad);

    uint64_t len64 = htobe64(len * 8);
    assert(msgbuff + (64 - topad) + tozero + 1 == msgbuff + 64 - sizeof(uint64_t));
    memcpy(msgbuff + (64 - topad) + tozero + 1, &len64, sizeof(uint64_t));
}

static unsigned num_msg_blocks(size_t len)
{
    return (len / 64) + ((len % 64) ? 1 : 0);
}

static int next_block(sha1_context_t *ctx, const char *msg, size_t len)
{
    size_t consume = MIN(len, 64 - ctx->incomp_block_sz);
    memcpy(((char*)ctx->last_block) + ctx->incomp_block_sz, msg, consume);

    size_t bsize = ctx->incomp_block_sz + consume;
    ctx->incomp_block_sz = bsize % 64;
    ctx->tot_len += consume;

    return consume;
}

int sha1_compute(const char *msg, size_t len, char out_digest[DIGEST_LEN])
{
    sha1_context_t *ctx = sha1_context_init();
    if(!ctx)
        return -1;

    sha1_update(ctx, msg, len); 
    sha1_finish(ctx, out_digest);

    sha1_context_free(ctx);
    return 0;
}

sha1_context_t *sha1_context_init(void)
{
    sha1_context_t *ret = malloc(sizeof(sha1_context_t));
    if(ret) {
        ret->digest.H[0] = htobe32(0x67452301);
        ret->digest.H[1] = htobe32(0xEFCDAB89);
        ret->digest.H[2] = htobe32(0x98BADCFE);
        ret->digest.H[3] = htobe32(0x10325476);
        ret->digest.H[4] = htobe32(0xC3D2E1F0);

        ret->incomp_block_sz = 0;
        ret->tot_len = 0;
    }
    return ret;
}

void sha1_update(sha1_context_t *ctx, const char *msg, size_t len)
{
    unsigned tot_blocks = num_msg_blocks(len);
    for(unsigned i = 0; i < tot_blocks; i++) {

        uint32_t A, B, C, D, E;
        uint32_t W[80];

        size_t consume = next_block(ctx, msg, len);
        assert(consume >= 0 && consume <= 64);
        assert(len - consume >= 0);
        msg += consume;
        len -= consume;

        if(ctx->incomp_block_sz > 0)
            break;

        for(int t = 0; t <= 15; t++) {
            W[t] = ctx->last_block[t];
        }

        for(int t = 16; t <= 79; t++) {
            W[t] = CIRCULAR_SHIFT_32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        A = ctx->digest.H[0]; 
        B = ctx->digest.H[1]; 
        C = ctx->digest.H[2]; 
        D = ctx->digest.H[3]; 
        E = ctx->digest.H[4];

        for(int t = 0; t <= 79; t++) {
            uint32_t temp = 
                ADD_32(ADD_32(ADD_32(ADD_32(CIRCULAR_SHIFT_32(A, 5), f(t, B, C, D)), E), W[t]), K(t));

            E = D; D = C; C = CIRCULAR_SHIFT_32(B, 30); B = A; A = temp;
        }

        ctx->digest.H[0] = ADD_32(ctx->digest.H[0], A);
        ctx->digest.H[1] = ADD_32(ctx->digest.H[1], B);
        ctx->digest.H[2] = ADD_32(ctx->digest.H[2], C);
        ctx->digest.H[3] = ADD_32(ctx->digest.H[3], D);
        ctx->digest.H[4] = ADD_32(ctx->digest.H[4], E);
    }
}

void sha1_finish(sha1_context_t *ctx, char digest[DIGEST_LEN])
{
    char msg_block[64];
    bool stopbit = true;

    if(64 - ctx->incomp_block_sz < 1 + sizeof(uint64_t)){
        memcpy(msg_block, ctx->last_block, ctx->incomp_block_sz);

        size_t topad = 64 - ctx->incomp_block_sz;
        assert(topad >= 1);
        memset(msg_block + ctx->incomp_block_sz, 0x80, 1);
        memset(msg_block + ctx->incomp_block_sz + 1, 0x00, topad - 1);
        stopbit = false;

        ctx->incomp_block_sz = 0;

        sha1_update(ctx, msg_block, 64);
        assert(ctx->incomp_block_sz == 0);
    }

    memcpy(msg_block, ctx->last_block, ctx->incomp_block_sz);
    pad_msg_block(msg_block, 64 - ctx->incomp_block_sz, ctx->tot_len, stopbit);
    ctx->incomp_block_sz = 0;

    sha1_update(ctx, msg_block, 64);

    memcpy(digest, ctx->digest.bytes, DIGEST_LEN);
}

void sha1_context_free(sha1_context_t *ctx)
{
    free(ctx);
}

