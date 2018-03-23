//
// Created by Dusan Klinec on 22/03/2018.
// https://raw.githubusercontent.com/clibs/sha1/master/sha1.c
//

#include "sha1.h"
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain

Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */

#define SHA1HANDSOFF

#include <cstdio>
#include <cstring>

/* for uint32_t */
#include <cstdint>
#include "sha1.h"


#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(
    uint32_t state[5],
    const unsigned char buffer[64],
    unsigned nr
)
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 block[1];      /* use array to appear as a pointer */

    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
    CHAR64LONG16 *block = (const CHAR64LONG16 *) buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0); if (nr == 1) goto finish;
    R0(e, a, b, c, d, 1); if (nr == 2) goto finish;
    R0(d, e, a, b, c, 2); if (nr == 3) goto finish;
    R0(c, d, e, a, b, 3); if (nr == 4) goto finish;
    R0(b, c, d, e, a, 4); if (nr == 5) goto finish;
    R0(a, b, c, d, e, 5); if (nr == 6) goto finish;
    R0(e, a, b, c, d, 6); if (nr == 7) goto finish;
    R0(d, e, a, b, c, 7); if (nr == 8) goto finish;
    R0(c, d, e, a, b, 8); if (nr == 9) goto finish;
    R0(b, c, d, e, a, 9); if (nr == 10) goto finish;
    R0(a, b, c, d, e, 10); if (nr == 11) goto finish;
    R0(e, a, b, c, d, 11); if (nr == 12) goto finish;
    R0(d, e, a, b, c, 12); if (nr == 13) goto finish;
    R0(c, d, e, a, b, 13); if (nr == 14) goto finish;
    R0(b, c, d, e, a, 14); if (nr == 15) goto finish;
    R0(a, b, c, d, e, 15); if (nr == 16) goto finish;
    R1(e, a, b, c, d, 16); if (nr == 17) goto finish;
    R1(d, e, a, b, c, 17); if (nr == 18) goto finish;
    R1(c, d, e, a, b, 18); if (nr == 19) goto finish;
    R1(b, c, d, e, a, 19); if (nr == 20) goto finish;
    R2(a, b, c, d, e, 20); if (nr == 21) goto finish;
    R2(e, a, b, c, d, 21); if (nr == 22) goto finish;
    R2(d, e, a, b, c, 22); if (nr == 23) goto finish;
    R2(c, d, e, a, b, 23); if (nr == 24) goto finish;
    R2(b, c, d, e, a, 24); if (nr == 25) goto finish;
    R2(a, b, c, d, e, 25); if (nr == 26) goto finish;
    R2(e, a, b, c, d, 26); if (nr == 27) goto finish;
    R2(d, e, a, b, c, 27); if (nr == 28) goto finish;
    R2(c, d, e, a, b, 28); if (nr == 29) goto finish;
    R2(b, c, d, e, a, 29); if (nr == 30) goto finish;
    R2(a, b, c, d, e, 30); if (nr == 31) goto finish;
    R2(e, a, b, c, d, 31); if (nr == 32) goto finish;
    R2(d, e, a, b, c, 32); if (nr == 33) goto finish;
    R2(c, d, e, a, b, 33); if (nr == 34) goto finish;
    R2(b, c, d, e, a, 34); if (nr == 35) goto finish;
    R2(a, b, c, d, e, 35); if (nr == 36) goto finish;
    R2(e, a, b, c, d, 36); if (nr == 37) goto finish;
    R2(d, e, a, b, c, 37); if (nr == 38) goto finish;
    R2(c, d, e, a, b, 38); if (nr == 39) goto finish;
    R2(b, c, d, e, a, 39); if (nr == 40) goto finish;
    R3(a, b, c, d, e, 40); if (nr == 41) goto finish;
    R3(e, a, b, c, d, 41); if (nr == 42) goto finish;
    R3(d, e, a, b, c, 42); if (nr == 43) goto finish;
    R3(c, d, e, a, b, 43); if (nr == 44) goto finish;
    R3(b, c, d, e, a, 44); if (nr == 45) goto finish;
    R3(a, b, c, d, e, 45); if (nr == 46) goto finish;
    R3(e, a, b, c, d, 46); if (nr == 47) goto finish;
    R3(d, e, a, b, c, 47); if (nr == 48) goto finish;
    R3(c, d, e, a, b, 48); if (nr == 49) goto finish;
    R3(b, c, d, e, a, 49); if (nr == 50) goto finish;
    R3(a, b, c, d, e, 50); if (nr == 51) goto finish;
    R3(e, a, b, c, d, 51); if (nr == 52) goto finish;
    R3(d, e, a, b, c, 52); if (nr == 53) goto finish;
    R3(c, d, e, a, b, 53); if (nr == 54) goto finish;
    R3(b, c, d, e, a, 54); if (nr == 55) goto finish;
    R3(a, b, c, d, e, 55); if (nr == 56) goto finish;
    R3(e, a, b, c, d, 56); if (nr == 57) goto finish;
    R3(d, e, a, b, c, 57); if (nr == 58) goto finish;
    R3(c, d, e, a, b, 58); if (nr == 59) goto finish;
    R3(b, c, d, e, a, 59); if (nr == 60) goto finish;
    R4(a, b, c, d, e, 60); if (nr == 61) goto finish;
    R4(e, a, b, c, d, 61); if (nr == 62) goto finish;
    R4(d, e, a, b, c, 62); if (nr == 63) goto finish;
    R4(c, d, e, a, b, 63); if (nr == 64) goto finish;
    R4(b, c, d, e, a, 64); if (nr == 65) goto finish;
    R4(a, b, c, d, e, 65); if (nr == 66) goto finish;
    R4(e, a, b, c, d, 66); if (nr == 67) goto finish;
    R4(d, e, a, b, c, 67); if (nr == 68) goto finish;
    R4(c, d, e, a, b, 68); if (nr == 69) goto finish;
    R4(b, c, d, e, a, 69); if (nr == 70) goto finish;
    R4(a, b, c, d, e, 70); if (nr == 71) goto finish;
    R4(e, a, b, c, d, 71); if (nr == 72) goto finish;
    R4(d, e, a, b, c, 72); if (nr == 73) goto finish;
    R4(c, d, e, a, b, 73); if (nr == 74) goto finish;
    R4(b, c, d, e, a, 74); if (nr == 75) goto finish;
    R4(a, b, c, d, e, 75); if (nr == 76) goto finish;
    R4(e, a, b, c, d, 76); if (nr == 77) goto finish;
    R4(d, e, a, b, c, 77); if (nr == 78) goto finish;
    R4(c, d, e, a, b, 78); if (nr == 79) goto finish;
    R4(b, c, d, e, a, 79); if (nr == 80) goto finish;

    /* Add the working vars back into context.state[] */
finish:
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(
    SHA1_CTX * context
)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(
    SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len,
    unsigned nr
)
{
    uint32_t i;

    uint32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            SHA1Transform(context->state, &data[i], nr);
        }
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context,
    unsigned nr
)
{
    unsigned i;

    unsigned char finalcount[8];

    unsigned char c;

#if 0    /* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
        uint32_t t = context->count[i];

        int j;

        for (j = 0; j < 4; t >>= 8, j++)
            *--fcp = (unsigned char) t}
#else
    for (i = 0; i < 8; i++)
    {
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);      /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1, nr);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1, nr);
    }
    SHA1Update(context, finalcount, 8, nr); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
    {
        digest[i] = (unsigned char)
            ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

void SHA1(
    char *hash_out,
    const char *str,
    int len,
    unsigned nr)
{
    SHA1_CTX ctx{};
    unsigned int ii;

    SHA1Init(&ctx);
    for (ii=0; ii<len; ii+=1)
        SHA1Update(&ctx, (const unsigned char*)str + ii, 1, nr);
    SHA1Final((unsigned char *)hash_out, &ctx, nr);
    hash_out[20] = '\0';
}
