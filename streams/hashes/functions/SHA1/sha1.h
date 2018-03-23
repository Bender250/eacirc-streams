//
// Created by Dusan Klinec on 22/03/2018.
// https://raw.githubusercontent.com/clibs/sha1/master/sha1.h
//

#ifndef EACIRC_STREAMS_SHA1_H
#define EACIRC_STREAMS_SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include <cstdint>
#define SHA1_FULL_ROUNDS 64

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
    uint32_t state[5],
    const unsigned char buffer[64]
);

void SHA1Init(
    SHA1_CTX * context
);

void SHA1Update(
    SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len,
    unsigned nr
);

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context,
    unsigned nr
);

void SHA1(
    char *hash_out,
    const char *str,
    int len,
    unsigned nr);


#endif //EACIRC_STREAMS_SHA1_H
