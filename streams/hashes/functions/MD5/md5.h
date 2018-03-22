/*********************************************************************
* Filename:   md5.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding MD5 implementation.
*********************************************************************/

#ifndef MD5_H
#define MD5_H

/*************************** HEADER FILES ***************************/
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

/****************************** MACROS ******************************/
#define MD5_BLOCK_SIZE 16               // MD5 outputs a 16 byte digest
#define MD5_DIGEST_LENGTH MD5_BLOCK_SIZE
#define MD5_FULL_ROUNDS 64

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[4];
} MD5_CTX;

typedef unsigned char MD5_DIGEST[MD5_DIGEST_LENGTH];

/*********************** FUNCTION DECLARATIONS **********************/
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const BYTE data[], size_t len, unsigned nr);
void md5_final(MD5_CTX *ctx, BYTE hash[], unsigned nr);

#ifdef __cplusplus
}
#endif


#endif   // MD5_H
