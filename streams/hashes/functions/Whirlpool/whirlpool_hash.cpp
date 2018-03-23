/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <cstdlib>
#include <cstring>
#include <memory>
#include "whirlpool_hash.h"

/*********************** SHA3 adapter **********************/
namespace hash {
    Whirlpool::Whirlpool(const int numRounds) {
        if (numRounds <= 0 || numRounds > WHIRPOOL_ROUNDS) {
            throw std::out_of_range("Valid numRounds range for Whirlpool is <1-10>");
        }

        this->m_rounds = (unsigned) numRounds;
    }

    int Whirlpool::Init(int hashbitlen) {
        if (hashbitlen != 256) {
            throw std::out_of_range("SHA256 supports only 256 bit output");
        }

        rhash_whirlpool_init(&(this->m_state));
        return 0;
    }

    int Whirlpool::Update(const BitSequence *data, DataLength databitlen) {
        rhash_whirlpool_update(&(this->m_state), data, static_cast<uint32_t>(databitlen / 8), m_rounds);
        return 0;
    }

    int Whirlpool::Final(BitSequence *hashval) {
        rhash_whirlpool_final(&(this->m_state), hashval, m_rounds);
        return 0;
    }

    int Whirlpool::Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) {
        int result;
        result = Whirlpool::Init(hashbitlen);
        if (result != 0)
            return result;
        result = Whirlpool::Update(data, databitlen);
        if (result != 0)
            return result;
        result = Whirlpool::Final(hashval);
        return result;
    }
}
