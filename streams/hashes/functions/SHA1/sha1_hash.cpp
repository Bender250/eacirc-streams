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
#include "sha1_hash.h"

/*********************** SHA3 adapter **********************/
namespace hash {
    SHA1::SHA1(const int numRounds) {
        if (numRounds <= 0 || numRounds > SHA1_FULL_ROUNDS) {
            throw std::out_of_range("Valid numRounds range for SHA1 is <1-64>");
        }

        this->m_rounds = (unsigned) numRounds;
    }

    int SHA1::Init(int hashbitlen) {
        if (hashbitlen != 256) {
            throw std::out_of_range("SHA256 supports only 256 bit output");
        }

        SHA1Init(&(this->m_state));
        return 0;
    }

    int SHA1::Update(const BitSequence *data, DataLength databitlen) {
        SHA1Update(&(this->m_state), data, static_cast<uint32_t>(databitlen / 8), m_rounds);
        return 0;
    }

    int SHA1::Final(BitSequence *hashval) {
        SHA1Final(hashval, &(this->m_state), m_rounds);
        return 0;
    }

    int SHA1::Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) {
        int result;
        result = SHA1::Init(hashbitlen);
        if (result != 0)
            return result;
        result = SHA1::Update(data, databitlen);
        if (result != 0)
            return result;
        result = SHA1::Final(hashval);
        return result;
    }
}
