#ifndef SHA1_H
#define SHA1_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include "sha1.h"

/*********************** SHA3 adapter **********************/
#include "../../hash_interface.h"

namespace hash {
    class SHA1 : public hash_interface {

    private:
        SHA1_CTX m_state;
        unsigned m_rounds;

    public:

        SHA1(int numRounds = SHA1_FULL_ROUNDS);
        int Init(int hash_bitsize);
        int Update(const BitSequence *data, DataLength databitlen);
        int Final(BitSequence *hashval);

        int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

    };
}

#endif   // SHA1_H
