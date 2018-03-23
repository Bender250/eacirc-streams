#ifndef RIPEMD160HASH_H
#define RIPEMD160HASH_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include "ripemd160.h"

/*********************** SHA3 adapter **********************/
#include "../../hash_interface.h"

namespace hash {
    class Ripemd160 : public hash_interface {

    private:
        ripemd160_ctx m_state;
        unsigned m_rounds;

    public:

        Ripemd160(int numRounds = ripemd160_full_rounds);
        int Init(int hash_bitsize);
        int Update(const BitSequence *data, DataLength databitlen);
        int Final(BitSequence *hashval);

        int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

    };
}

#endif   // RIPEMD160HASH_H
