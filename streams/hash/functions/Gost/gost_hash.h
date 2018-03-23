#ifndef GOSTHASH_H
#define GOSTHASH_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include "gost.h"

/*********************** SHA3 adapter **********************/
#include "../../hash_interface.h"

namespace hash {
    class Gost : public hash_interface {

    private:
        gost_ctx m_state;
        unsigned m_rounds;

    public:

        Gost(int numRounds = gost_full_rounds);
        int Init(int hash_bitsize);
        int Update(const BitSequence *data, DataLength databitlen);
        int Final(BitSequence *hashval);

        int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

    };
}

#endif   // GOSTHASH_H
