#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include "whirlpool.h"

/*********************** SHA3 adapter **********************/
#include "../../hash_interface.h"

namespace hash {
    class Whirlpool : public hash_interface {

    private:
        whirlpool_ctx m_state;
        unsigned m_rounds;

    public:

        Whirlpool(int numRounds = WHIRPOOL_ROUNDS);
        int Init(int hash_bitsize);
        int Update(const BitSequence *data, DataLength databitlen);
        int Final(BitSequence *hashval);

        int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

    };
}

#endif
