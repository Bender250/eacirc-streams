//
// Created by Dusan Klinec on 23/03/2018.
//

#ifndef EACIRC_STREAMS_TIGER_HASH_H
#define EACIRC_STREAMS_TIGER_HASH_H

/*************************** HEADER FILES ***************************/
#include <cstddef>
#include "tiger.h"

/*********************** SHA3 adapter **********************/
#include "../../hash_interface.h"

namespace hash {
    class Tiger : public hash_interface {

    private:
        tiger_ctx m_state;
        unsigned m_rounds;

    public:

        Tiger(int numRounds = tiger_full_rounds);
        int Init(int hash_bitsize);
        int Update(const BitSequence *data, DataLength databitlen);
        int Final(BitSequence *hashval);

        int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

    };
}


#endif //EACIRC_STREAMS_TIGER_HASH_H
