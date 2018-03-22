#ifndef KECCAK_SHA3_H
#define KECCAK_SHA3_H

#define KECCAK_FULL_ROUNDS 24

#include "../../hash_interface.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "md5.h"
#ifdef __cplusplus
}
#endif

namespace hash {

class MD5 : public hash_interface {

/*typedef unsigned char BitSequence;
typedef unsigned long long DataLength;*/
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

private:
    MD5_CTX m_contetx;
    unsigned m_rounds;

public:
    explicit MD5(int numRounds=MD5_FULL_ROUNDS);
    int Init(int hashbitlen) override;
    int Update(const BitSequence *data, DataLength databitlen) override;
    int Final(BitSequence *hashval) override;
    int Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) override;

};

} // namespace sha3

#endif
