#include <string.h>
#include <stdexcept>
#include "md5_hash.h"

extern "C" {

}

namespace hash {

MD5::MD5(const int numRounds) {
    if (numRounds <= 0 || numRounds > MD5_FULL_ROUNDS){
        throw std::out_of_range("Valid numRounds range for Keccak is <1-24>");
    }

    this->m_rounds = (unsigned)numRounds;
}

int MD5::Init(int hashbitlen)
{
    if (hashbitlen != 8*MD5_DIGEST_LENGTH){
        throw std::out_of_range("MD5 supports only 16B output");
    }

    md5_init(&m_contetx);
    return SUCCESS;
}

int MD5::Update(const BitSequence *data, DataLength databitlen)
{
    md5_update(&m_contetx, const_cast<unsigned char *>(data), static_cast<unsigned int>(databitlen / 8), m_rounds);
    return SUCCESS;
}

int MD5::Final(BitSequence *hashval)
{
    md5_final(&m_contetx, hashval, m_rounds);
    return SUCCESS;
}

int MD5::Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
    if (hashbitlen > 8*MD5_DIGEST_LENGTH){
        throw std::out_of_range("MD5 supports only 16B output");
    }

    MD5_CTX mdContext{};
    md5_init(&mdContext);
    md5_update(&mdContext, const_cast<unsigned char *>(data), static_cast<unsigned int>(databitlen / 8), m_rounds);
    md5_final(&mdContext, hashval, m_rounds);
    return SUCCESS;
}

} // namespace hash
