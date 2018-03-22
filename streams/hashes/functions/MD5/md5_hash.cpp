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

    MD5Init(&m_contetx, m_rounds);
    return SUCCESS;
}

int MD5::Update(const BitSequence *data, DataLength databitlen)
{
    MD5Update(&m_contetx, const_cast<unsigned char *>(data), static_cast<unsigned int>(databitlen / 8), m_rounds);
    return SUCCESS;
}

int MD5::Final(BitSequence *hashval)
{
    MD5Final(&m_contetx, m_rounds);
    memcpy((void *) hashval, m_contetx.digest, MD5_DIGEST_LENGTH);
    return SUCCESS;
}

int MD5::Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
    if (hashbitlen > 8*MD5_DIGEST_LENGTH){
        throw std::out_of_range("MD5 supports only 16B output");
    }

    MD5_CTX mdContext{};
    MD5Init(&mdContext, m_rounds);
    MD5Update(&mdContext, const_cast<unsigned char *>(data), static_cast<unsigned int>(databitlen), m_rounds);
    MD5Final(&mdContext, m_rounds);
    memcpy((void *) data, mdContext.digest, static_cast<size_t>(hashbitlen / 8));
    return SUCCESS;
}

} // namespace hash
