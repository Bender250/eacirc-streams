#include "hash_factory.h"
#include "functions/hash_functions.h"
#include "hash_interface.h"

namespace hash {

void _check_rounds(const std::string& algorithm, const unsigned rounds) {
    if (rounds > 0)
        throw std::runtime_error{"requested SHA-3 algorithm named \"" + algorithm +
                                 "\" cannot be limited in rounds"};
}

std::unique_ptr<hash_interface> hash_factory::create(const std::string& name, const unsigned rounds) {
    // clang-format off
    if (name == "Gost")        return std::make_unique<Gost>(rounds);
    if (name == "MD5")         return std::make_unique<MD5>(rounds);
    if (name == "RIPEMD160")   return std::make_unique<Ripemd160>(rounds);
    if (name == "SHA1")        return std::make_unique<SHA1>(rounds);
    if (name == "SHA256")      return std::make_unique<SHA256>(rounds);
    if (name == "Tiger")       return std::make_unique<Tiger>(rounds);
    if (name == "Whirlpool")   return std::make_unique<Whirlpool>(rounds);
    // clang-format on

    throw std::runtime_error("requested HASH algorithm named \"" + name +
                             "\" is either broken or does not exists");
}

} // namespace hash