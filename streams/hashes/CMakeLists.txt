add_library(hash STATIC EXCLUDE_FROM_ALL
    hash_factory
    hash_stream
    hash_interface
    functions/hash_functions
# === SHA-3 hash function files ===
    functions/Gost/gost
    functions/MD5/md5
    functions/MD5/md5_hash
    functions/SHA1/sha1
    functions/SHA1/sha1_hash
    functions/SHA2/sha256
    functions/Ripemd160/ripemd160
    functions/Whirlpool/byte_order
    functions/Whirlpool/whirlpool
    functions/Whirlpool/whirlpool_sbox.cpp
    functions/Whirlpool/whirlpool_hash
    )
target_link_libraries(hash eacirc-core)
