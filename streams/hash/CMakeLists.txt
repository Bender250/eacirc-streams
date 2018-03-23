add_library(hash STATIC EXCLUDE_FROM_ALL
    hash_factory
    hash_stream
    hash_interface
    functions/hash_functions
# === SHA-3 hash function files ===
    functions/gost/gost
    functions/gost/gost_hash
    functions/md5/md5
    functions/md5/md5_hash
    functions/sha1/sha1
    functions/sha1/sha1_hash
    functions/sha256/sha256
    functions/ripemd160/ripemd160
    functions/ripemd160/ripemd160_hash
    functions/tiger/tiger
    functions/tiger/tiger_sbox.cpp
    functions/tiger/tiger_hash
    functions/whirlpool/byte_order
    functions/whirlpool/whirlpool
    functions/whirlpool/whirlpool_sbox.cpp
    functions/whirlpool/whirlpool_hash
    )
target_link_libraries(hash eacirc-core)
