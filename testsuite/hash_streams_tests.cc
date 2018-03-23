#include <gtest/gtest.h>
#include <eacirc-core/json.h>
#include <streams/hashes/hash_factory.h>
#include <streams/hashes/hash_interface.h>
#include <fstream>
#include "stream.h"
#include "streams.h"

#include "testsuite/test-utils/hash_test_case.h"

/** Source of test vectors http://csrc.nist.gov/groups/ST/hash/sha-3/index.html */


TEST(gost, test_vectors) {
    testsuite::hash_test_case("Gost", 16)();
}

TEST(ripemd160, test_vectors) {
    testsuite::hash_test_case("RIPEMD160", 80)();
}

TEST(sha1, test_vectors) {
    testsuite::hash_test_case("SHA1", 80)();
}

TEST(sha256, test_vectors) {
    testsuite::hash_test_case("SHA256", 64)();
}

TEST(md5, test_vectors) {
    testsuite::hash_test_case("MD5", 64)();
}

TEST(whirlpool, test_vectors) {
    testsuite::hash_test_case("Whirlpool", 10)();
}
