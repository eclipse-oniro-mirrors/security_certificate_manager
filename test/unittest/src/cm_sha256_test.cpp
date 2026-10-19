/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "cm_sha256.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
/* NIST FIPS 180-4 / CAVP SHA-256 test vectors */
const char *EMPTY_VECTOR = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const char *ABC_VECTOR = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const char *VECTOR_448BIT = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
const char *VECTOR_896BIT = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
const char *MILLION_A_VECTOR = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
constexpr uint32_t CM_SHA256_HEX_CHARS_PER_BYTE = 2;
constexpr uint32_t MILLION_A_LEN = 1000000;

std::string ToHex(const uint8_t *hash)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(CM_SHA256_HASH_LEN * CM_SHA256_HEX_CHARS_PER_BYTE);
    for (uint32_t i = 0; i < CM_SHA256_HASH_LEN; ++i) {
        out.push_back(digits[hash[i] >> 4]);
        out.push_back(digits[hash[i] & 0x0F]);
    }
    return out;
}
}

class CmSha256Test : public testing::Test {
};

TEST_F(CmSha256Test, EmptyInputMatchesNistVector)
{
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(reinterpret_cast<const uint8_t *>(""), 0, hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), EMPTY_VECTOR);
}

TEST_F(CmSha256Test, ZeroLengthWithValidPointerMatchesEmptyDigest)
{
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    const uint8_t data[1] = {0x61};
    EXPECT_EQ(CmSha256(data, 0, hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), EMPTY_VECTOR);
}

TEST_F(CmSha256Test, ShortInputAbcMatchesNistVector)
{
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(reinterpret_cast<const uint8_t *>("abc"), 3, hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), ABC_VECTOR);
}

TEST_F(CmSha256Test, FiftySixByteInputMatchesNistVector)
{
    /* 448-bit message: length padding spills into a second block */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(reinterpret_cast<const uint8_t *>(msg), strlen(msg), hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), VECTOR_448BIT);
}

TEST_F(CmSha256Test, HundredTwelveByteInputMatchesNistVector)
{
    /* 896-bit message: exercises multi-block streaming */
    const char *msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
                      "klmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(reinterpret_cast<const uint8_t *>(msg), strlen(msg), hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), VECTOR_896BIT);
}

TEST_F(CmSha256Test, MillionAInputMatchesNistVector)
{
    std::vector<uint8_t> data(MILLION_A_LEN, 'a');
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(data.data(), MILLION_A_LEN, hash), CM_SUCCESS);
    EXPECT_EQ(ToHex(hash), MILLION_A_VECTOR);
}

TEST_F(CmSha256Test, NullDataPointerRejected)
{
    uint8_t hash[CM_SHA256_HASH_LEN] = {0};
    EXPECT_EQ(CmSha256(nullptr, 1, hash), CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmSha256Test, NullHashPointerRejected)
{
    const uint8_t data[1] = {0x61};
    EXPECT_EQ(CmSha256(data, 1, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
