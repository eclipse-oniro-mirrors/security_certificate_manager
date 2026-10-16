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
#include <ctime>
#include <vector>

#include "cm_revocation_cache.h"
#include "cert_manager_api.h"
#include "securec.h"

using namespace testing::ext;

namespace {
constexpr uint32_t INVALID_REVOCATION_TYPE = 99;
constexpr uint32_t SHA256_HEX_LEN = 64; /* sha256 hex digest length */
constexpr uint32_t HASH_PREFIX_LEN = 2;  /* sub dir prefix length */
}

class CmRevocationCacheTest : public testing::Test {
};

TEST_F(CmRevocationCacheTest, BuildRelPathRejectsInvalidType)
{
    uint8_t keyBuf[] = "abc";
    struct CmBlob key = { 3, keyBuf };
    char rel[300] = {0};
    EXPECT_EQ(CmRevocationCacheBuildRelPath(INVALID_REVOCATION_TYPE, &key, rel, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE);
}

TEST_F(CmRevocationCacheTest, BuildRelPathStableHashAndPrefix)
{
    uint8_t keyBuf[] = "abc";
    struct CmBlob key = { 3, keyBuf };
    char rel1[300] = {0};
    char rel2[300] = {0};
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, rel1, sizeof(rel1)), CM_SUCCESS);
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, rel2, sizeof(rel2)), CM_SUCCESS);
    EXPECT_STREQ(rel1, rel2);
    EXPECT_EQ(strncmp(rel1, "ocsp/", strlen("ocsp/")), 0);
    EXPECT_EQ(strlen(rel1), strlen("ocsp/") + HASH_PREFIX_LEN + 1 + SHA256_HEX_LEN + strlen(".cache"));
    /* sub dir prefix equals the first 2 hex chars of the key hash */
    const uint32_t prefixOff = strlen("ocsp/");
    EXPECT_EQ(strncmp(rel1 + prefixOff, rel1 + prefixOff + 1 + HASH_PREFIX_LEN, HASH_PREFIX_LEN), 0);
}

TEST_F(CmRevocationCacheTest, BuildBasePathTokenMapping)
{
    char base[300] = {0};
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_HAP, base, sizeof(base)), CM_SUCCESS);
    EXPECT_STREQ(base, REVOCATION_CACHE_SANDBOX_BASE);
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_NATIVE, base, sizeof(base)), CM_SUCCESS);
    EXPECT_STREQ(base, REVOCATION_CACHE_SERVICE_BASE);
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_SHELL, base, sizeof(base)),
        CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID);
    EXPECT_EQ(CmRevocationCacheBuildBasePath(INVALID_REVOCATION_TYPE, base, sizeof(base)),
        CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID);

    char small[8] = {0};
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_NATIVE, small, sizeof(small)),
        CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheTest, FreeNullSafe)
{
    CmFreeRevocationCache(nullptr);
    struct CmBlob b = {0, nullptr};
    CmFreeRevocationCache(&b);
}

TEST_F(CmRevocationCacheTest, SaveRejectsOversizedData)
{
    uint8_t keyBuf[] = "abc";
    struct CmBlob key = { 3, keyBuf };
    std::vector<uint8_t> big(CM_REVOCATION_CACHE_DATA_MAX_LEN + 1, 1);
    struct CmBlob data = { static_cast<uint32_t>(big.size()), big.data() };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_DATA);
}

TEST_F(CmRevocationCacheTest, SaveRejectsBadArgs)
{
    uint8_t keyBuf[] = "abc";
    uint8_t dataBuf[] = "d";
    struct CmBlob key = { 3, keyBuf };
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, static_cast<enum CmRevocationType>(INVALID_REVOCATION_TYPE), data,
        expire), CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE);
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data,
        static_cast<int64_t>(time(nullptr)) - 1), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheTest, SaveRejectsOversizedKey)
{
    uint8_t keyBuf[CM_REVOCATION_CACHE_KEY_MAX_LEN + 1] = { 0 };
    (void)memset_s(keyBuf, sizeof(keyBuf), 'k', sizeof(keyBuf));
    struct CmBlob key = { sizeof(keyBuf), keyBuf };
    uint8_t dataBuf[] = "d";
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
}

TEST_F(CmRevocationCacheTest, GetRejectsBadArgs)
{
    uint8_t keyBuf[] = "gk";
    struct CmBlob key = { 2, keyBuf };
    uint8_t keyBufBig[CM_REVOCATION_CACHE_KEY_MAX_LEN + 1] = { 0 };
    (void)memset_s(keyBufBig, sizeof(keyBufBig), 'g', sizeof(keyBufBig));
    struct CmBlob bigKey = { sizeof(keyBufBig), keyBufBig };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, nullptr), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(CmGetRevocationCache(key, static_cast<enum CmRevocationType>(INVALID_REVOCATION_TYPE), &out),
        CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE);
    EXPECT_EQ(CmGetRevocationCache(bigKey, CM_REVOCATION_TYPE_OCSP, &out),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
}

TEST_F(CmRevocationCacheTest, GetShellCallerRejected)
{
    /* this suite never mocks the caller, so the process keeps its shell identity */
    uint8_t keyBuf[] = "shkey1";
    struct CmBlob key = { 6, keyBuf };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out),
        CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID);
}

TEST_F(CmRevocationCacheTest, SaveShellCallerRejected)
{
    /* caller validation rejects the shell identity before any IPC is attempted */
    uint8_t keyBuf[] = "shkey1";
    struct CmBlob key = { 6, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire),
        CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID);
}

TEST_F(CmRevocationCacheTest, BuildRelPathRejectsBadKey)
{
    char rel[300] = { 0 };
    uint8_t keyBuf[CM_REVOCATION_CACHE_KEY_MAX_LEN + 1] = { 0 };
    (void)memset_s(keyBuf, sizeof(keyBuf), 'k', sizeof(keyBuf));
    struct CmBlob emptyKey = { 0, keyBuf };
    struct CmBlob bigKey = { sizeof(keyBuf), keyBuf };
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, nullptr, rel, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &emptyKey, rel, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &bigKey, rel, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
}

TEST_F(CmRevocationCacheTest, BuildRelPathAcceptsMaxKey)
{
    uint8_t keyBuf[CM_REVOCATION_CACHE_KEY_MAX_LEN] = { 0 };
    (void)memset_s(keyBuf, sizeof(keyBuf), 'm', sizeof(keyBuf));
    struct CmBlob key = { sizeof(keyBuf), keyBuf };
    char rel[300] = { 0 };
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_CRL, &key, rel, sizeof(rel)), CM_SUCCESS);
    EXPECT_EQ(strncmp(rel, "crl/", strlen("crl/")), 0); /* also covers the crl prefix branch */
}

TEST_F(CmRevocationCacheTest, BuildRelPathRejectsBadBuffer)
{
    uint8_t keyBuf[] = "abc";
    struct CmBlob key = { 3, keyBuf };
    char rel[300] = { 0 };
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, nullptr, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, rel, 0),
        CMR_ERROR_INVALID_ARGUMENT);
    char small[8] = { 0 };
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, small, sizeof(small)),
        CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheTest, Int64BeRoundTrip)
{
    const int64_t values[] = { 0, 1, -1, INT64_MAX, INT64_MIN };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        uint8_t buf[sizeof(int64_t)] = { 0 };
        CmRevocationCacheEncodeInt64Be(values[i], buf);
        EXPECT_EQ(CmRevocationCacheDecodeInt64Be(buf), values[i]);
    }
    CmRevocationCacheEncodeInt64Be(1, nullptr); /* null output must be a no-op */
    EXPECT_EQ(CmRevocationCacheDecodeInt64Be(nullptr), 0); /* null input decodes to 0 */
}

TEST_F(CmRevocationCacheTest, BuildBasePathRejectsBadBuffer)
{
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_NATIVE, nullptr, 300),
        CMR_ERROR_INVALID_ARGUMENT);
    char base[300] = { 0 };
    EXPECT_EQ(CmRevocationCacheBuildBasePath(CM_REVOCATION_TOKEN_TYPE_NATIVE, base, 0),
        CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmRevocationCacheTest, ValidateSaveParamsRejectsNullClampOut)
{
    uint8_t keyBuf[] = "abc";
    struct CmBlob key = { 3, keyBuf };
    uint8_t dataBuf[] = "d";
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmRevocationCacheValidateSaveParams(&key, CM_REVOCATION_TYPE_OCSP, &data, expire, nullptr),
        CMR_ERROR_INVALID_ARGUMENT);
    int64_t clamped = 0;
    EXPECT_EQ(CmRevocationCacheValidateSaveParams(&key, CM_REVOCATION_TYPE_OCSP, &data, expire, &clamped),
        CM_SUCCESS);
}
