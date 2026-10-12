/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <gtest/gtest.h>

#include "cert_manager_api.h"
#include "cert_manager_revocation_cache.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
class CmRevocationCacheEngineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    }
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};
} // namespace

TEST_F(CmRevocationCacheEngineTest, SaveThenGetRoundTrip)
{
    struct CmBlob key = { 4, reinterpret_cast<uint8_t *>(const_cast<char *>("key1")) };
    struct CmBlob data = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("DER")) };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    ASSERT_EQ(out.size, 3u);
    EXPECT_EQ(memcmp(out.data, "DER", 3), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, GetMissingKeyReturnsNotExist)
{
    struct CmBlob key = { 7, reinterpret_cast<uint8_t *>(const_cast<char *>("nokey00")) };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_CRL, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, RejectExpiredExpireTime)
{
    struct CmBlob key = { 1, reinterpret_cast<uint8_t *>(const_cast<char *>("k")) };
    struct CmBlob data = { 1, reinterpret_cast<uint8_t *>(const_cast<char *>("d")) };
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_CRL, &data,
        static_cast<int64_t>(time(nullptr)) - 10), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheEngineTest, ClampBeyondMaxValid)
{
    struct CmBlob key = { 2, reinterpret_cast<uint8_t *>(const_cast<char *>("k2")) };
    struct CmBlob data = { 2, reinterpret_cast<uint8_t *>(const_cast<char *>("d2")) };
    int64_t far = static_cast<int64_t>(time(nullptr)) + 100LL * 24 * 3600; /* > 30d → clamp, not error */
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, far), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, ResaveSameKeyLastWriteWins)
{
    struct CmBlob key = { 2, reinterpret_cast<uint8_t *>(const_cast<char *>("k3")) };
    struct CmBlob d1 = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("AAA")) };
    struct CmBlob d2 = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("BBB")) };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d1, expire), CM_SUCCESS);
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d2, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    ASSERT_EQ(out.size, 3u);
    EXPECT_EQ(memcmp(out.data, "BBB", 3), 0);
    CmFreeRevocationCache(&out);
}
