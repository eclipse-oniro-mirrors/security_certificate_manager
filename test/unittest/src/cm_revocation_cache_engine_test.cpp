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

#include <limits.h>
#include <unistd.h>

#include "cert_manager_api.h"
#include "cert_manager_revocation_cache.h"
#include "cert_manager_storage.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr int64_t ALREADY_EXPIRED_SEC = 10; /* expire offset already in the past */
MockNativeToken *g_mockNative = nullptr;

/* remove all revocation cache records, files and meta left by this or previous test runs */
void CleanupRevocationCacheState()
{
    char **paths = nullptr;
    uint32_t count = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &count) == CM_SUCCESS) {
        for (uint32_t i = 0; i < count; i++) {
            char full[PATH_MAX] = { 0 };
            if (snprintf_s(full, sizeof(full), sizeof(full) - 1, "%s%s", REVOCATION_CACHE_DIR,
                paths[i]) >= 0) {
                (void)unlink(full);
            }
            (void)DeleteRevocationCacheRecord(paths[i]);
        }
        FreeRevocationCacheFilePaths(paths, count);
    }
    (void)DeleteRevocationCacheMeta();
}

class CmRevocationCacheEngineTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CmRevocationCacheEngineTest::SetUpTestCase()
{
    /* record the shell token so MockNativeToken can query atm with shell identity */
    CmTestCommon::SetTestEnvironment(GetSelfTokenID());
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
}

void CmRevocationCacheEngineTest::TearDownTestCase()
{
    CmTestCommon::ResetTestEnvironment();
}

/* CmGetRevocationCache only serves HAP/native callers; mock self as a native process */
void CmRevocationCacheEngineTest::SetUp()
{
    CleanupRevocationCacheState(); /* clear leftovers from previous runs/cases */
    g_mockNative = new (std::nothrow) MockNativeToken("foundation");
}

void CmRevocationCacheEngineTest::TearDown()
{
    CleanupRevocationCacheState(); /* remove records/files/meta created by this case */
    if (g_mockNative != nullptr) {
        delete g_mockNative;
        g_mockNative = nullptr;
    }
}
} // namespace

TEST_F(CmRevocationCacheEngineTest, SaveThenGetRoundTrip)
{
    uint8_t keyBuf[] = "key1";
    uint8_t dataBuf[] = "DER";
    struct CmBlob key = { 4, keyBuf };
    struct CmBlob data = { 3, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectDer[] = "DER";
    ASSERT_EQ(out.size, sizeof(expectDer) - 1);
    EXPECT_EQ(memcmp(out.data, expectDer, sizeof(expectDer) - 1), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, GetMissingKeyReturnsNotExist)
{
    uint8_t keyBuf[] = "nokey00";
    struct CmBlob key = { 7, keyBuf };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_CRL, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, RejectExpiredExpireTime)
{
    uint8_t keyBuf[] = "k";
    uint8_t dataBuf[] = "d";
    struct CmBlob key = { 1, keyBuf };
    struct CmBlob data = { 1, dataBuf };
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_CRL, &data,
        static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheEngineTest, ClampBeyondMaxValid)
{
    uint8_t keyBuf[] = "k2";
    uint8_t dataBuf[] = "d2";
    struct CmBlob key = { 2, keyBuf };
    struct CmBlob data = { 2, dataBuf };
    int64_t far = static_cast<int64_t>(time(nullptr)) + 100LL * 24 * 3600; /* > 30d → clamp, not error */
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, far), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, ResaveSameKeyLastWriteWins)
{
    uint8_t keyBuf[] = "k3";
    uint8_t d1Buf[] = "AAA";
    uint8_t d2Buf[] = "BBB";
    struct CmBlob key = { 2, keyBuf };
    struct CmBlob d1 = { 3, d1Buf };
    struct CmBlob d2 = { 3, d2Buf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d1, expire), CM_SUCCESS);
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d2, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectData[] = "BBB";
    ASSERT_EQ(out.size, sizeof(expectData) - 1);
    EXPECT_EQ(memcmp(out.data, expectData, sizeof(expectData) - 1), 0);
    CmFreeRevocationCache(&out);
}
