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

#include <cstring>
#include <ctime>

#include "cm_revocation_cache.h"
#include "cert_manager_api.h"

using namespace testing::ext;

class CmRevocationCacheTest : public testing::Test {
};

TEST_F(CmRevocationCacheTest, BuildRelPathRejectsInvalidType)
{
    struct CmBlob key = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("abc")) };
    char rel[300] = {0};
    EXPECT_EQ(CmRevocationCacheBuildRelPath(99, &key, rel, sizeof(rel)),
        CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE);
}

TEST_F(CmRevocationCacheTest, BuildRelPathStableHashAndPrefix)
{
    struct CmBlob key = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("abc")) };
    char rel1[300] = {0};
    char rel2[300] = {0};
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, rel1, sizeof(rel1)), CM_SUCCESS);
    EXPECT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, rel2, sizeof(rel2)), CM_SUCCESS);
    EXPECT_STREQ(rel1, rel2);
    EXPECT_EQ(strncmp(rel1, "ocsp/", 5), 0);
    EXPECT_EQ(strlen(rel1), strlen("ocsp/") + 2 + 1 + 64 + strlen(".cache"));
    EXPECT_EQ(strncmp(rel1 + 5, rel1 + 8, 2), 0); /* prefix == first 2 hex chars */
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
    EXPECT_EQ(CmRevocationCacheBuildBasePath(99, base, sizeof(base)), CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID);

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
    struct CmBlob key = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("abc")) };
    uint8_t big[CM_REVOCATION_CACHE_DATA_MAX_LEN + 1] = {1};
    struct CmBlob data = { sizeof(big), big };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_DATA);
}

TEST_F(CmRevocationCacheTest, SaveRejectsBadArgs)
{
    struct CmBlob key = { 3, reinterpret_cast<uint8_t *>(const_cast<char *>("abc")) };
    struct CmBlob data = { 1, reinterpret_cast<uint8_t *>(const_cast<char *>("d")) };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmSaveRevocationCache(key, static_cast<enum CmRevocationType>(9), data, expire),
        CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE);
    EXPECT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data,
        static_cast<int64_t>(time(nullptr)) - 1), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}
