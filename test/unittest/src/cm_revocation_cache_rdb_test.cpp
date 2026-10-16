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

#include <limits.h>
#include <unistd.h>

#include "cert_manager_storage.h"
#include "cm_revocation_cache_rdb.h"
#include "securec.h"

using namespace testing::ext;

namespace {
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
}

class CmRevocationCacheRdbTest : public testing::Test {
public:
    void SetUp() override
    {
        ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
        CleanupRevocationCacheState();
    }
    void TearDown() override
    {
        CleanupRevocationCacheState();
    }
};

TEST_F(CmRevocationCacheRdbTest, CreateInsertQueryDelete)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    struct RevocationCacheRecord r = { 2000000000LL, "ocsp/ab/abcd.cache", 1234 };
    ASSERT_EQ(InsertRevocationCacheRecord(&r), CM_SUCCESS);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_GE(total, 1234u);
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/ab/abcd.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, MetaRoundTrip)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    int64_t v = 0;
    EXPECT_EQ(GetRevocationCacheMeta(&v), CMR_ERROR_NOT_FOUND);
    ASSERT_EQ(SetRevocationCacheMeta(12345), CM_SUCCESS);
    ASSERT_EQ(GetRevocationCacheMeta(&v), CM_SUCCESS);
    EXPECT_EQ(v, 12345);
}

TEST_F(CmRevocationCacheRdbTest, MetaDeleteThenGetReturnsNotFound)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    ASSERT_EQ(SetRevocationCacheMeta(424242), CM_SUCCESS);
    ASSERT_EQ(DeleteRevocationCacheMeta(), CM_SUCCESS);
    int64_t v = 0;
    EXPECT_EQ(GetRevocationCacheMeta(&v), CMR_ERROR_NOT_FOUND);
}

TEST_F(CmRevocationCacheRdbTest, DeleteNonexistentRecordIsIdempotent)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    /* deleting a path that was never inserted must still report success */
    EXPECT_EQ(DeleteRevocationCacheRecord("ocsp/zz/never-inserted.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, QueryEmptyTableReturnsNoPaths)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    char **paths = nullptr;
    uint32_t count = 1; /* must be reset to 0 by the query */
    ASSERT_EQ(QueryAllRevocationCacheFilePaths(&paths, &count), CM_SUCCESS);
    EXPECT_EQ(count, 0u);
    EXPECT_EQ(paths, nullptr);
    FreeRevocationCacheFilePaths(paths, count);
    uint64_t total = 99; /* must be reset to 0 as well */
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, 0u);
}

TEST_F(CmRevocationCacheRdbTest, QueryRejectsNullArgs)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    EXPECT_EQ(QueryRevocationCacheSumSize(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmRevocationCacheRdbTest, InsertDuplicatePathReplaces)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    struct RevocationCacheRecord first = { 2000000000LL, "ocsp/dd/dup.cache", 100 };
    ASSERT_EQ(InsertRevocationCacheRecord(&first), CM_SUCCESS);
    /* inserting the same path again must replace the row, not duplicate it */
    struct RevocationCacheRecord second = { 2000000500LL, "ocsp/dd/dup.cache", 200 };
    ASSERT_EQ(InsertRevocationCacheRecord(&second), CM_SUCCESS);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, 200u);
    struct RevocationCacheRecord oldest = { 0 };
    ASSERT_EQ(QueryRevocationCacheRecordByExpireAsc(&oldest), CM_SUCCESS);
    EXPECT_EQ(oldest.dataSize, 200u); /* the newest values win */
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/dd/dup.cache"), CM_SUCCESS);
}
