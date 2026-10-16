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

#include "cm_revocation_cache_rdb.h"

using namespace testing::ext;

class CmRevocationCacheRdbTest : public testing::Test {
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
