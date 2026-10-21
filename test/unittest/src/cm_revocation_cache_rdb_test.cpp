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

#include <climits>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

#include "cert_manager_storage.h"
#include "cm_config_rdb.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_revocation_cache_rdb.h"
#include "securec.h"

using namespace testing::ext;

namespace {
constexpr int64_t FIXED_EXPIRE_TIME_UTC = 2000000000LL; /* fixed future timestamp: the value is irrelevant */
constexpr int64_t LATER_EXPIRE_TIME_UTC = 2000000500LL; /* strictly later than FIXED_EXPIRE_TIME_UTC */
constexpr uint64_t RECORD_DATA_SIZE = 1234;             /* arbitrary data size of a fake record */
constexpr uint64_t DUP_FIRST_DATA_SIZE = 100;           /* first write of the duplicate-path case */
constexpr uint64_t DUP_SECOND_DATA_SIZE = 200;          /* replacement write: its values must win */
constexpr int64_t META_VALUE_FIRST = 12345;             /* arbitrary meta value for the round trip */
constexpr int64_t META_VALUE_BEFORE_DELETE = 424242;    /* meta value stored right before deleting */
constexpr int64_t META_VALUE_REWRITE = 999;             /* proves the meta row is re-created */
constexpr uint64_t NON_ZERO_SENTINEL_SIZE = 77;         /* must be reset to 0 by the query */
constexpr uint64_t COEXIST_FIRST_DATA_SIZE = 100;       /* first row of the composite primary key cases */
constexpr uint64_t COEXIST_SECOND_DATA_SIZE = 200;      /* second row: its values must win on a rewrite */
constexpr int64_t META_VALUE_IN_CONFIG = 1729;          /* arbitrary meta value proving config-table storage */

/* snapshot of all cache rel-paths recorded in the RDB; nullopt when the query itself fails */
std::optional<std::vector<std::string>> QueryCacheFilePaths()
{
    /* the array is owned by the C query API until FreeRevocationCacheFilePaths */
    char **paths = nullptr;
    uint32_t count = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &count) != CM_SUCCESS) {
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (uint32_t i = 0; i < count; i++) {
        result.emplace_back(paths[i]);
    }
    FreeRevocationCacheFilePaths(paths, count);
    return result;
}

/* remove all revocation cache records, files and meta left by this or previous test runs */
void CleanupRevocationCacheState()
{
    const auto paths = QueryCacheFilePaths();
    if (paths.has_value()) {
        for (const auto &rel : *paths) {
            (void)unlink((std::string(REVOCATION_CACHE_DIR) + rel).c_str());
            (void)DeleteRevocationCacheRecord(rel.c_str());
        }
    }
    (void)DeleteRevocationCacheMeta();
}
}

class CmRevocationCacheRdbTest : public testing::Test {
public:
    void SetUp() override
    {
        /* the meta row lives in cert_manager_config: both tables must exist */
        ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
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
    /* key "616263" = hex("abc"): the row keeps the encoded key and its type */
    struct RevocationCacheRecord r = { FIXED_EXPIRE_TIME_UTC, "616263", "ocsp",
        "ocsp/61/616263.cache", RECORD_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&r), CM_SUCCESS);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_GE(total, RECORD_DATA_SIZE);
    /* the KEY/TYPE columns must round-trip through the record query */
    struct RevocationCacheRecord queried = { 0 };
    ASSERT_EQ(QueryRevocationCacheRecordByExpireAsc(&queried), CM_SUCCESS);
    EXPECT_STREQ(queried.key, "616263");
    EXPECT_STREQ(queried.type, "ocsp");
    EXPECT_STREQ(queried.filePath, "ocsp/61/616263.cache");
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/61/616263.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, MetaRoundTrip)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    int64_t v = 0;
    EXPECT_EQ(GetRevocationCacheMeta(&v), CMR_ERROR_NOT_FOUND);
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_FIRST), CM_SUCCESS);
    ASSERT_EQ(GetRevocationCacheMeta(&v), CM_SUCCESS);
    EXPECT_EQ(v, META_VALUE_FIRST);
}

TEST_F(CmRevocationCacheRdbTest, MetaDeleteThenGetReturnsNotFound)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_BEFORE_DELETE), CM_SUCCESS);
    ASSERT_EQ(DeleteRevocationCacheMeta(), CM_SUCCESS);
    int64_t v = 0;
    EXPECT_EQ(GetRevocationCacheMeta(&v), CMR_ERROR_NOT_FOUND);
    /* meta can be written again after deletion: the row is re-created */
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_REWRITE), CM_SUCCESS);
    ASSERT_EQ(GetRevocationCacheMeta(&v), CM_SUCCESS);
    EXPECT_EQ(v, META_VALUE_REWRITE);
}

TEST_F(CmRevocationCacheRdbTest, DeleteNonexistentRecordIsIdempotent)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    /* deleting a path that was never inserted must still report success */
    EXPECT_EQ(DeleteRevocationCacheRecord("ocsp/ff/ffff0000.cache"), CM_SUCCESS);

    /* deleting an already deleted record stays successful and leaves nothing behind */
    struct RevocationCacheRecord r = { FIXED_EXPIRE_TIME_UTC, "deadbeef", "ocsp",
        "ocsp/de/deadbeef.cache", RECORD_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&r), CM_SUCCESS);
    ASSERT_EQ(DeleteRevocationCacheRecord(r.filePath), CM_SUCCESS);
    EXPECT_EQ(DeleteRevocationCacheRecord(r.filePath), CM_SUCCESS);
    uint64_t total = NON_ZERO_SENTINEL_SIZE; /* must be reset to 0: the table is empty again */
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, 0u);
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
    uint64_t total = NON_ZERO_SENTINEL_SIZE; /* must be reset to 0 as well */
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, 0u);
}

TEST_F(CmRevocationCacheRdbTest, QueryRejectsNullArgs)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    EXPECT_EQ(QueryRevocationCacheSumSize(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    /* a single null out parameter is rejected the same way */
    uint32_t count = 0;
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(nullptr, &count), CMR_ERROR_INVALID_ARGUMENT);
    char **paths = nullptr;
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(&paths, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    /* record queries and mutations guard their pointers too */
    EXPECT_EQ(QueryRevocationCacheRecordByExpireAsc(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryExpiredRevocationCacheRecord(0, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(InsertRevocationCacheRecord(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(DeleteRevocationCacheRecord(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetRevocationCacheMeta(nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmRevocationCacheRdbTest, InsertDuplicatePathReplaces)
{
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    /* key "647570" = hex("dup"): same path means the same encoded key and type */
    struct RevocationCacheRecord first = { FIXED_EXPIRE_TIME_UTC, "647570", "ocsp",
        "ocsp/64/647570.cache", DUP_FIRST_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&first), CM_SUCCESS);
    /* inserting the same path again must replace the row, not duplicate it */
    struct RevocationCacheRecord second = { LATER_EXPIRE_TIME_UTC, "647570", "ocsp",
        "ocsp/64/647570.cache", DUP_SECOND_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&second), CM_SUCCESS);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, DUP_SECOND_DATA_SIZE);
    struct RevocationCacheRecord oldest = { 0 };
    ASSERT_EQ(QueryRevocationCacheRecordByExpireAsc(&oldest), CM_SUCCESS);
    EXPECT_EQ(oldest.dataSize, DUP_SECOND_DATA_SIZE); /* the newest values win */
    EXPECT_STREQ(oldest.key, "647570");
    EXPECT_STREQ(oldest.type, "ocsp");
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/64/647570.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, SamePathDifferentKeysCoexist)
{
    /* the primary key is (KEY, TYPE): two different keys must coexist even
     * when a crafted row pair shares one FILE_PATH */
    struct RevocationCacheRecord first = { FIXED_EXPIRE_TIME_UTC, "616263", "ocsp",
        "ocsp/61/616263.cache", COEXIST_FIRST_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&first), CM_SUCCESS);
    /* key "6b657931" = hex("key1"): deliberately the same path, different key */
    struct RevocationCacheRecord second = { FIXED_EXPIRE_TIME_UTC, "6b657931", "ocsp",
        "ocsp/61/616263.cache", COEXIST_SECOND_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&second), CM_SUCCESS);

    const auto paths = QueryCacheFilePaths();
    ASSERT_TRUE(paths.has_value());
    EXPECT_EQ(paths->size(), 2u);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, COEXIST_FIRST_DATA_SIZE + COEXIST_SECOND_DATA_SIZE);
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/61/616263.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, SameKeyAndTypeReplaceAcrossPaths)
{
    /* one (KEY, TYPE) is one logical entry: a rewrite replaces the whole row,
     * also when the crafted rows disagree on FILE_PATH */
    struct RevocationCacheRecord first = { FIXED_EXPIRE_TIME_UTC, "616263", "ocsp",
        "ocsp/61/616263.cache", COEXIST_FIRST_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&first), CM_SUCCESS);
    struct RevocationCacheRecord second = { LATER_EXPIRE_TIME_UTC, "616263", "ocsp",
        "ocsp/62/616263.cache", COEXIST_SECOND_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&second), CM_SUCCESS);

    const auto paths = QueryCacheFilePaths();
    ASSERT_TRUE(paths.has_value());
    ASSERT_EQ(paths->size(), 1u);
    EXPECT_STREQ((*paths)[0].c_str(), "ocsp/62/616263.cache"); /* the newest write wins */
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, COEXIST_SECOND_DATA_SIZE);
    struct RevocationCacheRecord oldest = { 0 };
    ASSERT_EQ(QueryRevocationCacheRecordByExpireAsc(&oldest), CM_SUCCESS);
    EXPECT_EQ(oldest.expireTimeUtc, LATER_EXPIRE_TIME_UTC);
    EXPECT_EQ(oldest.dataSize, COEXIST_SECOND_DATA_SIZE);
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/62/616263.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, SameKeyDifferentTypesCoexist)
{
    /* one encoded key cached for both ocsp and crl stays two independent entries */
    struct RevocationCacheRecord ocspRec = { FIXED_EXPIRE_TIME_UTC, "616263", "ocsp",
        "ocsp/61/616263.cache", COEXIST_FIRST_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&ocspRec), CM_SUCCESS);
    struct RevocationCacheRecord crlRec = { FIXED_EXPIRE_TIME_UTC, "616263", "crl",
        "crl/61/616263.cache", COEXIST_SECOND_DATA_SIZE };
    ASSERT_EQ(InsertRevocationCacheRecord(&crlRec), CM_SUCCESS);

    const auto paths = QueryCacheFilePaths();
    ASSERT_TRUE(paths.has_value());
    EXPECT_EQ(paths->size(), 2u);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheSumSize(&total), CM_SUCCESS);
    EXPECT_EQ(total, COEXIST_FIRST_DATA_SIZE + COEXIST_SECOND_DATA_SIZE);
    ASSERT_EQ(DeleteRevocationCacheRecord("ocsp/61/616263.cache"), CM_SUCCESS);
    ASSERT_EQ(DeleteRevocationCacheRecord("crl/61/616263.cache"), CM_SUCCESS);
}

TEST_F(CmRevocationCacheRdbTest, MetaLivesInCertManagerConfig)
{
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_IN_CONFIG), CM_SUCCESS);
    /* the row must live in cert_manager_config under the whitelisted key */
    char value[MAX_LEN_CONFIG_VALUE] = { 0 };
    ASSERT_EQ(QueryConfigByKey(REVOCATION_CACHE_LAST_CLEANUP_KEY.c_str(), value, sizeof(value)), CM_SUCCESS);
    EXPECT_STREQ(value, std::to_string(META_VALUE_IN_CONFIG).c_str());
    int64_t roundTrip = 0;
    ASSERT_EQ(GetRevocationCacheMeta(&roundTrip), CM_SUCCESS);
    EXPECT_EQ(roundTrip, META_VALUE_IN_CONFIG);
}

TEST_F(CmRevocationCacheRdbTest, QueryAllConfigCoversInternalKeyCapacity)
{
    /* the config table legitimately holds 4 keys: 3 external + the internal meta key;
     * self-heal first so an interrupted earlier run cannot inflate the count */
    (void)DeleteConfigByKey("installGlobalUserCA_defaultConfig");
    (void)DeleteConfigByKey("enableInstallGlobalUserCA_userList");
    (void)DeleteConfigByKey("disableInstallGlobalUserCA_userList");
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_IN_CONFIG), CM_SUCCESS);
    ASSERT_EQ(InsertOrUpdateConfig("installGlobalUserCA_defaultConfig", "disable"), CM_SUCCESS);
    ASSERT_EQ(InsertOrUpdateConfig("enableInstallGlobalUserCA_userList", "100"), CM_SUCCESS);
    ASSERT_EQ(InsertOrUpdateConfig("disableInstallGlobalUserCA_userList", "101"), CM_SUCCESS);

    struct CertManagerConfig config = { 0, nullptr };
    ASSERT_EQ(QueryAllConfig(&config), CM_SUCCESS);
    EXPECT_EQ(config.count, 4u);
    CM_FREE_PTR(config.configItems);

    /* drop the external keys: the meta row is removed by the shared teardown */
    ASSERT_EQ(DeleteConfigByKey("installGlobalUserCA_defaultConfig"), CM_SUCCESS);
    ASSERT_EQ(DeleteConfigByKey("enableInstallGlobalUserCA_userList"), CM_SUCCESS);
    ASSERT_EQ(DeleteConfigByKey("disableInstallGlobalUserCA_userList"), CM_SUCCESS);
}
