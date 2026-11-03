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
#include <memory>
#include <string>

#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "cm_root_ca_store_rdb.h"

using namespace testing::ext;

namespace {
/* 64-char uppercase hex stand-ins: the value only has to round-trip */
const char *PK_HASH_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const char *PK_HASH_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const char *PK_HASH_C = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/* query capacity used by the test cases: far below the engine's 256 cap */
constexpr uint32_t TEST_RECORD_CAPACITY = 4;

/* engine uri blobs carry the trailing NUL (fileName.size = strlen + 1 in
 * cert_manager_query.c): the store must key both spellings to the same row */
constexpr uint32_t URI_NUL_LEN = 1;

/* drop the whole table so every test starts and ends on an empty store */
void DropRootCaStoreTable()
{
    using namespace OHOS::Security::CertManager;
    RdbConfig dropCfg;
    dropCfg.dbName = CERT_MANAGER_RDB_NAME;
    dropCfg.tableName = ROOT_CA_STORE_TABLE_NAME;
    dropCfg.createTableSql = "DROP TABLE IF EXISTS " + ROOT_CA_STORE_TABLE_NAME;
    /* make_shared is mandatory: the manager takes shared_from_this on open */
    auto dropMgr = std::make_shared<CmRdbDataManager>(dropCfg);
    (void)dropMgr->CreateTable();
}
} // namespace

class CmRootCaStoreRdbTest : public testing::Test {
public:
    void SetUp() override
    {
        DropRootCaStoreTable();
        ASSERT_EQ(CreateRootCaStoreRdb(), CM_SUCCESS);
    }
    void TearDown() override
    {
        DropRootCaStoreTable();
    }
};

TEST_F(CmRootCaStoreRdbTest, CreateTableSucceeds)
{
    /* idempotent: a second create over the existing table stays a success */
    EXPECT_EQ(CreateRootCaStoreRdb(), CM_SUCCESS);
}

TEST_F(CmRootCaStoreRdbTest, UpsertDisabledThenQuery)
{
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_A),
        CM_SUCCESS);

    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 0;
    ASSERT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, &count), CM_SUCCESS);
    ASSERT_EQ(count, 1u);
    EXPECT_STREQ(records[0].uri, "testa.0");
    EXPECT_EQ(records[0].algType, CM_ROOT_CA_ALG_TYPE_INTERNATIONAL);
    EXPECT_EQ(records[0].enable, 0u);
    EXPECT_STREQ(records[0].certPkHash, PK_HASH_A);

    uint32_t enable = 1;
    ASSERT_EQ(QueryRootCaEnable("testa.0", strlen("testa.0"), &enable), CM_SUCCESS);
    EXPECT_EQ(enable, 0u);
}

TEST_F(CmRootCaStoreRdbTest, ReupsertEnableClearsDisabled)
{
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_GM, 0, PK_HASH_A), CM_SUCCESS);
    /* same uri, now enabled: the upsert must update the row, not duplicate it */
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_GM, 1, PK_HASH_A), CM_SUCCESS);

    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 1; /* must be reset to 0: nothing is disabled anymore */
    ASSERT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, &count), CM_SUCCESS);
    EXPECT_EQ(count, 0u);

    uint32_t enable = 0;
    ASSERT_EQ(QueryRootCaEnable("testa.0", strlen("testa.0"), &enable), CM_SUCCESS);
    EXPECT_EQ(enable, 1u);
}

TEST_F(CmRootCaStoreRdbTest, UriWithTrailingNulKeysSameRow)
{
    /* engine callers pass blobs sized strlen + 1: the row key must not
     * inherit the NUL byte, or the enable lookup would never match */
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0") + URI_NUL_LEN, CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0,
        PK_HASH_A), CM_SUCCESS);

    uint32_t enable = 1;
    ASSERT_EQ(QueryRootCaEnable("testa.0", strlen("testa.0"), &enable), CM_SUCCESS);
    EXPECT_EQ(enable, 0u);

    /* and back out with a NUL-less spelling: same row again */
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 1, PK_HASH_A),
        CM_SUCCESS);
    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 1;
    ASSERT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, &count), CM_SUCCESS);
    EXPECT_EQ(count, 0u);
}

TEST_F(CmRootCaStoreRdbTest, QueryUnknownUriDefaultsEnabled)
{
    /* no row at all: the caller treats every unrecorded root CA as enabled */
    uint32_t enable = 0;
    EXPECT_EQ(QueryRootCaEnable("nonexist.0", strlen("nonexist.0"), &enable), CM_SUCCESS);
    EXPECT_EQ(enable, 1u);
}

TEST_F(CmRootCaStoreRdbTest, QueryReturnsOnlyDisabledOrderedByUri)
{
    ASSERT_EQ(UpsertRootCaStore("testb.0", strlen("testb.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_B),
        CM_SUCCESS);
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_GM, 0, PK_HASH_A), CM_SUCCESS);
    ASSERT_EQ(UpsertRootCaStore("testc.0", strlen("testc.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 1, PK_HASH_C),
        CM_SUCCESS);

    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 0;
    ASSERT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, &count), CM_SUCCESS);
    ASSERT_EQ(count, 2u);
    /* ORDER BY URI keeps the policy-file output deterministic */
    EXPECT_STREQ(records[0].uri, "testa.0");
    EXPECT_STREQ(records[0].certPkHash, PK_HASH_A);
    EXPECT_STREQ(records[1].uri, "testb.0");
    EXPECT_STREQ(records[1].certPkHash, PK_HASH_B);
}

TEST_F(CmRootCaStoreRdbTest, QueryRejectsTooSmallBuffer)
{
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_A),
        CM_SUCCESS);
    ASSERT_EQ(UpsertRootCaStore("testb.0", strlen("testb.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_B),
        CM_SUCCESS);

    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 0;
    EXPECT_EQ(QueryDisabledRootCa(records, 1, &count), CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRootCaStoreRdbTest, NullArgsRejected)
{
    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 0;
    uint32_t enable = 1;
    EXPECT_EQ(UpsertRootCaStore(nullptr, 1, CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_A),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, nullptr),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryDisabledRootCa(nullptr, TEST_RECORD_CAPACITY, &count), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRootCaEnable(nullptr, 1, &enable), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRootCaEnable("testa.0", strlen("testa.0"), nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
