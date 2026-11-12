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

/* Direct tests for the cert-property rdb open callback
 * (cm_rdb_open_callback.cpp): OnCreate/OnOpen/OnDowngrade succeed, and
 * OnUpgrade appends the AUTH_STORAGE_LEVEL column only for the 1->2 step.
 * Every case uses its own throwaway database file under the engine rdb
 * directory and removes it again in TearDown. */

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <string>

#include "cm_rdb_config.h"
#include "cm_rdb_open_callback.h"
#include "rdb_helper.h"
#include "rdb_store_config.h"

using namespace testing::ext;

namespace OHOS::Security::CertManager {
namespace {
/* the pre-2.0 table layout: same columns as the current schema minus
 * AUTH_STORAGE_LEVEL, which the upgrade step is supposed to append */
const std::string LEGACY_CERT_PROPERTY_DDL = "CREATE TABLE IF NOT EXISTS " + CERT_PROPERTY_TABLE_NAME +
    "(URI TEXT PRIMARY KEY, ALIAS TEXT NOT NULL, SUBJECT_NAME TEXT NOT NULL, CERT_TYPE TEXT NOT NULL, "
    "CERT_STORE INTEGER NOT NULL, USERID INTEGER NOT NULL, UID INTEGER NOT NULL);";

uint32_t g_dbSequence = 0;

std::string NewDbName()
{
    ++g_dbSequence;
    return "/cm_rdb_open_callback_test_" + std::to_string(g_dbSequence) + ".db";
}

std::shared_ptr<NativeRdb::RdbStore> OpenStore(const RdbConfig &rdbConfig, int32_t version)
{
    NativeRdb::RdbStoreConfig storeConfig(rdbConfig.dbPath + rdbConfig.dbName);
    storeConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    CmRdbOpenCallback callback(rdbConfig);
    int32_t errCode = NativeRdb::E_OK;
    return NativeRdb::RdbHelper::GetRdbStore(storeConfig, version, callback, errCode);
}

bool ColumnExists(const std::shared_ptr<NativeRdb::RdbStore> &store,
    const std::string &table, const std::string &column)
{
    std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet =
        store->QuerySql("PRAGMA table_info(" + table + ");");
    if (resultSet == nullptr) {
        return false;
    }
    int nameIndex = -1;
    bool found = false;
    if (resultSet->GetColumnIndex("name", nameIndex) == NativeRdb::E_OK) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            std::string name;
            if (resultSet->GetString(nameIndex, name) == NativeRdb::E_OK && name == column) {
                found = true;
                break;
            }
        }
    }
    (void)resultSet->Close();
    return found;
}
} // namespace

class CmRdbOpenCallbackTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        (void)mkdir("/data/service/el1/public/cert_manager_service", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        (void)mkdir("/data/service/el1/public/cert_manager_service/rdb",
            S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }

    void SetUp() override
    {
        rdbConfig_.version = RDB_VERSION_CURRENT;
        rdbConfig_.dbPath = "/data/service/el1/public/cert_manager_service/rdb";
        rdbConfig_.dbName = NewDbName();
        rdbConfig_.tableName = CERT_PROPERTY_TABLE_NAME;
    }

    void TearDown() override
    {
        NativeRdb::RdbHelper::ClearCache();
        const std::string base = rdbConfig_.dbPath + rdbConfig_.dbName;
        (void)unlink(base.c_str());
        (void)unlink((base + "-wal").c_str());
        (void)unlink((base + "-shm").c_str());
        (void)unlink((base + "-journal").c_str());
    }

protected:
    RdbConfig rdbConfig_;
};

/**
 * @tc.name: CmRdbOpenCallbackCreateOpenDowngrade_001
 * @tc.desc: a fresh database runs OnCreate and OnOpen and the callbacks report success.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbOpenCallbackTest, CmRdbOpenCallbackCreateOpenDowngrade_001, TestSize.Level0)
{
    std::shared_ptr<NativeRdb::RdbStore> store = OpenStore(rdbConfig_, RDB_VERSION_CURRENT);
    ASSERT_NE(store, nullptr);

    CmRdbOpenCallback callback(rdbConfig_);
    EXPECT_EQ(callback.OnCreate(*store), NativeRdb::E_OK);
    EXPECT_EQ(callback.OnOpen(*store), NativeRdb::E_OK);
    EXPECT_EQ(callback.OnDowngrade(*store, RDB_VERSION_CURRENT, RDB_VERSION_FIRST), NativeRdb::E_OK);
}

/**
 * @tc.name: CmRdbOpenCallbackUpgradeAddsColumn_001
 * @tc.desc: the 1->2 upgrade appends the AUTH_STORAGE_LEVEL column, other versions are no-ops.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbOpenCallbackTest, CmRdbOpenCallbackUpgradeAddsColumn_001, TestSize.Level0)
{
    std::shared_ptr<NativeRdb::RdbStore> store = OpenStore(rdbConfig_, RDB_VERSION_CURRENT);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->ExecuteSql(LEGACY_CERT_PROPERTY_DDL), NativeRdb::E_OK);
    EXPECT_FALSE(ColumnExists(store, CERT_PROPERTY_TABLE_NAME, COLUMN_AUTH_STORAGE_LEVEL));

    CmRdbOpenCallback callback(rdbConfig_);
    /* the real 1->2 step appends the missing column */
    EXPECT_EQ(callback.OnUpgrade(*store, RDB_VERSION_FIRST, RDB_VERSION_CURRENT), NativeRdb::E_OK);
    EXPECT_TRUE(ColumnExists(store, CERT_PROPERTY_TABLE_NAME, COLUMN_AUTH_STORAGE_LEVEL));

    /* rerunning the upgrade hits the duplicate column error but still reports success */
    EXPECT_EQ(callback.OnUpgrade(*store, RDB_VERSION_FIRST, RDB_VERSION_CURRENT), NativeRdb::E_OK);

    /* any other version combination skips the sql entirely */
    EXPECT_EQ(callback.OnUpgrade(*store, RDB_VERSION_CURRENT, RDB_VERSION_CURRENT), NativeRdb::E_OK);
    EXPECT_EQ(callback.OnUpgrade(*store, RDB_VERSION_FIRST, RDB_VERSION_FIRST), NativeRdb::E_OK);
}

/**
 * @tc.name: CmRdbOpenCallbackUpgradeViaHelper_001
 * @tc.desc: reopening a version 1 database at version 2 drives the upgrade through the rdb helper.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbOpenCallbackTest, CmRdbOpenCallbackUpgradeViaHelper_001, TestSize.Level0)
{
    RdbConfig firstConfig = rdbConfig_;
    std::shared_ptr<NativeRdb::RdbStore> oldStore = OpenStore(firstConfig, RDB_VERSION_FIRST);
    ASSERT_NE(oldStore, nullptr);
    ASSERT_EQ(oldStore->ExecuteSql(LEGACY_CERT_PROPERTY_DDL), NativeRdb::E_OK);
    EXPECT_FALSE(ColumnExists(oldStore, CERT_PROPERTY_TABLE_NAME, COLUMN_AUTH_STORAGE_LEVEL));

    /* reopen the same file at the current version: the helper detects the
     * stale user_version and routes through OnUpgrade(1, 2) */
    NativeRdb::RdbHelper::ClearCache();
    std::shared_ptr<NativeRdb::RdbStore> newStore = OpenStore(rdbConfig_, RDB_VERSION_CURRENT);
    ASSERT_NE(newStore, nullptr);
    EXPECT_TRUE(ColumnExists(newStore, CERT_PROPERTY_TABLE_NAME, COLUMN_AUTH_STORAGE_LEVEL));
}
} // namespace OHOS::Security::CertManager
