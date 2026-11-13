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
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#include "securec.h"

#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_status.h"
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

/* drop the whole table (used INSIDE one test to simulate a fresh table;
 * fixtures must NOT leave it dropped: the SA shares this database file) */
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

/* delete every row, then rewrite the policy file to match: the table itself
 * stays because the SA reads the same database file.
 * WARNING: this wipes REAL rows — any manual disable state an actual user
 * recorded in root_ca_cert_store is lost; running these tests is therefore
 * confined to a dedicated test device */
void CleanupRootCaStoreState()
{
    using namespace OHOS::Security::CertManager;
    RdbConfig cleanCfg;
    cleanCfg.dbName = CERT_MANAGER_RDB_NAME;
    cleanCfg.tableName = ROOT_CA_STORE_TABLE_NAME;
    /* make_shared is mandatory: the manager takes shared_from_this on open */
    auto cleanMgr = std::make_shared<CmRdbDataManager>(cleanCfg);
    (void)cleanMgr->ExecuteSql("DELETE FROM " + ROOT_CA_STORE_TABLE_NAME,
        std::vector<OHOS::NativeRdb::ValueObject>());
    (void)CmRegenerateRevocationPolicyFile();
}

/* whether FORCE_CHECK_POLICY_DIR existed before this suite started: the
 * service cfg mkdirs it on images carrying this PR, so what existed before
 * the suite is not the suite's to remove; when the suite created the
 * directory itself (old image: the engine's self-healing mkdir fallback
 * inside CmRegenerateRevocationPolicyFile), TearDownTestCase removes it
 * again so no forceCheck residue stays on the device */
bool g_policyDirPreExisting = false;
} // namespace

class CmRootCaStoreRdbTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        /* snapshot before the first SetUp regenerates the policy file,
         * which mkdirs the directory when missing */
        g_policyDirPreExisting = (access(FORCE_CHECK_POLICY_DIR, F_OK) == 0);
    }

    static void TearDownTestCase(void)
    {
        /* the last per-test TearDown already cleared the rows and
         * regenerated the empty policy file; when this suite created the
         * directory itself, remove it again so no forceCheck residue
         * stays; a pre-existing (cfg-owned) directory keeps the empty
         * file: an empty file is the no-disabled contract */
        if (g_policyDirPreExisting) {
            return;
        }
        (void)unlink(FORCE_CHECK_POLICY_FILE ".tmp");
        (void)unlink(FORCE_CHECK_POLICY_FILE);
        EXPECT_EQ(rmdir(FORCE_CHECK_POLICY_DIR), 0) << "removing suite-created forceCheck dir failed";
    }

    void SetUp() override
    {
        CleanupRootCaStoreState();
        ASSERT_EQ(CreateRootCaStoreRdb(), CM_SUCCESS);
    }
    void TearDown() override
    {
        CleanupRootCaStoreState();
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

/* ---------- CmRegenerateRevocationPolicyFile / CmSetSystemCertStatus ---------- */

/* read the whole policy file; false when it cannot be opened */
static bool ReadPolicyFile(std::string &out)
{
    std::ifstream f(FORCE_CHECK_POLICY_FILE, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

TEST_F(CmRootCaStoreRdbTest, RegeneratePolicyFileEmptyWhenNothingDisabled)
{
    ASSERT_EQ(CmRegenerateRevocationPolicyFile(), CM_SUCCESS);

    std::string content;
    ASSERT_TRUE(ReadPolicyFile(content));
    EXPECT_EQ(content.size(), 0u); /* no disabled row: 0-byte file, not absent */
}

TEST_F(CmRootCaStoreRdbTest, RegeneratePolicyFileListsDisabledOrderedByUri)
{
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_A),
        CM_SUCCESS);
    ASSERT_EQ(UpsertRootCaStore("testb.0", strlen("testb.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_B),
        CM_SUCCESS);
    ASSERT_EQ(CmRegenerateRevocationPolicyFile(), CM_SUCCESS);

    std::string content;
    ASSERT_TRUE(ReadPolicyFile(content));
    /* one "1,<hash>" line per disabled row, ordered by uri */
    std::string expected = std::string("1,") + PK_HASH_A + "\n" + "1," + PK_HASH_B + "\n";
    EXPECT_EQ(content, expected);
}

TEST_F(CmRootCaStoreRdbTest, RegeneratePolicyFileClearsAfterTableReset)
{
    ASSERT_EQ(UpsertRootCaStore("testa.0", strlen("testa.0"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL, 0, PK_HASH_A),
        CM_SUCCESS);
    ASSERT_EQ(CmRegenerateRevocationPolicyFile(), CM_SUCCESS);
    std::string before;
    ASSERT_TRUE(ReadPolicyFile(before));
    ASSERT_GT(before.size(), 0u);

    /* fresh table: nothing disabled means the policy file empties out again */
    DropRootCaStoreTable();
    ASSERT_EQ(CreateRootCaStoreRdb(), CM_SUCCESS);
    ASSERT_EQ(CmRegenerateRevocationPolicyFile(), CM_SUCCESS);
    std::string after;
    ASSERT_TRUE(ReadPolicyFile(after));
    EXPECT_EQ(after.size(), 0u);
}

TEST_F(CmRootCaStoreRdbTest, SetSystemCertStatusUnknownUriRejected)
{
    /* start from a known state: empty policy file */
    ASSERT_EQ(CmRegenerateRevocationPolicyFile(), CM_SUCCESS);
    std::string before;
    ASSERT_TRUE(ReadPolicyFile(before));
    ASSERT_EQ(before.size(), 0u);

    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    char uriBuf[] = "INVALIDXXXX";
    struct CmBlob uri = { sizeof(uriBuf), (uint8_t *)uriBuf };
    /* uri not in the system store: nothing recorded, nothing rewritten;
     * NULL out param is accepted on the rejection path */
    EXPECT_EQ(CmSetSystemCertStatus(&context, &uri, CERT_STATUS_DISABLED, NULL), CMR_ERROR_NOT_EXIST);

    struct RootCaStoreRecord records[TEST_RECORD_CAPACITY] = {};
    uint32_t count = 1;
    EXPECT_EQ(QueryDisabledRootCa(records, TEST_RECORD_CAPACITY, &count), CM_SUCCESS);
    EXPECT_EQ(count, 0u);
    std::string after;
    ASSERT_TRUE(ReadPolicyFile(after));
    EXPECT_EQ(after, before);
}

/* device case: round-trips the first REAL system root CA uri through
 * disable/enable; needs /etc/security/certificates on the target */
TEST_F(CmRootCaStoreRdbTest, SetSystemCertStatusRealUriRoundTrip)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    struct CmMutableBlob certFileList = { 0, nullptr };
    const struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
    ASSERT_EQ(CmServiceGetCertList(&context, &prop, CM_SYSTEM_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    ASSERT_GT(certFileList.size, 0u);

    /* copy the uri before the list (and its buffers) is freed */
    struct CertFileInfo *files = (struct CertFileInfo *)certFileList.data;
    ASSERT_GT(files[0].fileName.size, 0u);
    ASSERT_LT(files[0].fileName.size, (uint32_t)sizeof(char[MAX_LEN_URI]));
    char uriBuf[MAX_LEN_URI] = {0};
    ASSERT_EQ(memcpy_s(uriBuf, sizeof(uriBuf), files[0].fileName.data, files[0].fileName.size), EOK);
    CmFreeCertFiles(files, certFileList.size);

    struct CmBlob uri = { (uint32_t)strlen(uriBuf) + 1, (uint8_t *)uriBuf };
    char outPkHash[CM_ROOT_CA_PK_HASH_HEX_LEN + 1] = { 0 };
    ASSERT_EQ(CmSetSystemCertStatus(&context, &uri, CERT_STATUS_DISABLED, outPkHash), CM_SUCCESS);
    /* the out hash is the value the engine committed to the store */
    EXPECT_EQ(strlen(outPkHash), CM_ROOT_CA_PK_HASH_HEX_LEN);

    uint32_t enable = 1;
    ASSERT_EQ(QueryRootCaEnable(uriBuf, strlen(uriBuf), &enable), CM_SUCCESS);
    EXPECT_EQ(enable, 0u);

    std::string content;
    ASSERT_TRUE(ReadPolicyFile(content));
    /* exactly one force-check line: "1," + 64 uppercase hex chars + '\n' */
    constexpr size_t policyPrefixLen = 2; /* "1," */
    constexpr size_t policyLineLen = policyPrefixLen + CM_ROOT_CA_PK_HASH_HEX_LEN + 1;
    ASSERT_EQ(content.size(), policyLineLen);
    EXPECT_EQ(content.substr(0, policyPrefixLen), "1,");
    /* the policy line carries the same hash the engine reported */
    EXPECT_EQ(content.substr(policyPrefixLen, CM_ROOT_CA_PK_HASH_HEX_LEN), std::string(outPkHash));
    EXPECT_EQ(content[policyLineLen - 1], '\n');

    /* re-enable empties the policy file and clears the disabled row; NULL
     * out param on a success path exercises the internal fallback buffer */
    ASSERT_EQ(CmSetSystemCertStatus(&context, &uri, CERT_STATUS_ENANLED, NULL), CM_SUCCESS);
    std::string cleared;
    ASSERT_TRUE(ReadPolicyFile(cleared));
    EXPECT_EQ(cleared.size(), 0u);
    uint32_t reenable = 0;
    ASSERT_EQ(QueryRootCaEnable(uriBuf, strlen(uriBuf), &reenable), CM_SUCCESS);
    EXPECT_EQ(reenable, 1u);
}
