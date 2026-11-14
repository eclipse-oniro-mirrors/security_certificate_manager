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

/* Direct tests for the rdb C APIs of the engine rdb directory
 * (cm_cert_property_rdb / cm_config_rdb / cm_revocation_cache_rdb) and the
 * CmRdbDataManager failure paths. The suite is linked FIRST in cm_sdk_test
 * on purpose: the first case observes the file-scope data-manager pointers
 * before any engine initialization, covering the not-initialized guards of
 * every exported API. The remaining cases then create the tables themselves
 * and drive the query/update branches that the engine-level suites cannot
 * reach (oversized column values, empty results, dropped tables). */

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "rdb_helper.h"
#include "values_bucket.h"

#include "cm_cert_property_rdb.h"
#include "cm_config_rdb.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "securec.h"

using namespace testing::ext;

namespace OHOS::Security::CertManager {
namespace {
constexpr int64_t RDB_API_FUTURE_EXPIRE = 2000000000LL; /* fixed future timestamp */
constexpr int64_t RDB_API_PAST_EXPIRE = 1000000000LL;   /* fixed past timestamp */
constexpr uint64_t RDB_API_SENTINEL_SIZE = 77;          /* must be overwritten by the query */
const std::string RDB_API_DIRECT_DB = "/cm_rdb_api_test_dm.db";
/* fixed ids the raw-row helper writes past the MakeCertProperty buffers */
constexpr int32_t RDB_API_RAW_USERID = 700009;
constexpr int32_t RDB_API_RAW_UID = 700010;

/* remove every revocation cache row and the meta entry left by earlier runs */
void CleanupRevocationRows()
{
    char **paths = nullptr;
    uint32_t count = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &count) != CM_SUCCESS) {
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        (void)DeleteRevocationCacheRecord(paths[i]);
    }
    FreeRevocationCacheFilePaths(paths, count);
    (void)DeleteRevocationCacheMeta();
}

struct CertProperty MakeCertProperty(const char *uri, const char *alias, const char *subject,
    const char *certType, int32_t userId)
{
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    (void)strcpy_s(prop.uri, sizeof(prop.uri), uri);
    (void)strcpy_s(prop.alias, sizeof(prop.alias), alias);
    (void)strcpy_s(prop.subjectName, sizeof(prop.subjectName), subject);
    (void)strcpy_s(prop.certType, sizeof(prop.certType), certType);
    prop.certStore = CM_USER_TRUSTED_STORE;
    prop.userId = userId;
    prop.uid = userId + 1;
    prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
    return prop;
}

struct CmFindCertCondition BuildCondition(const char *certType, const int32_t *userIds,
    uint32_t userIdCount, const char *name, const char *certId)
{
    struct CmFindCertCondition cond = { nullptr, nullptr, 0, nullptr, nullptr };
    cond.certType = certType;
    cond.userIds = userIds;
    cond.userIdCount = userIdCount;
    cond.name = name;
    cond.certId = certId;
    return cond;
}

/* run one conditioned query and count how many of the given uris it returned */
uint32_t CountMatchingUris(const struct CmFindCertCondition &cond, const std::vector<std::string> &uris)
{
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    EXPECT_EQ(QueryCertPropertyByCondition(&cond, &results, &count), CM_SUCCESS);
    uint32_t matched = 0;
    for (uint32_t i = 0; i < count; i++) {
        for (const auto &uri : uris) {
            if (uri == results[i].uri) {
                matched++;
                break;
            }
        }
    }
    free(results);
    return matched;
}

/* insert a raw row bypassing the CertProperty fixed-size buffers: the values
 * may exceed the C-struct limits, which the query readers must survive */
void InsertCertPropertyRaw(const std::string &uri, const std::string &alias,
    const std::string &subject, const std::string &certType)
{
    RdbConfig cfg;
    cfg.dbName = CERT_MANAGER_RDB_NAME;
    cfg.tableName = CERT_PROPERTY_TABLE_NAME;
    auto mgr = std::make_shared<CmRdbDataManager>(cfg);
    NativeRdb::ValuesBucket bucket;
    bucket.PutString(COLUMN_URI, uri);
    bucket.PutString(COLUMN_ALIAS, alias);
    bucket.PutString(COLUMN_SUBJECT_NAME, subject);
    bucket.PutString(COLUMN_CERT_TYPE, certType);
    bucket.PutInt(COLUMN_CERT_STORE, CM_USER_TRUSTED_STORE);
    bucket.PutInt(COLUMN_USERID, RDB_API_RAW_USERID);
    bucket.PutInt(COLUMN_UID, RDB_API_RAW_UID);
    bucket.PutInt(COLUMN_AUTH_STORAGE_LEVEL, 1);
    ASSERT_TRUE(mgr->InsertData(bucket));
}
} // namespace

class CmRdbApiTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        (void)mkdir("/data/service/el1/public/cert_manager_service", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        (void)mkdir("/data/service/el1/public/cert_manager_service/rdb",
            S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
};

/**
 * @tc.name: RdbApiGuardBeforeInit_001
 * @tc.desc: every rdb C API rejects calls made before its data manager was created.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiGuardBeforeInit_001, TestSize.Level0)
{
    /* this suite is linked first, so the file-scope managers are still null
     * here: every API must fail fast with CMR_ERROR_NULL_POINTER */
    struct CertProperty prop = MakeCertProperty("oh:t=rd;o=rdinit;u=1;a=1", "a", "s", "z", 1);
    EXPECT_EQ(InsertCertProperty(&prop), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(UpdateCertProperty(&prop), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(DeleteCertProperty(prop.uri), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryCertProperty(prop.uri, &prop), CMR_ERROR_NULL_POINTER);
    struct CertProperty *results = nullptr;
    uint32_t resultCount = 0;
    struct CmFindCertCondition cond = BuildCondition(nullptr, nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(QueryCertPropertyByCondition(&cond, &results, &resultCount), CMR_ERROR_NULL_POINTER);

    EXPECT_EQ(InsertOrUpdateConfig("rdc_init", "v"), CMR_ERROR_NULL_POINTER);
    char value[MAX_LEN_CONFIG_VALUE] = { 0 };
    EXPECT_EQ(QueryConfigByKey("rdc_init", value, sizeof(value)), CMR_ERROR_NULL_POINTER);
    struct CertManagerConfig config = { 0, nullptr };
    EXPECT_EQ(QueryAllConfig(&config), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(DeleteConfigByKey("rdc_init"), CMR_ERROR_NULL_POINTER);

    struct RevocationCacheRecord record = { RDB_API_FUTURE_EXPIRE, "rdinit", "ocsp",
        "ocsp/rdinit.cache", 16 };
    uint64_t totalSize = 0;
    char **paths = nullptr;
    uint32_t pathCount = 0;
    EXPECT_EQ(InsertRevocationCacheRecord(&record), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(DeleteRevocationCacheRecord(record.filePath), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(MarkRevocationCacheRecordDeleted(record.filePath), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryRevocationCacheActiveSumSize("k", "t", &totalSize), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryRevocationCacheDeletedSumSize(&totalSize), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryRevocationCacheEvictCandidate("k", "t", &record), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryExpiredRevocationCacheRecord(RDB_API_PAST_EXPIRE, &record), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(&paths, &pathCount), CMR_ERROR_NULL_POINTER);
}

/**
 * @tc.name: RdbApiGuardNullArguments_002
 * @tc.desc: every rdb C API rejects null pointers and empty buffers as invalid arguments.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiGuardNullArguments_002, TestSize.Level0)
{
    struct CertProperty prop = MakeCertProperty("oh:t=rd;o=rdarg;u=1;a=1", "a", "s", "z", 1);
    struct CertProperty out;
    (void)memset_s(&out, sizeof(out), 0, sizeof(out));
    EXPECT_EQ(InsertCertProperty(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(UpdateCertProperty(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(DeleteCertProperty(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertProperty(nullptr, &out), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertProperty(prop.uri, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    struct CertProperty *results = nullptr;
    uint32_t resultCount = 0;
    struct CmFindCertCondition cond = BuildCondition(nullptr, nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(QueryCertPropertyByCondition(nullptr, &results, &resultCount), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertPropertyByCondition(&cond, nullptr, &resultCount), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertPropertyByCondition(&cond, &results, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    char value[MAX_LEN_CONFIG_VALUE] = { 0 };
    EXPECT_EQ(InsertOrUpdateConfig(nullptr, "v"), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(InsertOrUpdateConfig("rdc_arg", nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryConfigByKey(nullptr, value, sizeof(value)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryConfigByKey("rdc_arg", nullptr, sizeof(value)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryConfigByKey("rdc_arg", value, 0), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryAllConfig(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(DeleteConfigByKey(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    uint64_t totalSize = 0;
    EXPECT_EQ(MarkRevocationCacheRecordDeleted(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRevocationCacheDeletedSumSize(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRevocationCacheActiveSumSize(nullptr, "t", &totalSize), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRevocationCacheActiveSumSize("k", nullptr, &totalSize), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryRevocationCacheActiveSumSize("k", "t", nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: RdbApiCertPropertyCrud_003
 * @tc.desc: the cert_property API round-trips insert, query, update and delete.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiCertPropertyCrud_003, TestSize.Level0)
{
    ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
    struct CertProperty prop = MakeCertProperty("oh:t=rd;o=rdcrud;u=700001;a=1", "rdcrudAlias",
        "rdcrudSubject", "z", 700001);
    ASSERT_EQ(InsertCertProperty(&prop), CM_SUCCESS);

    struct CertProperty out;
    (void)memset_s(&out, sizeof(out), 0, sizeof(out));
    ASSERT_EQ(QueryCertProperty(prop.uri, &out), CM_SUCCESS);
    EXPECT_STREQ(out.uri, prop.uri);
    EXPECT_STREQ(out.alias, prop.alias);
    EXPECT_STREQ(out.subjectName, prop.subjectName);
    EXPECT_STREQ(out.certType, prop.certType);
    EXPECT_EQ(out.certStore, prop.certStore);
    EXPECT_EQ(out.userId, prop.userId);
    EXPECT_EQ(out.uid, prop.uid);
    EXPECT_EQ(out.level, prop.level);

    (void)strcpy_s(prop.alias, sizeof(prop.alias), "rdcrudAliasTwo");
    ASSERT_EQ(UpdateCertProperty(&prop), CM_SUCCESS);
    (void)memset_s(&out, sizeof(out), 0, sizeof(out));
    ASSERT_EQ(QueryCertProperty(prop.uri, &out), CM_SUCCESS);
    EXPECT_STREQ(out.alias, "rdcrudAliasTwo");

    ASSERT_EQ(DeleteCertProperty(prop.uri), CM_SUCCESS);
    (void)memset_s(&out, sizeof(out), 0, sizeof(out));
    /* a missing row is not an error: success with an untouched output */
    ASSERT_EQ(QueryCertProperty(prop.uri, &out), CM_SUCCESS);
    EXPECT_EQ(out.uri[0], '\0');
}

/**
 * @tc.name: RdbApiCertPropertyCondition_004
 * @tc.desc: the conditioned query applies each filter alone and in combination.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiCertPropertyCondition_004, TestSize.Level0)
{
    ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
    const std::string uriOne = "oh:t=rd;o=rdm1;u=700001;a=1";
    const std::string uriTwo = "oh:t=rd;o=rdm2;u=700002;a=2";
    const std::string uriThree = "oh:t=rd;o=rdm3;u=700003;a=3";
    struct CertProperty one = MakeCertProperty(uriOne.c_str(), "rdmAlpha", "rdmSubjectOne", "z", 700001);
    struct CertProperty two = MakeCertProperty(uriTwo.c_str(), "rdmBeta", "rdmSubjectTwo", "z", 700002);
    struct CertProperty three = MakeCertProperty(uriThree.c_str(), "rdmGamma", "rdmOther", "y", 700003);
    ASSERT_EQ(InsertCertProperty(&one), CM_SUCCESS);
    ASSERT_EQ(InsertCertProperty(&two), CM_SUCCESS);
    ASSERT_EQ(InsertCertProperty(&three), CM_SUCCESS);

    int32_t twoIds[] = { 700001, 700002 };
    int32_t oneId[] = { 700003 };
    /* certType filter: an empty string behaves like no filter at all */
    EXPECT_EQ(CountMatchingUris(BuildCondition("z", nullptr, 0, nullptr, nullptr), { uriOne, uriTwo }), 2u);
    EXPECT_EQ(CountMatchingUris(BuildCondition("", nullptr, 0, nullptr, nullptr),
        { uriOne, uriTwo, uriThree }), 3u);
    /* userId filter: two ids exercise the OR join, one id the plain equality */
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, twoIds, 2, nullptr, nullptr), { uriOne, uriTwo }), 2u);
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, oneId, 1, nullptr, nullptr), { uriThree }), 1u);
    /* name filter matches the alias and the subject */
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdmAlpha", nullptr), { uriOne }), 1u);
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdmSubjectTwo", nullptr), { uriTwo }), 1u);
    /* certId filter matches the o= component of the uri */
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, nullptr, "rdm2"), { uriTwo }), 1u);
    /* filters combine by AND */
    EXPECT_EQ(CountMatchingUris(BuildCondition("z", nullptr, 0, "rdmBeta", nullptr), { uriTwo }), 1u);

    /* a query matching nothing reports an empty result, not a failure */
    struct CertProperty *results = nullptr;
    uint32_t resultCount = 1;
    struct CmFindCertCondition cond = BuildCondition(nullptr, nullptr, 0, "rdbrdnomatch", nullptr);
    ASSERT_EQ(QueryCertPropertyByCondition(&cond, &results, &resultCount), CM_SUCCESS);
    EXPECT_EQ(resultCount, 0u);
    EXPECT_EQ(results, nullptr);

    ASSERT_EQ(DeleteCertProperty(uriOne.c_str()), CM_SUCCESS);
    ASSERT_EQ(DeleteCertProperty(uriTwo.c_str()), CM_SUCCESS);
    ASSERT_EQ(DeleteCertProperty(uriThree.c_str()), CM_SUCCESS);
}

/**
 * @tc.name: RdbApiCertPropertyOverflowSkipped_005
 * @tc.desc: rows whose column values exceed the C-struct buffers are skipped by the readers.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiCertPropertyOverflowSkipped_005, TestSize.Level0)
{
    ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
    /* one crafted row per column: each overflows exactly one fixed-size field
     * while keeping the filter marker inside the LIKE-matched column */
    const std::string longUri = "oh:t=rd;o=" + std::string(MAX_LEN_URI + 40, 'u') + ";u=1;a=1";
    const std::string longAlias = "rdbovfB" + std::string(MAX_LEN_CERT_ALIAS + 60, 'a');
    const std::string longSubject = "rdbovfSubject" + std::string(MAX_LEN_SUBJECT_NAME + 60, 's');
    const std::string longCertType = "z" + std::string(MAX_LEN_CERT_TYPE + 8, 't');
    const std::string uriB = "oh:t=rd;o=rdbovfB;u=1;a=1";
    const std::string uriC = "oh:t=rd;o=rdbovfC;u=1;a=1";
    const std::string uriD = "oh:t=rd;o=rdbovfD;u=1;a=1";
    InsertCertPropertyRaw(longUri, "rdbovfA", "rdbovfSubject", "z");
    InsertCertPropertyRaw(uriB, longAlias, "rdbovfSubject", "z");
    InsertCertPropertyRaw(uriC, "rdbovfC", longSubject, "z");
    InsertCertPropertyRaw(uriD, "rdbovfD", "rdbovfSubject", longCertType);

    /* every oversized row is dropped by the reader: the query itself succeeds
     * and reports an empty result instead of overflowing any buffer. Each
     * filter marker lives in the alias column the LIKE runs on; the matched
     * row then overflows one of the fixed-size fields while being read out */
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdbovfA", nullptr), { longUri }), 0u);
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdbovfB", nullptr), { uriB }), 0u);
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdbovfC", nullptr), { uriC }), 0u);
    EXPECT_EQ(CountMatchingUris(BuildCondition(nullptr, nullptr, 0, "rdbovfD", nullptr), { uriD }), 0u);

    ASSERT_EQ(DeleteCertProperty(longUri.c_str()), CM_SUCCESS);
    ASSERT_EQ(DeleteCertProperty(uriB.c_str()), CM_SUCCESS);
    ASSERT_EQ(DeleteCertProperty(uriC.c_str()), CM_SUCCESS);
    ASSERT_EQ(DeleteCertProperty(uriD.c_str()), CM_SUCCESS);
}

/**
 * @tc.name: RdbApiConfigQueryBranches_006
 * @tc.desc: the config API covers empty tables, oversized values and the item cap.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiConfigQueryBranches_006, TestSize.Level0)
{
    ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
    /* deterministic start: only the 3 external keys and the meta key are
     * legitimate; the rdc_* marker rows are self-healed away so an
     * interrupted earlier run cannot inflate any count below */
    (void)DeleteConfigByKey("installGlobalUserCA_defaultConfig");
    (void)DeleteConfigByKey("enableInstallGlobalUserCA_userList");
    (void)DeleteConfigByKey("disableInstallGlobalUserCA_userList");
    (void)DeleteConfigByKey(REVOCATION_CACHE_LAST_CLEANUP_KEY.c_str());
    (void)DeleteConfigByKey("rdc_long");
    (void)DeleteConfigByKey("rdc_one");
    for (int i = 0; i < 5; i++) {
        (void)DeleteConfigByKey(("rdc_junk" + std::to_string(i)).c_str());
    }

    /* empty table: query-all reports zero items and a null array */
    struct CertManagerConfig config = { 0, nullptr };
    ASSERT_EQ(QueryAllConfig(&config), CM_SUCCESS);
    EXPECT_EQ(config.count, 0u);
    EXPECT_EQ(config.configItems, nullptr);

    /* an oversized value aborts the whole row reader */
    std::string longValue(MAX_LEN_CONFIG_VALUE + 10, 'v');
    ASSERT_EQ(InsertOrUpdateConfig("rdc_long", longValue.c_str()), CM_SUCCESS);
    EXPECT_EQ(QueryAllConfig(&config), CMR_ERROR_QUERY_RDB_DATA_FAIL);
    ASSERT_EQ(DeleteConfigByKey("rdc_long"), CM_SUCCESS);

    /* normal round trip plus the small output buffer guard */
    std::string hundred(100, 'x');
    ASSERT_EQ(InsertOrUpdateConfig("rdc_one", hundred.c_str()), CM_SUCCESS);
    char value[MAX_LEN_CONFIG_VALUE] = { 0 };
    ASSERT_EQ(QueryConfigByKey("rdc_one", value, sizeof(value)), CM_SUCCESS);
    EXPECT_STREQ(value, hundred.c_str());
    EXPECT_EQ(QueryConfigByKey("rdc_one", value, 8), CMR_ERROR_MEM_OPERATION_COPY);
    ASSERT_EQ(DeleteConfigByKey("rdc_one"), CM_SUCCESS);
    EXPECT_EQ(QueryConfigByKey("rdc_one", value, sizeof(value)), CMR_ERROR_NOT_FOUND);

    /* the item cap counts every row: 5 junk keys exceed the cap of 4 */
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(InsertOrUpdateConfig(("rdc_junk" + std::to_string(i)).c_str(), "x"), CM_SUCCESS);
    }
    EXPECT_EQ(QueryAllConfig(&config), CMR_ERROR_INVALID_OPERATION);
    for (int i = 0; i < 5; i++) {
        (void)DeleteConfigByKey(("rdc_junk" + std::to_string(i)).c_str());
    }
}

/**
 * @tc.name: RdbApiRevocationCacheBranches_007
 * @tc.desc: the revocation cache covers deleted sums, negative sizes and expiry queries.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiRevocationCacheBranches_007, TestSize.Level0)
{
    ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    CleanupRevocationRows();

    /* deleted sum over an empty table: the NULL aggregate clamps to zero */
    uint64_t deletedSum = RDB_API_SENTINEL_SIZE;
    ASSERT_EQ(QueryRevocationCacheDeletedSumSize(&deletedSum), CM_SUCCESS);
    EXPECT_EQ(deletedSum, 0u);

    struct RevocationCacheRecord deleted = { RDB_API_FUTURE_EXPIRE, "rdbrone", "ocsp",
        "ocsp/rdbrone.cache", 111 };
    ASSERT_EQ(InsertRevocationCacheRecord(&deleted), CM_SUCCESS);
    ASSERT_EQ(MarkRevocationCacheRecordDeleted(deleted.filePath), CM_SUCCESS);
    ASSERT_EQ(QueryRevocationCacheDeletedSumSize(&deletedSum), CM_SUCCESS);
    EXPECT_EQ(deletedSum, 111u);

    /* a negative stored size clamps to zero on both read paths */
    struct RevocationCacheRecord negative = { RDB_API_FUTURE_EXPIRE, "rdbrneg", "ocsp",
        "ocsp/rdbrneg.cache", UINT64_MAX };
    ASSERT_EQ(InsertRevocationCacheRecord(&negative), CM_SUCCESS);
    uint64_t activeSum = RDB_API_SENTINEL_SIZE;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &activeSum), CM_SUCCESS);
    EXPECT_EQ(activeSum, 0u);
    struct RevocationCacheRecord candidate;
    (void)memset_s(&candidate, sizeof(candidate), 0, sizeof(candidate));
    ASSERT_EQ(QueryRevocationCacheEvictCandidate("none", "none", &candidate), CM_SUCCESS);
    EXPECT_STREQ(candidate.filePath, negative.filePath);
    EXPECT_EQ(candidate.dataSize, 0u);

    /* expired-record query: found while stale, not found once removed */
    struct RevocationCacheRecord expired = { RDB_API_PAST_EXPIRE, "rdbrexp", "ocsp",
        "ocsp/rdbrexp.cache", 55 };
    ASSERT_EQ(InsertRevocationCacheRecord(&expired), CM_SUCCESS);
    (void)memset_s(&candidate, sizeof(candidate), 0, sizeof(candidate));
    ASSERT_EQ(QueryExpiredRevocationCacheRecord(RDB_API_FUTURE_EXPIRE, &candidate), CM_SUCCESS);
    EXPECT_STREQ(candidate.filePath, expired.filePath);
    ASSERT_EQ(DeleteRevocationCacheRecord(expired.filePath), CM_SUCCESS);
    (void)memset_s(&candidate, sizeof(candidate), 0, sizeof(candidate));
    EXPECT_EQ(QueryExpiredRevocationCacheRecord(RDB_API_FUTURE_EXPIRE, &candidate), CMR_ERROR_NOT_FOUND);
}

/**
 * @tc.name: RdbApiRevocationCacheDroppedTable_008
 * @tc.desc: a dropped table turns every statement into its error, and the create self-heals.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiRevocationCacheDroppedTable_008, TestSize.Level0)
{
    /* defensive start: clear whatever an earlier case or run may have left */
    CleanupRevocationRows();

    /* a dropped table turns every statement into its query/update error */
    RdbConfig dropCfg;
    dropCfg.dbName = CERT_MANAGER_RDB_NAME;
    dropCfg.tableName = REVOCATION_CACHE_TABLE_NAME;
    dropCfg.createTableSql = std::string("DROP TABLE IF EXISTS ") + REVOCATION_CACHE_TABLE_NAME;
    auto dropMgr = std::make_shared<CmRdbDataManager>(dropCfg);
    ASSERT_TRUE(dropMgr->CreateTable());

    uint64_t activeSum = RDB_API_SENTINEL_SIZE;
    uint64_t deletedSum = RDB_API_SENTINEL_SIZE;
    struct RevocationCacheRecord candidate;
    (void)memset_s(&candidate, sizeof(candidate), 0, sizeof(candidate));
    EXPECT_EQ(MarkRevocationCacheRecordDeleted("ocsp/rdbrone.cache"), CMR_ERROR_UPDATE_RDB_DATA_FAIL);
    EXPECT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &activeSum), CMR_ERROR_QUERY_RDB_DATA_FAIL);
    EXPECT_EQ(QueryRevocationCacheDeletedSumSize(&deletedSum), CMR_ERROR_QUERY_RDB_DATA_FAIL);
    EXPECT_EQ(QueryRevocationCacheEvictCandidate("none", "none", &candidate), CMR_ERROR_QUERY_RDB_DATA_FAIL);
    EXPECT_EQ(QueryExpiredRevocationCacheRecord(RDB_API_FUTURE_EXPIRE, &candidate),
        CMR_ERROR_QUERY_RDB_DATA_FAIL);
    char **paths = nullptr;
    uint32_t pathCount = 0;
    EXPECT_EQ(QueryAllRevocationCacheFilePaths(&paths, &pathCount), CMR_ERROR_QUERY_RDB_DATA_FAIL);

    /* self-heal: the create rebuilds the table and later operations succeed */
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
    struct RevocationCacheRecord rebuilt = { RDB_API_FUTURE_EXPIRE, "rdbrone", "ocsp",
        "ocsp/rdbrone.cache", 111 };
    ASSERT_EQ(InsertRevocationCacheRecord(&rebuilt), CM_SUCCESS);
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &activeSum), CM_SUCCESS);
    EXPECT_EQ(activeSum, 111u);
    ASSERT_EQ(DeleteRevocationCacheRecord(rebuilt.filePath), CM_SUCCESS);
}

/**
 * @tc.name: RdbApiDataManagerFailurePaths_009
 * @tc.desc: CmRdbDataManager fails fast on an unwritable path and rejects bad create sql.
 * @tc.type: FUNC
 */
HWTEST_F(CmRdbApiTest, RdbApiDataManagerFailurePaths_009, TestSize.Level0)
{
    /* unwritable db path: the store never opens, every API fails fast */
    RdbConfig badCfg;
    badCfg.dbPath = "/dev/null/cm_rdb_api_test_bad_path";
    badCfg.dbName = "/bad.db";
    badCfg.tableName = "t_bad";
    badCfg.createTableSql = "CREATE TABLE IF NOT EXISTS t_bad(a INTEGER)";
    auto badMgr = std::make_shared<CmRdbDataManager>(badCfg);
    NativeRdb::ValuesBucket bucket;
    bucket.PutInt("a", 1);
    std::vector<NativeRdb::ValueObject> noArgs;
    EXPECT_FALSE(badMgr->InsertData(bucket));
    EXPECT_FALSE(badMgr->UpdateData("1", "a", bucket));
    EXPECT_FALSE(badMgr->DeleteData("1", "a"));
    EXPECT_EQ(badMgr->QueryData("1", "a"), nullptr);
    EXPECT_EQ(badMgr->QueryAllData(), nullptr);
    EXPECT_FALSE(badMgr->ExecuteSql("SELECT 1", noArgs));
    EXPECT_EQ(badMgr->QueryBySql("SELECT 1", noArgs), nullptr);
    EXPECT_EQ(badMgr->QueryDataWithPredicates(NativeRdb::AbsRdbPredicates("t_bad")), nullptr);
    EXPECT_FALSE(badMgr->CreateTable());

    /* writable path: guard clauses and sql failures report false */
    RdbConfig goodCfg;
    goodCfg.dbName = RDB_API_DIRECT_DB;
    goodCfg.tableName = "t_dm";
    goodCfg.createTableSql = "CREATE TABLE IF NOT EXISTS t_dm(a INTEGER)";
    auto goodMgr = std::make_shared<CmRdbDataManager>(goodCfg);
    ASSERT_TRUE(goodMgr->CreateTable());

    RdbConfig emptySqlCfg = goodCfg;
    emptySqlCfg.createTableSql = "";
    auto emptySqlMgr = std::make_shared<CmRdbDataManager>(emptySqlCfg);
    EXPECT_FALSE(emptySqlMgr->CreateTable()); /* an empty create sql is rejected */

    RdbConfig badSqlCfg = goodCfg;
    badSqlCfg.createTableSql = "THIS IS NOT SQL";
    auto badSqlMgr = std::make_shared<CmRdbDataManager>(badSqlCfg);
    EXPECT_FALSE(badSqlMgr->CreateTable());  /* an invalid create sql is rejected */
    EXPECT_FALSE(goodMgr->ExecuteSql("THIS IS NOT SQL", noArgs));
    EXPECT_NE(goodMgr->QueryBySql("SELECT 1", noArgs), nullptr);
    goodMgr->ClearCache();

    const std::string base = goodCfg.dbPath + goodCfg.dbName;
    (void)unlink(base.c_str());
    (void)unlink((base + "-wal").c_str());
    (void)unlink((base + "-shm").c_str());
    (void)unlink((base + "-journal").c_str());
}
} // namespace OHOS::Security::CertManager
