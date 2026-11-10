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
 
#include <cstring>
#include <string>
#include <vector>
 
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>
 
#include "cert_manager_check.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cm_cert_property_rdb.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "cm_type_free.h"
#include "securec.h"
 
using namespace testing::ext;
using namespace CertmanagerTest;
 
namespace {
constexpr uint32_t TEST_UID = 500;
constexpr uint32_t GLOBAL_USERID = 0;
constexpr uint32_t CERT_STORE_USER_CA = 2; /* CM_USER_TRUSTED_STORE */
constexpr enum CmAuthStorageLevel CERT_LEVEL_EL1 = CM_AUTH_STORAGE_LEVEL_EL1;
 
struct TestCertSeed {
    const char *uri;
    const char *alias;
    const char *subjectName;
    int32_t userId;
    int32_t uid;
};
 
/*
 * The FindCertificate service path builds the cert file path from USER_CA_STORE
 * and the config dir from CERT_BACKUP_CONFIG_ROOT_DIR, so the test data has to
 * land in those real directories for GetCertDataAndStatus to succeed.
 */
const std::vector<TestCertSeed> g_testSeeds = {
    { "oh:t=c;o=aaa111;u=100;a=500", "aliasAAA", "CN=AAA Test CA", 100, 500 },
    { "oh:t=c;o=bbb222;u=100;a=500", "aliasBBB", "CN=BBB Test CA", 100, 500 },
    { "oh:t=c;o=ccc333;u=0;a=0",     "aliasCCC", "CN=CCC Global CA", 0, 0 },
    { "oh:t=c;o=ddd444;u=0;a=0",     "aliasDDD", "CN=DDD Global CA", 0, 0 },
};
 
const uint8_t g_fakeCertData[] = {
    0x30, 0x82, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
};
 
std::vector<std::string> g_createdCertFiles;
std::vector<std::string> g_createdConfigFiles;
std::vector<std::string> g_createdDirs;
 
static std::string GetCertFilePath(const struct TestCertSeed &seed)
{
    return std::string(USER_CA_STORE) + std::to_string(seed.userId) + "/" +
        std::to_string(seed.uid) + "/" + seed.uri;
}
 
static std::string GetConfigFilePath(const struct TestCertSeed &seed)
{
    return std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(seed.userId) + "/" +
        std::to_string(seed.uid) + "/" + seed.uri + CERT_CONFIG_FILE_SUFFIX;
}
 
/* make the parent directory chain of a full file path (best effort) */
static void MakeParentDirs(const std::string &fullPath)
{
    std::string dir;
    for (size_t i = 0; i < fullPath.size(); ++i) {
        dir += fullPath[i];
        if (fullPath[i] == '/' && !dir.empty()) {
            int32_t ret = CmMakeDir(dir.c_str());
            if (ret == CM_SUCCESS || ret == CMR_ERROR_ALREADY_EXISTS) {
                g_createdDirs.push_back(dir);
            }
        }
    }
}
 
/* create the certificate file (required by GetCertDataAndStatus) */
static int32_t CreateCertFile(const struct TestCertSeed &seed)
{
    const std::string fullPath = GetCertFilePath(seed);
    MakeParentDirs(fullPath);
    int32_t ret = CmFileWrite(nullptr, fullPath.c_str(), 0, g_fakeCertData, sizeof(g_fakeCertData));
    if (ret == CM_SUCCESS) {
        g_createdCertFiles.push_back(fullPath);
    }
    return ret;
}
 
/* create the .config status file so the cert is reported ENABLED */
static int32_t CreateConfigFile(const struct TestCertSeed &seed)
{
    const std::string fullPath = GetConfigFilePath(seed);
    MakeParentDirs(fullPath);
    int32_t ret = CmFileWrite(nullptr, fullPath.c_str(), 0, g_fakeCertData, sizeof(g_fakeCertData));
    if (ret == CM_SUCCESS) {
        g_createdConfigFiles.push_back(fullPath);
    }
    return ret;
}
 
/* insert the cert property row into the RDB */
static int32_t InsertUserCertProperty(const struct TestCertSeed &seed)
{
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    if (strncpy_s(prop.uri, sizeof(prop.uri), seed.uri, strlen(seed.uri)) != EOK ||
        strncpy_s(prop.alias, sizeof(prop.alias), seed.alias, strlen(seed.alias)) != EOK ||
        strncpy_s(prop.subjectName, sizeof(prop.subjectName), seed.subjectName,
            strlen(seed.subjectName)) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (strncpy_s(prop.certType, sizeof(prop.certType), "c", strlen("c")) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    prop.certStore = static_cast<int32_t>(CERT_STORE_USER_CA);
    prop.userId = seed.userId;
    prop.uid = seed.uid;
    prop.level = static_cast<enum CmAuthStorageLevel>(CERT_LEVEL_EL1);
    return InsertCertProperty(&prop);
}
 
static void CleanupCreatedFiles()
{
    for (const auto &path : g_createdCertFiles) {
        (void)CmFileRemove(nullptr, path.c_str());
    }
    g_createdCertFiles.clear();
    for (const auto &path : g_createdConfigFiles) {
        (void)CmFileRemove(nullptr, path.c_str());
    }
    g_createdConfigFiles.clear();
    /* remove dirs in reverse creation order so children are gone first */
    for (auto it = g_createdDirs.rbegin(); it != g_createdDirs.rend(); ++it) {
        (void)CmDirRemove(it->c_str());
    }
    g_createdDirs.clear();
}
 
static void CleanupRdbData()
{
    for (const auto &seed : g_testSeeds) {
        (void)DeleteCertProperty(seed.uri);
    }
}
 
/*
 * Drop every user-CA row so the count-based assertions below are deterministic
 * regardless of leftovers left by other suites running earlier in the binary.
 */
static void CleanupAllUserCaRows()
{
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    condition.certType = "c";
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    if (QueryCertPropertyByCondition(&condition, &results, &count) != CM_SUCCESS) {
        return;
    }
    for (uint32_t i = 0; i < count; ++i) {
        (void)DeleteCertProperty(results[i].uri);
    }
    free(results); /* owned by the C query API, allocated with malloc */
}
 
static void SeedAllTestData()
{
    for (const auto &seed : g_testSeeds) {
        ASSERT_EQ(InsertUserCertProperty(seed), CM_SUCCESS);
        ASSERT_EQ(CreateCertFile(seed), CM_SUCCESS);
        ASSERT_EQ(CreateConfigFile(seed), CM_SUCCESS);
    }
}
 
static struct FindCertRequest MakeFindRequest(enum CmFindCertScope scope)
{
    struct FindCertRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = scope;
    return request;
}
} // namespace
 
class CmFindCertificateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
 
private:
    MockHapToken *mockHap_ = nullptr;
};
 
void CmFindCertificateTest::SetUpTestCase()
{
    CmTestCommon::SetTestEnvironment(GetSelfTokenID());
    ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
}
 
void CmFindCertificateTest::TearDownTestCase()
{
    CmTestCommon::ResetTestEnvironment();
}
 
void CmFindCertificateTest::SetUp()
{
    /* mock a HAP caller with the common cert-manager permission */
    mockHap_ = new (std::nothrow) MockHapToken();
    CleanupRdbData();
    CleanupCreatedFiles();
    CleanupAllUserCaRows();
}
 
void CmFindCertificateTest::TearDown()
{
    CleanupRdbData();
    CleanupCreatedFiles();
    if (mockHap_ != nullptr) {
        delete mockHap_;
        mockHap_ = nullptr;
    }
}
 
/* ---------- CmServiceFindCertCheck ---------- */
 
HWTEST_F(CmFindCertificateTest, FindCertCheckNullRequest, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    EXPECT_EQ(CmServiceFindCertCheck(&context, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, FindCertCheckInvalidScope, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(static_cast<enum CmFindCertScope>(99));
    EXPECT_EQ(CmServiceFindCertCheck(&context, &request), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, FindCertCheckCertTypesNullWithCount, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    request.certTypesCount = 1;
    request.certTypes = nullptr;
    EXPECT_EQ(CmServiceFindCertCheck(&context, &request), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, FindCertCheckUnsupportedCertType, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    enum CmFindCertType types[] = { static_cast<enum CmFindCertType>(7) };
    request.certTypesCount = 1;
    request.certTypes = types;
    EXPECT_EQ(CmServiceFindCertCheck(&context, &request), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, FindCertCheckValidRequest, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    enum CmFindCertType types[] = { CM_FIND_CERT_TYPE_USER_CA };
    request.certTypesCount = 1;
    request.certTypes = types;
    EXPECT_EQ(CmServiceFindCertCheck(&context, &request), CM_SUCCESS);
}
 
HWTEST_F(CmFindCertificateTest, FindCertCheckNoCommonPermission, TestSize.Level0)
{
    /* a HAP without the common cert-manager permission must be rejected */
    MockHapToken noPermHap{std::vector<std::string>()};
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    EXPECT_EQ(CmServiceFindCertCheck(&context, &request), CMR_ERROR_PERMISSION_DENIED);
}
 
/* ---------- CmServiceFindCertificate ---------- */
 
HWTEST_F(CmFindCertificateTest, FindCertificateNullArgs, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    EXPECT_EQ(CmServiceFindCertificate(nullptr, &request, &result), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateNoResultsWhenNoData, TestSize.Level0)
{
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateCurrentUserScope, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 2u);
    for (uint32_t i = 0; i < result.count; ++i) {
        EXPECT_EQ(result.certInfos[i].type, static_cast<uint32_t>(CM_FIND_CERT_TYPE_USER_CA));
        EXPECT_EQ(result.certInfos[i].state, CERT_STATUS_ENABLED);
        EXPECT_EQ(result.certInfos[i].scope, CM_FIND_CERT_SCOPE_CURRENT_USER);
        EXPECT_GT(result.certInfos[i].certData.size, 0u);
        EXPECT_NE(result.certInfos[i].certData.data, nullptr);
    }
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateGlobalScope, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_GLOBAL);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 2u);
    for (uint32_t i = 0; i < result.count; ++i) {
        EXPECT_EQ(result.certInfos[i].scope, CM_FIND_CERT_SCOPE_GLOBAL);
    }
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateCurrentAndGlobalScope, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 4u);
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateNameFilter, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    (void)strncpy_s(request.name, sizeof(request.name), "AAA", strlen("AAA"));
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    EXPECT_STREQ(result.certInfos[0].alias, "aliasAAA");
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateCertIdFilter, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    (void)strncpy_s(request.certId, sizeof(request.certId), "ccc333", strlen("ccc333"));
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    EXPECT_STREQ(result.certInfos[0].uri, "oh:t=c;o=ccc333;u=0;a=0");
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateCountLimit, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    request.countLimit = 3;
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 3u);
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateCountLimitZero, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL);
    request.countLimit = 0; /* no limit */
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 4u);
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateSkipsMissingFile, TestSize.Level0)
{
    /* only the first cert has its cert file present; the second must be skipped */
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[0]), CM_SUCCESS);
    ASSERT_EQ(CreateCertFile(g_testSeeds[0]), CM_SUCCESS);
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[1]), CM_SUCCESS);
 
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    EXPECT_STREQ(result.certInfos[0].uri, g_testSeeds[0].uri);
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateResultFields, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 2u);
    bool foundAaa = false;
    bool foundBbb = false;
    for (uint32_t i = 0; i < result.count; ++i) {
        const struct FindCertInfo &info = result.certInfos[i];
        EXPECT_EQ(info.type, static_cast<uint32_t>(CM_FIND_CERT_TYPE_USER_CA));
        EXPECT_EQ(info.state, CERT_STATUS_ENABLED);
        EXPECT_EQ(info.scope, CM_FIND_CERT_SCOPE_CURRENT_USER);
        EXPECT_EQ(info.certData.size, sizeof(g_fakeCertData));
        if (strcmp(info.alias, "aliasAAA") == 0) {
            foundAaa = true;
            EXPECT_STREQ(info.uri, "oh:t=c;o=aaa111;u=100;a=500");
            EXPECT_STREQ(info.subjectName, "CN=AAA Test CA");
        } else if (strcmp(info.alias, "aliasBBB") == 0) {
            foundBbb = true;
            EXPECT_STREQ(info.uri, "oh:t=c;o=bbb222;u=100;a=500");
            EXPECT_STREQ(info.subjectName, "CN=BBB Test CA");
        }
    }
    EXPECT_TRUE(foundAaa);
    EXPECT_TRUE(foundBbb);
    CmFreeFindCertResultInner(&result);
}
 
HWTEST_F(CmFindCertificateTest, FindCertificateFreeResult, TestSize.Level0)
{
    SeedAllTestData();
    struct CmContext context = { TEST_USERID, TEST_UID, { 0 } };
    struct FindCertRequest request = MakeFindRequest(CM_FIND_CERT_SCOPE_CURRENT_USER);
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 2u);
    CmFreeFindCertResultInner(&result);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);
 
    /* double-free / NULL result are no-ops */
    CmFreeFindCertResultInner(&result);
    CmFreeFindCertResultInner(nullptr);
}
 
/* ---------- QueryCertPropertyByCondition ---------- */
 
HWTEST_F(CmFindCertificateTest, QueryByConditionNullArgs, TestSize.Level0)
{
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    EXPECT_EQ(QueryCertPropertyByCondition(nullptr, &results, &count), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertPropertyByCondition(&condition, nullptr, &count), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(QueryCertPropertyByCondition(&condition, &results, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
 
HWTEST_F(CmFindCertificateTest, QueryByConditionUserIdList, TestSize.Level0)
{
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[0]), CM_SUCCESS);
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[2]), CM_SUCCESS);
 
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    condition.certType = "c";
    int32_t userIds[] = { static_cast<int32_t>(TEST_USERID), static_cast<int32_t>(GLOBAL_USERID) };
    condition.userIds = userIds;
    condition.userIdCount = 2;
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    ASSERT_EQ(QueryCertPropertyByCondition(&condition, &results, &count), CM_SUCCESS);
    ASSERT_EQ(count, 2u);
    EXPECT_NE(results, nullptr);
    free(results); /* owned by the C query API, allocated with malloc */
}
 
HWTEST_F(CmFindCertificateTest, QueryByConditionNameFilter, TestSize.Level0)
{
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[0]), CM_SUCCESS);
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[1]), CM_SUCCESS);
 
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    condition.certType = "c";
    condition.name = "BBB";
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    ASSERT_EQ(QueryCertPropertyByCondition(&condition, &results, &count), CM_SUCCESS);
    ASSERT_EQ(count, 1u);
    EXPECT_STREQ(results[0].alias, "aliasBBB");
    free(results);
}
 
HWTEST_F(CmFindCertificateTest, QueryByConditionCertIdFilter, TestSize.Level0)
{
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[2]), CM_SUCCESS);
 
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    condition.certType = "c";
    condition.certId = "ccc333";
    struct CertProperty *results = nullptr;
    uint32_t count = 0;
    ASSERT_EQ(QueryCertPropertyByCondition(&condition, &results, &count), CM_SUCCESS);
    ASSERT_EQ(count, 1u);
    EXPECT_STREQ(results[0].uri, "oh:t=c;o=ccc333;u=0;a=0");
    free(results);
}
 
HWTEST_F(CmFindCertificateTest, QueryByConditionNoMatch, TestSize.Level0)
{
    ASSERT_EQ(InsertUserCertProperty(g_testSeeds[0]), CM_SUCCESS);
 
    struct CmFindCertCondition condition;
    (void)memset_s(&condition, sizeof(condition), 0, sizeof(condition));
    condition.certType = "c";
    condition.name = "NoSuchName";
    struct CertProperty *results = nullptr;
    uint32_t count = 1; /* must be reset to 0 by the query */
    ASSERT_EQ(QueryCertPropertyByCondition(&condition, &results, &count), CM_SUCCESS);
    EXPECT_EQ(count, 0u);
    EXPECT_EQ(results, nullptr);
    free(results);
}
