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

#include <cstdio>
#include <cstring>
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <openssl/x509.h>

#include "cert_manager_file.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_user.h"
#include "cm_cert_property_rdb.h"
#include "cm_config_rdb.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_SERVICE_USER = 8899;
constexpr uint32_t TEST_SERVICE_UID = 889901;
constexpr uint32_t TEST_SERVICE_OTHER_UID = 889902;
constexpr int NFTW_MAX_OPEN_FDS = 16;
constexpr uint32_t MULTI_CERT_MAX_COUNT = 16;

/* roots owned by the SA that are created here only when missing */
const std::vector<std::string> NEEDED_ROOTS = {
    USER_CA_STORE,
    CERT_BACKUP_CONFIG_ROOT_DIR,
    CERT_BACKUP_ROOT_DIR,
    CREDNTIAL_STORE,
    SYS_CREDNTIAL_STORE,
    "/data/service/el1/public/cert_manager_service/rdb",
};
std::vector<std::string> g_createdRoots;

/* the global user store dir (user_ca/0) may be created by the GLOBAL scope cases */
const std::string GLOBAL_USER_DIR = std::string(USER_CA_STORE) + "0";
bool g_globalUserDirCreated = false;

std::vector<std::string> g_installedUris; /* RDB rows created through the install entry points */

/* isolated user subtrees touched by the cases below */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER),
        std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_SERVICE_USER),
        std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_SERVICE_USER),
        std::string(CREDNTIAL_STORE) + std::to_string(TEST_SERVICE_USER),
        std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_SERVICE_USER),
    };
}

int RemoveTreeEntry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return (type == FTW_DP) ? rmdir(path) : remove(path);
}

void RemoveTree(const std::string &root)
{
    if (root.empty()) {
        return;
    }
    (void)nftw(root.c_str(), RemoveTreeEntry, NFTW_MAX_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

void MakeDirOrExists(const std::string &path)
{
    int32_t ret = CmMakeDir(path.c_str());
    ASSERT_TRUE(ret == CMR_OK || ret == CMR_ERROR_ALREADY_EXISTS) << "mkdir failed for " << path;
}

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}

void TrackInstalledUri(const struct CmBlob *certUri)
{
    if (certUri != nullptr && certUri->data != nullptr) {
        g_installedUris.emplace_back(reinterpret_cast<char *>(certUri->data));
    }
}

void DeleteInstalledRdbRowsQuietly()
{
    for (const auto &uri : g_installedUris) {
        (void)DeleteCertProperty(uri.c_str());
    }
    g_installedUris.clear();
}

void FreeFindCertResult(struct FindCertResult *result)
{
    if (result == nullptr || result->certInfos == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < result->count; i++) {
        CMFree(result->certInfos[i].certData.data);
        result->certInfos[i].certData.data = nullptr;
        result->certInfos[i].certData.size = 0;
    }
    CMFree(result->certInfos);
    result->certInfos = nullptr;
    result->count = 0;
}

void FreeCertManagerConfig(struct CertManagerConfig *config)
{
    if (config == nullptr || config->configItems == nullptr) {
        return;
    }
    CMFree(config->configItems);
    config->configItems = nullptr;
    config->count = 0;
}

/* install one user CA cert through the engine entry point with an explicit alias */
int32_t InstallUserCertWithAlias(const std::string &alias, std::string &outUri)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmBlob userCert = { strlen(g_certData06), reinterpret_cast<uint8_t *>(g_certData06) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri);
    if (ret == CM_SUCCESS) {
        outUri = std::string(reinterpret_cast<char *>(uriBuf));
        g_installedUris.emplace_back(outUri);
    }
    return ret;
}

/* number of certificates inside the P7B test data */
int32_t CountP7bCerts(void)
{
    STACK_OF(X509) *stack = InitCertStackContext(g_p7bUserCert.data, g_p7bUserCert.size);
    if (stack == nullptr) {
        return -1;
    }
    int32_t count = sk_X509_num(stack);
    sk_X509_pop_free(stack, X509_free);
    return count;
}
} // namespace

class CmEngineServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        CmTestCommon::SetTestEnvironment(GetSelfTokenID());
        if (CmIsDirExist(CERT_DIR) != CMR_OK) {
            (void)CmMakeDir(CERT_DIR);
            g_createdRoots.emplace_back(CERT_DIR);
        }
        for (const auto &root : NEEDED_ROOTS) {
            if (CmIsDirExist(root.c_str()) != CMR_OK) {
                (void)CmMakeDir(root.c_str());
                g_createdRoots.emplace_back(root);
            }
        }
        if (CmIsDirExist(GLOBAL_USER_DIR.c_str()) != CMR_OK) {
            g_globalUserDirCreated = true; /* created lazily below by the scope cases */
        }
        /* the service entry points consult both rdb tables */
        ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
        ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
        if (g_globalUserDirCreated) {
            (void)rmdir(GLOBAL_USER_DIR.c_str()); /* best effort: only succeeds when empty */
        }
        for (const auto &root : g_createdRoots) {
            (void)rmdir(root.c_str());
        }
        g_createdRoots.clear();
    }

    void SetUp() {}

    void TearDown()
    {
        for (const auto &subtree : UserSubtrees()) {
            RemoveTree(subtree);
        }
        DeleteInstalledRdbRowsQuietly();
    }
};

/**
 * @tc.name: CmServiceGetAppCertInvalidUri_001
 * @tc.desc: get app cert rejects undecodable uris and wrong uri types before storage access.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAppCertInvalidUri_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };

    uint8_t garbage[] = "garbage";
    struct CmBlob badUri = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &badUri, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* uri type 'c' is not valid for the credential store */
    uint8_t typeUri[] = "oh:t=c;o=alias;u=8899;a=889901";
    struct CmBlob wrongType = { sizeof(typeUri) - 1, typeUri };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &wrongType, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmServiceGetAppCertInvalidStore_001
 * @tc.desc: get app cert rejects stores which are not credential stores.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAppCertInvalidStore_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    uint8_t uriBuf[] = "oh:t=ak;o=alias;u=8899;a=889901";
    struct CmBlob keyUri = { sizeof(uriBuf) - 1, uriBuf };

    EXPECT_EQ(CmServiceGetAppCert(&context, CM_USER_TRUSTED_STORE, &keyUri, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE + 10, &keyUri, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmServiceGetAppCertCredential_001
 * @tc.desc: get app cert for the public credential store: miss, hit and non producer rejection.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAppCertCredential_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    const std::string uidDir = std::string(CREDNTIAL_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);

    uint8_t uriBuf[] = "oh:t=ak;o=enginecred;u=8899;a=889901";
    struct CmBlob keyUri = { sizeof(uriBuf) - 1, uriBuf };
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };

    /* producer uri but no credential file */
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &keyUri, &certBlob), CMR_ERROR_NOT_EXIST);

    /* place the credential file and read it back */
    const uint8_t credData[] = "FAKE_CREDENTIAL_FOR_ENGINE_UT";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), reinterpret_cast<char *>(uriBuf), 0, const_cast<uint8_t *>(credData),
        sizeof(credData) - 1), CMR_OK);
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &keyUri, &certBlob), CM_SUCCESS);
    EXPECT_EQ(certBlob.size, sizeof(credData) - 1);
    EXPECT_EQ(memcmp(certBlob.data, credData, sizeof(credData) - 1), 0);
    CMFree(certBlob.data);
    certBlob.data = nullptr;

    /* uri owned by another uid and no client app: the caller is neither producer nor grantee */
    uint8_t otherUri[] = "oh:t=ak;o=othercred;u=8899;a=889902";
    struct CmBlob other = { sizeof(otherUri) - 1, otherUri };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &other, &certBlob),
        CMR_ERROR_NOT_PERMITTED);
}

/**
 * @tc.name: CmServiceGetAppCertPrivate_001
 * @tc.desc: get app cert for the private credential store: producer path and permission rejection.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAppCertPrivate_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t uriBuf[] = "oh:t=ak;o=enginepri;u=8899;a=889901";
    struct CmBlob keyUri = { sizeof(uriBuf) - 1, uriBuf };
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };

    /* producer uri, no credential file stored */
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &keyUri, &certBlob), CMR_ERROR_NOT_EXIST);

    /* non producer uri without any token: privileged permission is missing */
    uint8_t otherUri[] = "oh:t=ak;o=otherpri;u=8899;a=889902";
    struct CmBlob other = { sizeof(otherUri) - 1, otherUri };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &other, &certBlob),
        CMR_ERROR_PERMISSION_DENIED);

    /* the same call succeeds the permission check with the mock hap token and fails on storage */
    MockHapToken mockHap;
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &other, &certBlob), CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmServiceGetAppCertSystem_001
 * @tc.desc: get app cert for the system credential store: direct storage access without permission.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAppCertSystem_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    const std::string uidDir = std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);

    uint8_t uriBuf[] = "oh:t=sk;o=enginesys;u=8899;a=889901";
    struct CmBlob keyUri = { sizeof(uriBuf) - 1, uriBuf };
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };

    EXPECT_EQ(CmServiceGetAppCert(&context, CM_SYS_CREDENTIAL_STORE, &keyUri, &certBlob), CMR_ERROR_NOT_EXIST);

    const uint8_t credData[] = "FAKE_SYS_CREDENTIAL_FOR_UT";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), reinterpret_cast<char *>(uriBuf), 0, const_cast<uint8_t *>(credData),
        sizeof(credData) - 1), CMR_OK);
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_SYS_CREDENTIAL_STORE, &keyUri, &certBlob), CM_SUCCESS);
    EXPECT_EQ(certBlob.size, sizeof(credData) - 1);
    EXPECT_EQ(memcmp(certBlob.data, credData, sizeof(credData) - 1), 0);
    CMFree(certBlob.data);
    certBlob.data = nullptr;

    /* wrong uri type for the system credential store */
    uint8_t akUri[] = "oh:t=ak;o=wrongtype;u=8899;a=889901";
    struct CmBlob wrongType = { sizeof(akUri) - 1, akUri };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_SYS_CREDENTIAL_STORE, &wrongType, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmServiceInitInvalidArgs_001
 * @tc.desc: init rejects invalid uri/handle and callers without common permission.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceInitInvalidArgs_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t handleBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob handle = { sizeof(handleBuf), handleBuf };
    struct CmSignatureSpec spec;
    (void)memset_s(&spec, sizeof(spec), 0, sizeof(spec));

    uint8_t garbage[] = "garbage";
    struct CmBlob badUri = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmServiceInit(&context, &badUri, &spec, &handle), CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t uriBuf[] = "oh:t=ak;o=enginecred;u=8899;a=889901";
    struct CmBlob keyUri = { sizeof(uriBuf) - 1, uriBuf };
    struct CmBlob badHandle = { 0, nullptr };
    EXPECT_EQ(CmServiceInit(&context, &keyUri, &spec, &badHandle), CMR_ERROR_INVALID_ARGUMENT_HANDLE);

    /* caller without common permission */
    EXPECT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CMR_ERROR_PERMISSION_DENIED);

    /* system key uri without permission on the system app cert */
    uint8_t skUri[] = "oh:t=sk;o=enginesys;u=8899;a=889901";
    struct CmBlob sysUri = { sizeof(skUri) - 1, skUri };
    EXPECT_EQ(CmServiceInit(&context, &sysUri, &spec, &handle), CMR_ERROR_PERMISSION_DENIED);

    /* with the mock hap token the flow proceeds up to the HUKS key operation */
    MockHapToken mockHap;
    int32_t ret = CmServiceInit(&context, &keyUri, &spec, &handle);
    EXPECT_NE(ret, CM_SUCCESS); /* the referenced key does not exist in HUKS */
}

/**
 * @tc.name: CmServiceInitSysKeyUserId_001
 * @tc.desc: init validates the caller user id against the system key uri.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceInitSysKeyUserId_001, TestSize.Level0)
{
    uint8_t handleBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob handle = { sizeof(handleBuf), handleBuf };
    struct CmSignatureSpec spec;
    (void)memset_s(&spec, sizeof(spec), 0, sizeof(spec));

    /* hap caller (userId != 0) referencing a foreign user id in the uri */
    {
        MockHapToken mockHap; /* full permission set: reaches the sk uri user id check */
        struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
        uint8_t skUri[] = "oh:t=sk;o=enginesys;u=100;a=889901";
        struct CmBlob sysUri = { sizeof(skUri) - 1, skUri };
        EXPECT_EQ(CmServiceInit(&context, &sysUri, &spec, &handle), CMR_ERROR_INVALID_ARGUMENT_USER_ID);
    }

    /* caller without the common permission is rejected before the uri is resolved */
    {
        MockHapToken mockNoPerm(std::vector<std::string>{});
        struct CmContext saContext = BuildContext(0, 0);
        uint8_t skUri2[] = "oh:t=sk;o=enginesys;u=0;a=0";
        struct CmBlob sysUri2 = { sizeof(skUri2) - 1, skUri2 };
        EXPECT_EQ(CmServiceInit(&saContext, &sysUri2, &spec, &handle), CMR_ERROR_PERMISSION_DENIED);
    }
}

/**
 * @tc.name: CmServiceUpdateFinishAbort_001
 * @tc.desc: update/finish/abort validate blobs, permissions and unknown session handles.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceUpdateFinishAbort_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t handleBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob handle = { sizeof(handleBuf), handleBuf };
    uint8_t dataBuf[] = "payload";
    struct CmBlob inData = { sizeof(dataBuf) - 1, dataBuf };
    uint8_t outBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob outData = { sizeof(outBuf), outBuf };

    struct CmBlob badHandle = { 0, nullptr };
    EXPECT_EQ(CmServiceUpdate(&context, &badHandle, &inData), CMR_ERROR_INVALID_ARGUMENT_HANDLE);
    EXPECT_EQ(CmServiceFinish(&context, &badHandle, &inData, &outData), CMR_ERROR_INVALID_ARGUMENT_HANDLE);
    EXPECT_EQ(CmServiceAbort(&context, &badHandle), CMR_ERROR_INVALID_ARGUMENT_HANDLE);

    struct CmBlob badData = { 0, nullptr };
    EXPECT_EQ(CmServiceUpdate(&context, &handle, &badData), CMR_ERROR_INVALID_ARGUMENT);

    /* caller without common permission */
    EXPECT_EQ(CmServiceUpdate(&context, &handle, &inData), CMR_ERROR_PERMISSION_DENIED);
    EXPECT_EQ(CmServiceFinish(&context, &handle, &inData, &outData), CMR_ERROR_PERMISSION_DENIED);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CMR_ERROR_PERMISSION_DENIED);

    /* unknown session handle: update/finish fail, abort is idempotent */
    MockHapToken mockHap;
    EXPECT_EQ(CmServiceUpdate(&context, &handle, &inData), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(CmServiceFinish(&context, &handle, &inData, &outData), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CM_SUCCESS);
}

/**
 * @tc.name: CmServiceGetCertListInvalidParams_001
 * @tc.desc: get cert list validates scope, store and the target user id for hap callers.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertListInvalidParams_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmMutableBlob certFileList = { 0, nullptr };

    struct UserCAProperty badScope = { INIT_INVALID_VALUE, static_cast<enum CmCertScope>(99) };
    EXPECT_EQ(CmServiceGetCertList(&context, &badScope, CM_USER_TRUSTED_STORE, &certFileList),
        CMR_ERROR_INVALID_ARGUMENT_SCOPE);

    struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_CURRENT_USER };
    EXPECT_EQ(CmServiceGetCertList(&context, &prop, CM_CREDENTIAL_STORE, &certFileList),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* hap callers may not query an explicit target user id */
    struct UserCAProperty targetUser = { 100, CM_CURRENT_USER };
    EXPECT_EQ(CmServiceGetCertList(&context, &targetUser, CM_USER_TRUSTED_STORE, &certFileList),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);
    EXPECT_EQ(certFileList.data, nullptr);
}

/**
 * @tc.name: CmServiceGetCertListCurrentUser_001
 * @tc.desc: get cert list returns exactly the certificates of the caller's user store.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertListCurrentUser_001, TestSize.Level0)
{
    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);
    const uint8_t *certData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "oh:t=c;o=listone;u=8899;a=889901", 0,
        const_cast<uint8_t *>(certData), strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "oh:t=c;o=listtwo;u=8899;a=889901", 0,
        const_cast<uint8_t *>(certData), strlen(g_certData06)), CMR_OK);

    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_CURRENT_USER };
    struct CmMutableBlob certFileList = { 0, nullptr };
    ASSERT_EQ(CmServiceGetCertList(&context, &prop, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    ASSERT_EQ(certFileList.size, 2u);

    struct CertFileInfo *cFileList = reinterpret_cast<struct CertFileInfo *>(certFileList.data);
    bool seenOne = false;
    bool seenTwo = false;
    for (uint32_t i = 0; i < certFileList.size; i++) {
        const std::string name(reinterpret_cast<char *>(cFileList[i].fileName.data));
        const std::string path(reinterpret_cast<char *>(cFileList[i].path.data));
        seenOne = seenOne || (name == "oh:t=c;o=listone;u=8899;a=889901");
        seenTwo = seenTwo || (name == "oh:t=c;o=listtwo;u=8899;a=889901");
        EXPECT_NE(path.find(uidDir), std::string::npos);
    }
    EXPECT_TRUE(seenOne);
    EXPECT_TRUE(seenTwo);
    CmFreeCertFiles(cFileList, certFileList.size);
}

/**
 * @tc.name: CmServiceGetCertListScopes_001
 * @tc.desc: get cert list covers global, all user and system scopes for hap and sa callers.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertListScopes_001, TestSize.Level0)
{
    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);
    const uint8_t *certData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "oh:t=c;o=scopeone;u=8899;a=889901", 0,
        const_cast<uint8_t *>(certData), strlen(g_certData06)), CMR_OK);

    struct CmContext hapContext = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmMutableBlob certFileList = { 0, nullptr };

    /* empty store for the current user */
    struct UserCAProperty currentProp = { INIT_INVALID_VALUE, CM_CURRENT_USER };
    RemoveTree(std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER));
    ASSERT_EQ(CmServiceGetCertList(&hapContext, &currentProp, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    EXPECT_EQ(certFileList.size, 0u);
    EXPECT_EQ(certFileList.data, nullptr);

    /* re-create the caller certificate for the scope queries below */
    MakeDirOrExists(uidDir);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "oh:t=c;o=scopeone;u=8899;a=889901", 0,
        const_cast<uint8_t *>(certData), strlen(g_certData06)), CMR_OK);

    /* global scope resolves to the user id 0 store */
    struct UserCAProperty globalProp = { INIT_INVALID_VALUE, CM_GLOBAL_USER };
    ASSERT_EQ(CmServiceGetCertList(&hapContext, &globalProp, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    CmFreeCertFiles(reinterpret_cast<struct CertFileInfo *>(certFileList.data), certFileList.size);
}

/**
 * @tc.name: CmServiceGetCertListScopes_002
 * @tc.desc: get cert list merges all user, target user and system scopes for hap and sa callers.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertListScopes_002, TestSize.Level0)
{
    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);
    const uint8_t *certData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "oh:t=c;o=scopeone;u=8899;a=889901", 0,
        const_cast<uint8_t *>(certData), strlen(g_certData06)), CMR_OK);

    struct CmContext hapContext = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmContext saContext = BuildContext(0, 0);
    struct CmMutableBlob certFileList = { 0, nullptr };

    /* all user scope merges the caller store with the global store */
    struct UserCAProperty allProp = { INIT_INVALID_VALUE, CM_ALL_USER };
    ASSERT_EQ(CmServiceGetCertList(&hapContext, &allProp, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    ASSERT_NE(certFileList.data, nullptr);
    struct CertFileInfo *cFileList = reinterpret_cast<struct CertFileInfo *>(certFileList.data);
    bool seenMine = false;
    for (uint32_t i = 0; i < certFileList.size; i++) {
        seenMine = seenMine ||
            (strcmp(reinterpret_cast<char *>(cFileList[i].fileName.data), "oh:t=c;o=scopeone;u=8899;a=889901") == 0);
    }
    EXPECT_TRUE(seenMine);
    CmFreeCertFiles(cFileList, certFileList.size);
    certFileList = { 0, nullptr };

    /* sa caller with an explicit target user id merges the global store with the target store */
    struct UserCAProperty targetProp = { TEST_SERVICE_USER, CM_ALL_USER };
    ASSERT_EQ(CmServiceGetCertList(&saContext, &targetProp, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    ASSERT_NE(certFileList.data, nullptr);
    cFileList = reinterpret_cast<struct CertFileInfo *>(certFileList.data);
    seenMine = false;
    for (uint32_t i = 0; i < certFileList.size; i++) {
        seenMine = seenMine ||
            (strcmp(reinterpret_cast<char *>(cFileList[i].fileName.data), "oh:t=c;o=scopeone;u=8899;a=889901") == 0);
    }
    EXPECT_TRUE(seenMine);
    CmFreeCertFiles(cFileList, certFileList.size);
    certFileList = { 0, nullptr };

    /* sa caller with an invalid target user id falls back to the global store */
    struct UserCAProperty invalidProp = { INIT_INVALID_VALUE, CM_ALL_USER };
    ASSERT_EQ(CmServiceGetCertList(&saContext, &invalidProp, CM_USER_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    CmFreeCertFiles(reinterpret_cast<struct CertFileInfo *>(certFileList.data), certFileList.size);
    certFileList = { 0, nullptr };

    /* system store */
    ASSERT_EQ(CmServiceGetCertList(&hapContext, &allProp, CM_SYSTEM_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    CmFreeCertFiles(reinterpret_cast<struct CertFileInfo *>(certFileList.data), certFileList.size);
}

/**
 * @tc.name: CmServiceGetCertInfoUserStore_001
 * @tc.desc: get cert info for the user CA store returns the stored data and the config status.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertInfoUserStore_001, TestSize.Level0)
{
    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    MakeDirOrExists(uidDir);
    const uint8_t *certData = reinterpret_cast<const uint8_t *>(g_certData06);
    const char *uri = "oh:t=c;o=infocert;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri, 0, const_cast<uint8_t *>(certData), strlen(g_certData06)),
        CMR_OK);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    uint8_t certBuf[MAX_LEN_CERTIFICATE] = { 0 };
    struct CmBlob certificateData = { sizeof(certBuf), certBuf };
    uint32_t status = CERT_STATUS_ENABLED;

    /* without a config file the certificate is disabled */
    struct CmContext ctx1 = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    ASSERT_EQ(CmServiceGetCertInfo(&ctx1, &certUri, CM_USER_TRUSTED_STORE, &certificateData, &status), CM_SUCCESS);
    EXPECT_EQ(certificateData.size, strlen(g_certData06));
    EXPECT_EQ(memcmp(certificateData.data, certData, strlen(g_certData06)), 0);
    EXPECT_EQ(status, CERT_STATUS_DISABLED);
    CMFree(certificateData.data);
    certificateData.data = nullptr;
    certificateData.size = 0;

    /* with a config file the certificate is enabled */
    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_SERVICE_USER, TEST_SERVICE_UID, confUidDir, sizeof(confUidDir)),
        CM_SUCCESS);
    const std::string confFile = std::string(confUidDir) + "/" + uri + CERT_CONFIG_FILE_SUFFIX;
    const uint8_t flag[] = "1";
    ASSERT_EQ(CmFileWrite(nullptr, confFile.c_str(), 0, const_cast<uint8_t *>(flag), sizeof(flag) - 1), CMR_OK);

    struct CmContext ctx2 = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    ASSERT_EQ(CmServiceGetCertInfo(&ctx2, &certUri, CM_USER_TRUSTED_STORE, &certificateData, &status), CM_SUCCESS);
    EXPECT_EQ(status, CERT_STATUS_ENABLED);
    CMFree(certificateData.data);
    certificateData.data = nullptr;
    certificateData.size = 0;

    /* missing certificate file */
    const char *missingUri = "oh:t=c;o=missing;u=8899;a=889901";
    uint8_t missBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(missBuf), sizeof(missBuf), missingUri), EOK);
    struct CmBlob missing = { sizeof(missBuf), missBuf };
    struct CmContext ctx3 = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    EXPECT_EQ(CmServiceGetCertInfo(&ctx3, &missing, CM_USER_TRUSTED_STORE, &certificateData, &status),
        CMR_ERROR_NOT_EXIST);

    /* uri referencing another user id */
    const char *otherUserUri = "oh:t=c;o=infocert;u=100;a=889901";
    uint8_t otherBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(otherBuf), sizeof(otherBuf), otherUserUri), EOK);
    struct CmBlob otherUser = { sizeof(otherBuf), otherBuf };
    struct CmContext ctx4 = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    EXPECT_EQ(CmServiceGetCertInfo(&ctx4, &otherUser, CM_USER_TRUSTED_STORE, &certificateData, &status),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);
}

/**
 * @tc.name: CmServiceGetCertInfoParams_001
 * @tc.desc: get cert info validates uri and store and rejects unknown system certificates.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertInfoParams_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t certBuf[MAX_LEN_CERTIFICATE] = { 0 };
    struct CmBlob certificateData = { sizeof(certBuf), certBuf };
    uint32_t status = CERT_STATUS_ENABLED;

    uint8_t garbage[] = "garbage";
    struct CmBlob badUri = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmServiceGetCertInfo(&context, &badUri, CM_USER_TRUSTED_STORE, &certificateData, &status),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), "oh:t=c;o=alias;u=8899;a=889901"), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmServiceGetCertInfo(&context, &certUri, CM_CREDENTIAL_STORE, &certificateData, &status),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* unknown system certificate */
    uint8_t sysBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(sysBuf), sizeof(sysBuf), "0123abcd.0"), EOK);
    struct CmBlob sysUri = { sizeof(sysBuf), sysBuf };
    EXPECT_EQ(CmServiceGetCertInfo(&context, &sysUri, CM_SYSTEM_TRUSTED_STORE, &certificateData, &status),
        CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmServiceGetCertInfoSystemHit_001
 * @tc.desc: get cert info returns the preset system certificate content and enabled status.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetCertInfoSystemHit_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(0, 0);
    struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
    struct CmMutableBlob certFileList = { 0, nullptr };
    ASSERT_EQ(CmServiceGetCertList(&context, &prop, CM_SYSTEM_TRUSTED_STORE, &certFileList), CM_SUCCESS);
    if (certFileList.size == 0) {
        GTEST_SKIP() << "no preset system certificates on this image";
    }

    struct CertFileInfo *cFileList = reinterpret_cast<struct CertFileInfo *>(certFileList.data);
    /* copy the first system certificate file name as the requested uri */
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(memcpy_s(uriBuf, sizeof(uriBuf), cFileList[0].fileName.data, cFileList[0].fileName.size), EOK);
    struct CmBlob certUri = { cFileList[0].fileName.size, uriBuf };
    uint8_t certBuf[MAX_LEN_CERTIFICATE] = { 0 };
    struct CmBlob certificateData = { sizeof(certBuf), certBuf };
    uint32_t status = CERT_STATUS_DISABLED;

    ASSERT_EQ(CmServiceGetCertInfo(&context, &certUri, CM_SYSTEM_TRUSTED_STORE, &certificateData, &status),
        CM_SUCCESS);
    EXPECT_EQ(status, CERT_STATUS_ENABLED);
    EXPECT_GT(certificateData.size, 0u);
    CMFree(certificateData.data);
    certificateData.data = nullptr;

    CmFreeCertFiles(cFileList, certFileList.size);
}

/**
 * @tc.name: CmX509ToPEM_001
 * @tc.desc: X509 to PEM conversion rejects null arguments and converts the DER test certificate.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmX509ToPEM_001, TestSize.Level0)
{
    struct CmBlob pemBlob = { 0, nullptr };
    EXPECT_EQ(CmX509ToPEM(nullptr, &pemBlob), CMR_ERROR_OPENSSL_FAIL);
    EXPECT_EQ(CmX509ToPEM(nullptr, nullptr), CMR_ERROR_OPENSSL_FAIL);

    const unsigned char *data = g_certData01;
    X509 *cert = d2i_X509(nullptr, &data, sizeof(g_certData01));
    ASSERT_NE(cert, nullptr);
    ASSERT_EQ(CmX509ToPEM(cert, &pemBlob), CM_SUCCESS);
    EXPECT_GT(pemBlob.size, 0u);
    EXPECT_EQ(memcmp(pemBlob.data, "-----BEGIN CERTIFICATE-----",
        strlen("-----BEGIN CERTIFICATE-----")), 0);
    CMFree(pemBlob.data);
    X509_free(cert);
}

/**
 * @tc.name: CmInstallUserCertWithAlias_001
 * @tc.desc: install a user CA cert with an explicit alias persists file, RDB row and backup.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmInstallUserCertWithAlias_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmBlob userCert = { strlen(g_certData06), reinterpret_cast<uint8_t *>(g_certData06) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineAlias"), EOK);
    struct CmBlob certAlias = { sizeof("EngineAlias"), aliasBuf };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    ASSERT_EQ(CmInstallUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri), CM_SUCCESS);
    TrackInstalledUri(&certUri);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(uriBuf), "oh:t=c;o=EngineAlias;u=8899;a=889901"), 0);

    /* the certificate file, the RDB row and the backup config exist after the install */
    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);

    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(reinterpret_cast<char *>(uriBuf), &prop), CM_SUCCESS);
    EXPECT_EQ(strcmp(prop.alias, "EngineAlias"), 0);
    EXPECT_EQ(strcmp(prop.uri, reinterpret_cast<char *>(uriBuf)), 0);
    EXPECT_EQ(prop.certStore, static_cast<int32_t>(CM_USER_TRUSTED_STORE));

    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_SERVICE_USER, TEST_SERVICE_UID, confUidDir, sizeof(confUidDir)),
        CM_SUCCESS);
    const std::string confFile = std::string(confUidDir) + "/" + reinterpret_cast<char *>(uriBuf) + CERT_CONFIG_FILE_SUFFIX;
    EXPECT_EQ(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);

    /* reinstall with the same alias is idempotent (file and row are replaced) */
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri2 = { sizeof(uriBuf2), uriBuf2 };
    ASSERT_EQ(CmInstallUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri2), CM_SUCCESS);
    TrackInstalledUri(&certUri2);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(uriBuf2), reinterpret_cast<char *>(uriBuf)), 0);
}

/**
 * @tc.name: CmInstallUserCertEmptyAlias_001
 * @tc.desc: install with an empty alias derives the object name from the certificate hash.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmInstallUserCertEmptyAlias_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmBlob userCert = { strlen(g_certData06), reinterpret_cast<uint8_t *>(g_certData06) };
    uint8_t emptyAlias[] = "";
    struct CmBlob certAlias = { sizeof(emptyAlias), emptyAlias };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    ASSERT_EQ(CmInstallUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri), CM_SUCCESS);
    TrackInstalledUri(&certUri);
    /* the uri object is the base64url sha256 of the certificate, not the empty alias */
    const std::string firstUri(reinterpret_cast<char *>(uriBuf));
    EXPECT_EQ(firstUri.find("o=;"), std::string::npos);
    EXPECT_EQ(firstUri.rfind("oh:t=c;o=", 0), 0u);

    /* installing the very same certificate again takes the duplicate update path */
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri2 = { sizeof(uriBuf2), uriBuf2 };
    ASSERT_EQ(CmInstallUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri2), CM_SUCCESS);
    TrackInstalledUri(&certUri2);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(uriBuf2), reinterpret_cast<char *>(uriBuf)), 0);

    /* a different certificate gets its own object name */
    struct CmBlob otherCert = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    uint8_t uriBuf3[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri3 = { sizeof(uriBuf3), uriBuf3 };
    ASSERT_EQ(CmInstallUserCert(&context, &otherCert, &certAlias, CERT_STATUS_ENABLED, &certUri3), CM_SUCCESS);
    TrackInstalledUri(&certUri3);
    EXPECT_STRNE(reinterpret_cast<char *>(uriBuf3), reinterpret_cast<char *>(uriBuf));

    /* invalid certificate data is rejected before any storage access */
    uint8_t garbage[] = "garbage";
    struct CmBlob badCert = { sizeof(garbage) - 1, garbage };
    uint8_t uriBuf4[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri4 = { sizeof(uriBuf4), uriBuf4 };
    EXPECT_EQ(CmInstallUserCert(&context, &badCert, &certAlias, CERT_STATUS_ENABLED, &certUri4),
        CMR_ERROR_INVALID_CERT_FORMAT);
}

/**
 * @tc.name: CmUninstallUserCert_001
 * @tc.desc: uninstall removes the certificate file, RDB row, config and backup and stays idempotent.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmUninstallUserCert_001, TestSize.Level0)
{
    std::string installedUri;
    ASSERT_EQ(InstallUserCertWithAlias("UninstallAlias", installedUri), CM_SUCCESS);

    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), installedUri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    ASSERT_EQ(CmUninstallUserCert(&context, &certUri), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);

    /* the RDB row is gone */
    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&certUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);

    /* uninstalling again is idempotent */
    ASSERT_EQ(CmUninstallUserCert(&context, &certUri), CM_SUCCESS);

    /* caller identity must match the uri */
    struct CmContext otherContext = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_OTHER_UID);
    EXPECT_EQ(CmUninstallUserCert(&otherContext, &certUri), CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t garbage[] = "garbage";
    struct CmBlob badUri = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmUninstallUserCert(&context, &badUri), CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmUninstallAllUserCert_001
 * @tc.desc: uninstall all removes every certificate, uid directory and config directory of the user.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmUninstallAllUserCert_001, TestSize.Level0)
{
    std::string firstUri;
    std::string secondUri;
    ASSERT_EQ(InstallUserCertWithAlias("AllRemoveOne", firstUri), CM_SUCCESS);
    ASSERT_EQ(InstallUserCertWithAlias("AllRemoveTwo", secondUri), CM_SUCCESS);

    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    ASSERT_EQ(CmUninstallAllUserCert(&context), CM_SUCCESS);

    const std::string uidDir = std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER) + "/" +
        std::to_string(TEST_SERVICE_UID);
    EXPECT_NE(CmIsDirExist(uidDir.c_str()), CMR_OK);
    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    uint32_t uid = TEST_SERVICE_UID;
    (void)CmGetCertConfUidDir(TEST_SERVICE_USER, uid, confUidDir, sizeof(confUidDir));
    EXPECT_NE(CmIsDirExist(confUidDir), CMR_OK);

    /* both RDB rows are gone */
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), firstUri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&certUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);

    /* an empty store is a successful no-op */
    RemoveTree(std::string(USER_CA_STORE) + std::to_string(TEST_SERVICE_USER));
    ASSERT_EQ(CmUninstallAllUserCert(&context), CM_SUCCESS);
}

/**
 * @tc.name: CmInstallMultiUserCert_001
 * @tc.desc: multi certificate install validates arguments, buffer capacity and installs P7B chains.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmInstallMultiUserCert_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmBlob userCert = g_p7bUserCert;
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "MultiAlias"), EOK);
    struct CmBlob certAlias = { sizeof("MultiAlias"), aliasBuf };

    const uint32_t outSize = sizeof(uint32_t) + MULTI_CERT_MAX_COUNT * MAX_LEN_URI;
    std::vector<uint8_t> outData(outSize, 0);
    struct CmBlob certUri = { outSize, outData.data() };

    /* argument validation */
    EXPECT_EQ(CmInstallMultiUserCert(nullptr, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmInstallMultiUserCert(&context, nullptr, &certAlias, CERT_STATUS_ENABLED, &certUri),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmInstallMultiUserCert(&context, &userCert, nullptr, CERT_STATUS_ENABLED, &certUri),
        CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob noData = { outSize, nullptr };
    EXPECT_EQ(CmInstallMultiUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &noData),
        CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob tiny = { sizeof(uint32_t), outData.data() };
    EXPECT_EQ(CmInstallMultiUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &tiny),
        CMR_ERROR_INVALID_ARGUMENT);

    /* not a P7B chain */
    uint8_t garbage[] = "garbage";
    struct CmBlob badCert = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmInstallMultiUserCert(&context, &badCert, &certAlias, CERT_STATUS_ENABLED, &certUri),
        CMR_ERROR_INVALID_CERT_FORMAT);

    int32_t p7bCount = CountP7bCerts();
    ASSERT_GT(p7bCount, 0);

    /* buffer too small for the whole chain: capacity of a single uri slot */
    if (p7bCount > 1) {
        struct CmBlob small = { sizeof(uint32_t) + MAX_LEN_URI, outData.data() };
        EXPECT_EQ(CmInstallMultiUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &small),
            CMR_ERROR_MAX_CERT_COUNT_REACHED);
    }

    /* full install: each certificate of the chain is installed under the same alias */
    ASSERT_EQ(CmInstallMultiUserCert(&context, &userCert, &certAlias, CERT_STATUS_ENABLED, &certUri), CM_SUCCESS);
    EXPECT_EQ(*reinterpret_cast<const uint32_t *>(outData.data()), static_cast<uint32_t>(p7bCount));
    const char *firstUri = reinterpret_cast<const char *>(outData.data() + sizeof(uint32_t));
    EXPECT_EQ(strcmp(firstUri, "oh:t=c;o=MultiAlias;u=8899;a=889901"), 0);
    g_installedUris.emplace_back(firstUri);
}

/**
 * @tc.name: CmServiceCheckAppPermission_001
 * @tc.desc: check app permission validates inputs and derives the huks alias from the uri.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceCheckAppPermission_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), "oh:t=ak;o=shortcred;u=8899;a=889901"), EOK);
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    uint8_t aliasBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob huksAlias = { sizeof(aliasBuf), aliasBuf };
    uint32_t hasPermission = 0;

    EXPECT_EQ(CmServiceCheckAppPermission(&context, nullptr, &hasPermission, &huksAlias),
        CMR_ERROR_INVALID_ARGUMENT_URI);
    struct CmBlob badAlias = { 0, nullptr };
    EXPECT_EQ(CmServiceCheckAppPermission(&context, &keyUri, &hasPermission, &badAlias),
        CMR_ERROR_INVALID_ARGUMENT_HANDLE);
    EXPECT_EQ(CmServiceCheckAppPermission(nullptr, &keyUri, &hasPermission, &huksAlias),
        CMR_ERROR_INVALID_ARGUMENT);

    /* wrong uri type for the credential store */
    uint8_t wrongType[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(wrongType), sizeof(wrongType), "oh:t=c;o=alias;u=8899;a=889901"), EOK);
    struct CmBlob wrongTypeUri = { sizeof(wrongType), wrongType };
    EXPECT_EQ(CmServiceCheckAppPermission(&context, &wrongTypeUri, &hasPermission, &huksAlias),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* producer uri: the alias is the common uri itself when it is short enough */
    ASSERT_EQ(CmServiceCheckAppPermission(&context, &keyUri, &hasPermission, &huksAlias), CM_SUCCESS);
    EXPECT_EQ(hasPermission, 1u);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(aliasBuf), "oh:t=ak;o=shortcred;u=8899;a=889901"), 0);
}

/**
 * @tc.name: CmServiceCheckAppPermissionLongAlias_001
 * @tc.desc: long uris are encoded to the base64url sha256 huks alias and sys keys need permission.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceCheckAppPermissionLongAlias_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);

    /* uri longer than MAX_LEN_MAC_KEY: the huks alias becomes the encoded hash */
    std::string longObject(70, 'x');
    std::string longUri = "oh:t=ak;o=" + longObject + ";u=8899;a=889901";
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), longUri.c_str()), EOK);
    struct CmBlob keyUri = { longUri.size() + 1, uriBuf };
    uint8_t aliasBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob huksAlias = { sizeof(aliasBuf), aliasBuf };
    uint32_t hasPermission = 0;

    ASSERT_EQ(CmServiceCheckAppPermission(&context, &keyUri, &hasPermission, &huksAlias), CM_SUCCESS);
    EXPECT_EQ(hasPermission, 1u);
    EXPECT_LE(huksAlias.size, MAX_LEN_BASE64URL_SHA256);
    EXPECT_STRNE(reinterpret_cast<char *>(aliasBuf), longUri.c_str());

    /* system key uri without the system app cert permission */
    uint8_t skUriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(skUriBuf), sizeof(skUriBuf), "oh:t=sk;o=syscred;u=8899;a=889901"), EOK);
    struct CmBlob sysUri = { sizeof(skUriBuf), skUriBuf };
    hasPermission = 0;
    (void)memset_s(aliasBuf, sizeof(aliasBuf), 0, sizeof(aliasBuf));
    EXPECT_EQ(CmServiceCheckAppPermission(&context, &sysUri, &hasPermission, &huksAlias),
        CMR_ERROR_PERMISSION_DENIED);

    /* with the mock hap token the system key permission is granted */
    MockHapToken mockHap;
    ASSERT_EQ(CmServiceCheckAppPermission(&context, &sysUri, &hasPermission, &huksAlias), CM_SUCCESS);
    EXPECT_EQ(hasPermission, 1u);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(aliasBuf), "oh:t=sk;o=syscred;u=8899;a=889901"), 0);
}

/**
 * @tc.name: CmServiceSetGetCertManagerConfig_001
 * @tc.desc: set/get cert manager config roundtrip through the config rdb table.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceSetGetCertManagerConfig_001, TestSize.Level0)
{
    const char *testKey = "com.engine.ut.config";
    (void)DeleteConfigByKey(testKey);

    struct CmConfigItem item;
    (void)memset_s(&item, sizeof(item), 0, sizeof(item));
    ASSERT_EQ(strcpy_s(item.key, sizeof(item.key), testKey), EOK);
    ASSERT_EQ(strcpy_s(item.value, sizeof(item.value), "on"), EOK);
    struct CertManagerConfig config;
    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    config.count = 1;
    config.configItems = &item;

    /* argument validation */
    EXPECT_EQ(CmServiceSetCertManagerConfig(nullptr), CMR_ERROR_INVALID_ARGUMENT);
    struct CertManagerConfig noItems = { 1, nullptr };
    EXPECT_EQ(CmServiceSetCertManagerConfig(&noItems), CMR_ERROR_INVALID_ARGUMENT);

    /* caller without permission */
    EXPECT_EQ(CmServiceSetCertManagerConfig(&config), CMR_ERROR_PERMISSION_DENIED);

    MockHapToken mockHap;
    ASSERT_EQ(CmServiceSetCertManagerConfig(&config), CM_SUCCESS);

    /* query the specific key back */
    uint8_t keyBuf[MAX_LEN_CONFIG_KEY * 2] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(keyBuf), sizeof(keyBuf), testKey), EOK);
    struct CmBlob keysBlob = { strlen(testKey) + 1, keyBuf };
    struct CertManagerConfig outConfig;
    (void)memset_s(&outConfig, sizeof(outConfig), 0, sizeof(outConfig));
    ASSERT_EQ(CmServiceGetCertManagerConfig(&keysBlob, &outConfig), CM_SUCCESS);
    ASSERT_EQ(outConfig.count, 1u);
    EXPECT_EQ(strcmp(outConfig.configItems[0].key, testKey), 0);
    EXPECT_EQ(strcmp(outConfig.configItems[0].value, "on"), 0);
    FreeCertManagerConfig(&outConfig);

    /* unknown key */
    uint8_t missBuf[MAX_LEN_CONFIG_KEY * 2] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(missBuf), sizeof(missBuf), "com.engine.ut.missing"), EOK);
    struct CmBlob missKeys = { strlen("com.engine.ut.missing") + 1, missBuf };
    (void)memset_s(&outConfig, sizeof(outConfig), 0, sizeof(outConfig));
    ASSERT_EQ(CmServiceGetCertManagerConfig(&missKeys, &outConfig), CM_SUCCESS);
    EXPECT_EQ(outConfig.count, 0u);
    EXPECT_EQ(outConfig.configItems, nullptr);

    /* query all when no keys are given */
    ASSERT_EQ(CmServiceGetCertManagerConfig(nullptr, &outConfig), CM_SUCCESS);
    EXPECT_GE(outConfig.count, 1u);
    EXPECT_LE(outConfig.count, MAX_COUNT_CONFIG_ITEM);
    FreeCertManagerConfig(&outConfig);

    /* config pointer validation on get */
    EXPECT_EQ(CmServiceGetCertManagerConfig(nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    (void)DeleteConfigByKey(testKey);
}

/**
 * @tc.name: CmServiceFindCertificate_001
 * @tc.desc: find certificate covers argument validation, empty results and the rdb query path.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceFindCertificate_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct FindCertRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    struct FindCertResult result;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));

    EXPECT_EQ(CmServiceFindCertificate(nullptr, &request, &result), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceFindCertificate(&context, nullptr, &result), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* caller without common permission */
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, &result), CMR_ERROR_PERMISSION_DENIED);

    MockHapToken mockHap;

    /* invalid scope and cert types */
    request.scope = static_cast<enum CmFindCertScope>(99);
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, &result), CMR_ERROR_INVALID_ARGUMENT);
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    request.certTypesCount = 1;
    request.certTypes = nullptr;
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, &result), CMR_ERROR_INVALID_ARGUMENT);
    enum CmFindCertType badTypes[1] = { static_cast<enum CmFindCertType>(5) };
    request.certTypes = badTypes;
    EXPECT_EQ(CmServiceFindCertificate(&context, &request, &result), CMR_ERROR_INVALID_ARGUMENT);
    enum CmFindCertType okTypes[1] = { CM_FIND_CERT_TYPE_USER_CA };
    request.certTypes = okTypes;

    /* no rows for this user: empty result */
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);

    /* global scope does not see the current user's rows */
    request.scope = CM_FIND_CERT_SCOPE_GLOBAL;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
}

/**
 * @tc.name: CmServiceFindCertificateMatch_001
 * @tc.desc: find certificate returns installed certs with data and status and honours filters.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceFindCertificateMatch_001, TestSize.Level0)
{
    std::string firstUri;
    std::string secondUri;
    ASSERT_EQ(InstallUserCertWithAlias("FindAliasOne", firstUri), CM_SUCCESS);
    ASSERT_EQ(InstallUserCertWithAlias("FindAliasTwo", secondUri), CM_SUCCESS);

    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct FindCertRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;

    struct FindCertResult result;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 2u);
    EXPECT_STREQ(result.certInfos[0].uri, firstUri.c_str());
    EXPECT_STREQ(result.certInfos[1].uri, secondUri.c_str());
    EXPECT_EQ(result.certInfos[0].type, CM_FIND_CERT_TYPE_USER_CA);
    EXPECT_EQ(result.certInfos[0].scope, CM_FIND_CERT_SCOPE_CURRENT_USER);
    EXPECT_EQ(result.certInfos[0].state, CERT_STATUS_DISABLED);
    EXPECT_GT(result.certInfos[0].certData.size, 0u);
    EXPECT_EQ(memcmp(result.certInfos[0].certData.data, g_certData06, strlen(g_certData06)), 0);
    FreeFindCertResult(&result);

    /* name filter narrows the result */
    ASSERT_EQ(strcpy_s(request.name, sizeof(request.name), "FindAliasTwo"), EOK);
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    EXPECT_STREQ(result.certInfos[0].uri, secondUri.c_str());
    FreeFindCertResult(&result);
    (void)memset_s(request.name, sizeof(request.name), 0, sizeof(request.name));

    /* certId filter matches the uri object component */
    ASSERT_EQ(strcpy_s(request.certId, sizeof(request.certId), "FindAliasOne"), EOK);
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    EXPECT_STREQ(result.certInfos[0].uri, firstUri.c_str());
    FreeFindCertResult(&result);
    (void)memset_s(request.certId, sizeof(request.certId), 0, sizeof(request.certId));

    /* count limit truncates the result set */
    request.countLimit = 1;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_EQ(result.count, 1u);
    FreeFindCertResult(&result);
}

/**
 * @tc.name: CmServiceFindCertificateMatch_002
 * @tc.desc: find certificate skips orphan rows and covers the current and global scope.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceFindCertificateMatch_002, TestSize.Level0)
{
    std::string firstUri;
    std::string secondUri;
    ASSERT_EQ(InstallUserCertWithAlias("FindAliasOne", firstUri), CM_SUCCESS);
    ASSERT_EQ(InstallUserCertWithAlias("FindAliasTwo", secondUri), CM_SUCCESS);

    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct FindCertRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;

    struct FindCertResult result;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));

    /* a row without a certificate file is skipped entirely */
    const char *orphanUri = "oh:t=c;o=orphanrow;u=8899;a=889901";
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(strcpy_s(prop.uri, sizeof(prop.uri), orphanUri), EOK);
    ASSERT_EQ(strcpy_s(prop.alias, sizeof(prop.alias), "orphan"), EOK);
    ASSERT_EQ(strcpy_s(prop.subjectName, sizeof(prop.subjectName), "subject"), EOK);
    ASSERT_EQ(strcpy_s(prop.certType, sizeof(prop.certType), "c"), EOK);
    prop.certStore = static_cast<int32_t>(CM_USER_TRUSTED_STORE);
    prop.userId = static_cast<int32_t>(TEST_SERVICE_USER);
    prop.uid = static_cast<int32_t>(TEST_SERVICE_UID);
    prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(InsertCertProperty(&prop), CM_SUCCESS);
    g_installedUris.emplace_back(orphanUri);

    ASSERT_EQ(strcpy_s(request.name, sizeof(request.name), "orphan"), EOK);
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);
    (void)memset_s(request.name, sizeof(request.name), 0, sizeof(request.name));

    /* current and global scope still sees the current user rows */
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL;
    (void)memset_s(&result, sizeof(result), 0, sizeof(result));
    ASSERT_EQ(CmServiceFindCertificate(&context, &request, &result), CM_SUCCESS);
    ASSERT_GE(result.count, 2u);
    FreeFindCertResult(&result);
}

/**
 * @tc.name: CmServiceGetAuthorizedAppList_001
 * @tc.desc: authorization service entries validate uri and permission before touching the auth store.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineServiceTest, CmServiceGetAuthorizedAppList_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_SERVICE_USER, TEST_SERVICE_UID);
    struct CmAppUidList appUidList;
    (void)memset_s(&appUidList, sizeof(appUidList), 0, sizeof(appUidList));

    uint8_t garbage[] = "garbage";
    struct CmBlob badUri = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmServiceGetAuthorizedAppList(&context, &badUri, &appUidList),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* grant/authorized/remove also validate their inputs first */
    EXPECT_EQ(CmServiceIsAuthorizedApp(&context, &badUri), CMR_ERROR_INVALID_ARGUMENT);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), "oh:t=ak;o=authcert;u=8899;a=889901"), EOK);
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    uint8_t outAuthBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob outAuthUri = { sizeof(outAuthBuf), outAuthBuf };

    EXPECT_EQ(CmServiceGrantAppCertificate(&context, &keyUri, TEST_SERVICE_OTHER_UID, &outAuthUri),
        CMR_ERROR_PERMISSION_DENIED);
    EXPECT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CMR_ERROR_PERMISSION_DENIED);
    EXPECT_EQ(CmServiceRemoveGrantedApp(&context, &keyUri, TEST_SERVICE_OTHER_UID),
        CMR_ERROR_PERMISSION_DENIED);

    /* grant validates the auth uri blob as well */
    MockHapToken mockHap;
    struct CmBlob badAuthUri = { 0, nullptr };
    EXPECT_EQ(CmServiceGrantAppCertificate(nullptr, &keyUri, TEST_SERVICE_OTHER_UID, &outAuthUri),
        CMR_ERROR_INVALID_ARGUMENT_URI);
    EXPECT_EQ(CmServiceGrantAppCertificate(&context, &keyUri, TEST_SERVICE_OTHER_UID, &badAuthUri),
        CMR_ERROR_INVALID_ARGUMENT_URI);
}
