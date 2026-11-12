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
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "cert_manager.h"
#include "cert_manager_check.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cm_cert_data_chain_key.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_property_rdb.h"
#include "cm_config_rdb.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_APPCERT_USER = 8899;
constexpr uint32_t TEST_APPCERT_UID = 889901;
constexpr uint32_t TEST_APPCERT_OTHER_UID = 889902;
constexpr uint32_t TEST_APPCERT_THIRD_UID = 889903;
constexpr int NFTW_MAX_OPEN_FDS = 16;
constexpr uint32_t RSA2048_SIGNATURE_LEN = 256;
constexpr uint32_t AUTH_UID_CAPACITY = 8;
const std::vector<std::string> COMMON_ONLY_PERMS = {
    "ohos.permission.ACCESS_CERT_MANAGER",
};

/* roots owned by the SA that are created here only when missing */
const std::vector<std::string> NEEDED_ROOTS = {
    CREDNTIAL_STORE,
    PRI_CREDNTIAL_STORE,
    SYS_CREDNTIAL_STORE,
    "/data/service/el1/public/cert_manager_service/rdb",
};
std::vector<std::string> g_createdRoots;

std::vector<std::string> g_installedUris; /* RDB rows created through the install entry points */

/* isolated user subtrees touched by the cases below; the credential user 0
 * case only owns its private uid directory under the real user 0 store */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(CREDNTIAL_STORE) + "0/" + std::to_string(TEST_APPCERT_UID),
        std::string(CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER),
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER),
        std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER),
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

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}

struct CmAppCertParam BuildAppCertParam(struct CmBlob *appCert, struct CmBlob *appCertPwd,
    struct CmBlob *certAlias, uint32_t store, uint32_t userId, enum CmAuthStorageLevel level,
    enum CredFormat credFormat, struct CmBlob *appCertPrivKey)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    param.appCert = appCert;
    param.appCertPwd = appCertPwd;
    param.certAlias = certAlias;
    param.store = store;
    param.userId = userId;
    param.level = level;
    param.credFormat = credFormat;
    param.appCertPrivKey = appCertPrivKey;
    param.aliasFormat = DEFAULT_FORMAT;
    return param;
}

void TrackInstalledUri(const struct CmBlob *keyUri)
{
    if (keyUri != nullptr && keyUri->data != nullptr) {
        g_installedUris.emplace_back((char *)keyUri->data);
    }
}

void DeleteInstalledRdbRowsQuietly()
{
    for (const auto &uri : g_installedUris) {
        (void)DeleteCertProperty(uri.c_str());
    }
    g_installedUris.clear();
}

/* install one P12 (rsa2048) credential through the service entry point */
int32_t InstallP12Cert(const std::string &alias, uint32_t store, uint32_t paramUserId,
    enum CmAuthStorageLevel level, struct CmContext *context, struct CmBlob *keyUri)
{
    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    (void)strcpy_s((char *)aliasBuf, sizeof(aliasBuf), alias.c_str());
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };
    struct CmBlob emptyKey = { 0, nullptr };

    struct CmAppCertParam param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias,
        store, paramUserId, level, FILE_P12, &emptyKey);
    int32_t ret = CmServicInstallAppCert(context, &param, keyUri);
    if (ret == CM_SUCCESS) {
        TrackInstalledUri(keyUri);
    }
    return ret;
}

/* install one chain+key credential through the service entry point */
int32_t InstallChainKeyCert(const std::string &alias, uint32_t store, uint32_t paramUserId,
    enum CmAuthStorageLevel level, struct CmContext *context, struct CmBlob *keyUri)
{
    struct CmBlob certChain = { strlen(g_rsa2048PEMCertChain) + 1,
        reinterpret_cast<uint8_t *>(g_rsa2048PEMCertChain) };
    struct CmBlob privKey = { strlen(g_rsa2048PEMPrivKey) + 1,
        reinterpret_cast<uint8_t *>(g_rsa2048PEMPrivKey) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    (void)strcpy_s((char *)aliasBuf, sizeof(aliasBuf), alias.c_str());
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };

    struct CmAppCertParam param = BuildAppCertParam(&certChain, &appCertPwd, &certAlias,
        store, paramUserId, level, CHAIN_KEY, &privKey);
    int32_t ret = CmServicInstallAppCert(context, &param, keyUri);
    if (ret == CM_SUCCESS) {
        TrackInstalledUri(keyUri);
    }
    return ret;
}

void InitSignatureSpec(struct CmSignatureSpec *spec, uint32_t purpose)
{
    (void)memset_s(spec, sizeof(*spec), 0, sizeof(*spec));
    spec->purpose = purpose;
    spec->padding = CM_PADDING_PSS;
    spec->digest = CM_DIGEST_SHA256;
}

void MakeMessageBlob(struct CmBlob *message)
{
    static uint8_t msg[] = "This_is_test_message_for_test_sign_and_verify";
    message->size = sizeof(msg) - 1;
    message->data = msg;
}
} // namespace

class CmEngineAppCertTest : public testing::Test {
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
        /* installs and grant flow consult both rdb tables */
        ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
        ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
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
 * @tc.name: CmEngineInstallCredAppCert_001
 * @tc.desc: install, query and uninstall a public credential end to end.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallCredAppCert_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    const std::string expectUri = "oh:t=ak;o=EngineCred;u=0;a=889901";
    const std::string uidDir = std::string(CREDNTIAL_STORE) + "0/" + std::to_string(TEST_APPCERT_UID);

    /* install */
    ASSERT_EQ(InstallP12Cert("EngineCred", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);
    EXPECT_EQ(std::string((char *)uriBuf), expectUri);
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), (char *)uriBuf), CMR_OK);

    /* the public credential defaults to level el2 when the row is fresh */
    enum CmAuthStorageLevel level = static_cast<enum CmAuthStorageLevel>(ERROR_LEVEL);
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL2);

    /* re-installing the very same credential is idempotent */
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri2 = { sizeof(uriBuf2), uriBuf2 };
    ASSERT_EQ(InstallP12Cert("EngineCred", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri2), CM_SUCCESS);
    EXPECT_EQ(strcmp((char *)uriBuf2, (char *)uriBuf), 0);

    /* the producer reads the stored app cert back */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    struct AppCert *appCert = (struct AppCert *)certBlob.data;
    EXPECT_GE(appCert->certCount, 1u);
    EXPECT_EQ(appCert->keyCount, 1u);
    EXPECT_GT(appCert->certSize, 0u);
    EXPECT_EQ(uriCopy.size, strlen((char *)uriBuf) + 1);
    CmFree(certBlob.data);
    certBlob.data = nullptr;
    certBlob.size = 0;

    /* the credential appears in the file list of the uid layer */
    ASSERT_EQ(CmServiceGetAppCertListCheck(&context, CM_CREDENTIAL_STORE), CM_SUCCESS);
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    (void)memset_s(fileNames, sizeof(fileNames), 0, sizeof(fileNames));
    uint32_t fileCount = 0;
    ASSERT_EQ(CmServiceGetAppCertList(&context, CM_CREDENTIAL_STORE, fileNames,
        MAX_COUNT_CERTIFICATE, &fileCount), CM_SUCCESS);
    EXPECT_GE(fileCount, 1u);
    bool seen = false;
    for (uint32_t i = 0; i < fileCount; i++) {
        seen = seen || (strstr((char *)fileNames[i].data, (char *)uriBuf) != nullptr);
    }
    EXPECT_TRUE(seen);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* uninstall removes file and rdb row and stays observable */
    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), (char *)uriBuf), CMR_OK);

    level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);

    struct CmBlob uriCopy2 = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &uriCopy2, &certBlob),
        CMR_ERROR_NOT_EXIST);

    /* a second uninstall finds nothing left and reports it */
    EXPECT_NE(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);

    /* the list is empty again for this caller */
    (void)memset_s(fileNames, sizeof(fileNames), 0, sizeof(fileNames));
    fileCount = 0;
    ASSERT_EQ(CmServiceGetAppCertList(&context, CM_CREDENTIAL_STORE, fileNames,
        MAX_COUNT_CERTIFICATE, &fileCount), CM_SUCCESS);
    EXPECT_EQ(fileCount, 0u);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
}

/**
 * @tc.name: CmEngineInstallAppCertInvalid_001
 * @tc.desc: the install entry point rejects bad password, data, store, level and alias.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallAppCertInvalid_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    uint8_t wrongPwd[] = "12345678";
    struct CmBlob wrongPwdBlob = { sizeof(wrongPwd), wrongPwd };
    struct CmBlob goodPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[] = "EngineBad";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t badAliasBuf[] = "Engine-Bad";
    struct CmBlob badAlias = { sizeof(badAliasBuf), badAliasBuf };
    uint8_t garbage[] = "garbage";
    struct CmBlob badCert = { sizeof(garbage) - 1, garbage };
    struct CmBlob emptyKey = { 0, nullptr };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    /* wrong p12 password fails while parsing */
    struct CmAppCertParam param = BuildAppCertParam(&appCert, &wrongPwdBlob, &certAlias,
        CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2, FILE_P12, &emptyKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_PASSWORD_IS_ERR);

    /* garbage certificate data is rejected by the p12 parser */
    param = BuildAppCertParam(&badCert, &goodPwd, &certAlias, CM_CREDENTIAL_STORE,
        INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2, FILE_P12, &emptyKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_INVALID_CERT_FORMAT);

    /* unsupported store value */
    param = BuildAppCertParam(&appCert, &goodPwd, &certAlias, CM_SYS_CREDENTIAL_STORE + 1,
        INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2, FILE_P12, &emptyKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* unsupported storage level */
    param = BuildAppCertParam(&appCert, &goodPwd, &certAlias, CM_CREDENTIAL_STORE,
        INIT_INVALID_VALUE, static_cast<enum CmAuthStorageLevel>(3), FILE_P12, &emptyKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);

    /* alias containing a character outside [A-Za-z0-9_] */
    param = BuildAppCertParam(&appCert, &goodPwd, &badAlias, CM_CREDENTIAL_STORE,
        INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL2, FILE_P12, &emptyKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_INVALID_ARGUMENT_ALIAS);
}

/**
 * @tc.name: CmEngineInstallPriAppCert_001
 * @tc.desc: private credentials support producer and privileged readers and level switch.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallPriAppCert_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    const std::string uidDir = std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);

    ASSERT_EQ(InstallP12Cert("EnginePri", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);
    EXPECT_EQ(std::string((char *)uriBuf), "oh:t=ak;o=EnginePri;u=8899;a=889901");
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), (char *)uriBuf), CMR_OK);

    enum CmAuthStorageLevel level = static_cast<enum CmAuthStorageLevel>(ERROR_LEVEL);
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL2);

    /* producer reads the private credential */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    EXPECT_EQ(((struct AppCert *)certBlob.data)->keyCount, 1u);
    CmFree(certBlob.data);
    certBlob.data = nullptr;
    certBlob.size = 0;

    /* a privileged non producer caller is allowed to read it too */
    struct CmContext otherContext = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_OTHER_UID);
    struct CmBlob uriCopy2 = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&otherContext, CM_PRI_CREDENTIAL_STORE, &uriCopy2, &certBlob),
        CM_SUCCESS);
    EXPECT_EQ(((struct AppCert *)certBlob.data)->keyCount, 1u);
    CmFree(certBlob.data);
    certBlob.data = nullptr;
    certBlob.size = 0;

    /* a caller with only the common permission is rejected */
    {
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        struct CmContext noPermContext = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_OTHER_UID);
        struct CmBlob uriCopy3 = { sizeof(uriBuf), uriBuf };
        EXPECT_EQ(CmServiceGetAppCert(&noPermContext, CM_PRI_CREDENTIAL_STORE, &uriCopy3, &certBlob),
            CMR_ERROR_PERMISSION_DENIED);
    }

    /* re-installing with another level removes the old credential first */
    ASSERT_EQ(InstallP12Cert("EnginePri", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &keyUri), CM_SUCCESS);
    level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL1);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), (char *)uriBuf), CMR_OK);
    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
}

/**
 * @tc.name: CmEngineInstallSysAppCert_001
 * @tc.desc: system credentials require an explicit user and use the sk uri type.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallSysAppCert_001, TestSize.Level0)
{
    MockHapToken mockHap;
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    /* hap style caller: user id comes from the context. the client wrapper
     * always sends level el1 for system credentials, so the rdb row mirrors it. */
    struct CmContext context = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_UID);
    ASSERT_EQ(InstallP12Cert("EngineSys", CM_SYS_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &keyUri), CM_SUCCESS);
    EXPECT_EQ(std::string((char *)uriBuf), "oh:t=sk;o=EngineSys;u=8899;a=889901");

    /* the system credential key is imported at level el1 */
    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL1);

    /* sa style caller designates the target user through the param */
    struct CmContext saContext = BuildContext(0, TEST_APPCERT_OTHER_UID);
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri2 = { sizeof(uriBuf2), uriBuf2 };
    ASSERT_EQ(InstallP12Cert("EngineSysSa", CM_SYS_CREDENTIAL_STORE, TEST_APPCERT_USER,
        CM_AUTH_STORAGE_LEVEL_EL1, &saContext, &keyUri2), CM_SUCCESS);
    EXPECT_EQ(std::string((char *)uriBuf2), "oh:t=sk;o=EngineSysSa;u=8899;a=889902");

    /* sa style caller must designate a user for system credentials */
    struct CmContext badSaContext = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf3[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri3 = { sizeof(uriBuf3), uriBuf3 };
    EXPECT_EQ(InstallP12Cert("EngineSysBad", CM_SYS_CREDENTIAL_STORE, 0,
        CM_AUTH_STORAGE_LEVEL_EL1, &badSaContext, &keyUri3), CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    /* system credentials are read without a producer check */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_SYS_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    EXPECT_EQ(((struct AppCert *)certBlob.data)->keyCount, 1u);
    CmFree(certBlob.data);

    /* both installs are removed again */
    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_SYS_CREDENTIAL_STORE), CM_SUCCESS);
    struct CmContext ownerContext = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_OTHER_UID);
    ASSERT_EQ(CmRemoveAppCert(&ownerContext, &keyUri2, CM_SYS_CREDENTIAL_STORE), CM_SUCCESS);

    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
}

/**
 * @tc.name: CmEngineInstallChainKeyCert_001
 * @tc.desc: credentials supplied as a certificate chain plus a pem private key install and read.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallChainKeyCert_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    ASSERT_EQ(InstallChainKeyCert("EngineChain", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &keyUri), CM_SUCCESS);
    EXPECT_EQ(std::string((char *)uriBuf), "oh:t=ak;o=EngineChain;u=8899;a=889901");

    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    struct AppCert *appCert = (struct AppCert *)certBlob.data;
    EXPECT_GE(appCert->certCount, 1u);
    EXPECT_EQ(appCert->keyCount, 1u);
    CmFree(certBlob.data);

    /* garbage chain data is rejected before any storage access */
    uint8_t garbage[] = "garbage";
    struct CmBlob garbageChain = { sizeof(garbage), garbage };
    struct CmBlob privKey = { strlen(g_rsa2048PEMPrivKey) + 1,
        reinterpret_cast<uint8_t *>(g_rsa2048PEMPrivKey) };
    struct CmBlob goodPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[] = "EngineChainBad";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    struct CmAppCertParam param = BuildAppCertParam(&garbageChain, &goodPwd, &certAlias,
        CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1, CHAIN_KEY, &privKey);
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri2 = { sizeof(uriBuf2), uriBuf2 };
    EXPECT_NE(CmServicInstallAppCert(&context, &param, &keyUri2), CM_SUCCESS);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineGrantCertFlow_001
 * @tc.desc: grant, query, authorize and revoke the access of another app to a credential.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineGrantCertFlow_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(InstallP12Cert("EngineGrant", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* grant access to another app */
    uint8_t authUriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ASSERT_EQ(CmServiceGrantAppCertificate(&context, &keyUri, TEST_APPCERT_OTHER_UID, &authUri),
        CM_SUCCESS);
    const std::string authUriStr((char *)authUriBuf);
    EXPECT_EQ(authUriStr.rfind("oh:t=ak;o=EngineGrant;u=0;a=889901", 0), 0u);
    EXPECT_NE(authUriStr.find("?ca=889902&m="), std::string::npos);

    /* the authorized app list reports the granted uid */
    uint32_t appUids[AUTH_UID_CAPACITY] = { 0 };
    struct CmAppUidList appUidList = { AUTH_UID_CAPACITY, appUids };
    ASSERT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, 1u);
    EXPECT_EQ(appUidList.appUid[0], TEST_APPCERT_OTHER_UID);

    /* the granted app is authorized through the auth uri */
    struct CmContext authedContext = BuildContext(0, TEST_APPCERT_OTHER_UID);
    ASSERT_EQ(CmServiceIsAuthorizedApp(&authedContext, &authUri), CM_SUCCESS);

    /* a tampered mac is rejected */
    std::string tampered = authUriStr;
    size_t macPos = tampered.find("&m=");
    ASSERT_NE(macPos, std::string::npos);
    tampered[macPos + 3] = (tampered[macPos + 3] == '0') ? '1' : '0';
    uint8_t tamperedBuf[MAX_LEN_URI] = { 0 };
    (void)strcpy_s((char *)tamperedBuf, sizeof(tamperedBuf), tampered.c_str());
    struct CmBlob tamperedUri = { tampered.size() + 1, tamperedBuf };
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &tamperedUri),
        CMR_ERROR_AUTH_FAILED_MAC_MISMATCH);

    /* an uri without client app and mac is not an auth uri */
    uint8_t plainBuf[MAX_LEN_URI] = { 0 };
    (void)strcpy_s((char *)plainBuf, sizeof(plainBuf), "oh:t=ak;o=EngineGrant;u=0;a=889901");
    struct CmBlob plainUri = { strlen((char *)plainBuf) + 1, plainBuf };
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &plainUri), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* revoke the grant */
    ASSERT_EQ(CmServiceRemoveGrantedApp(&context, &keyUri, TEST_APPCERT_OTHER_UID), CM_SUCCESS);
    appUidList = { AUTH_UID_CAPACITY, appUids };
    (void)memset_s(appUids, sizeof(appUids), 0, sizeof(appUids));
    ASSERT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, 0u);

    /* after the revocation the auth uri no longer authorizes */
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &authUri), CMR_ERROR_AUTH_FAILED_MAC_MISMATCH);

    /* granting for a missing credential fails */
    uint8_t missingBuf[MAX_LEN_URI] = { 0 };
    (void)strcpy_s((char *)missingBuf, sizeof(missingBuf), "oh:t=ak;o=EngineMissing;u=0;a=889901");
    struct CmBlob missingUri = { strlen((char *)missingBuf) + 1, missingBuf };
    uint8_t outBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob outAuthUri = { sizeof(outBuf), outBuf };
    EXPECT_NE(CmServiceGrantAppCertificate(&context, &missingUri, TEST_APPCERT_OTHER_UID,
        &outAuthUri), CM_SUCCESS);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineSignVerifyCred_001
 * @tc.desc: the installed credential signs a message and verifies the signature.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineSignVerifyCred_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(InstallP12Cert("EngineSign", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    struct CmSignatureSpec spec;
    struct CmBlob message;
    MakeMessageBlob(&message);
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    uint8_t signData[1024] = { 0 };
    struct CmBlob signature = { sizeof(signData), signData };
    struct CmBlob emptyIn = { 0, nullptr };

    /* sign */
    InitSignatureSpec(&spec, CM_KEY_PURPOSE_SIGN);
    ASSERT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CM_SUCCESS);
    ASSERT_EQ(CmServiceUpdate(&context, &handle, &message), CM_SUCCESS);
    ASSERT_EQ(CmServiceFinish(&context, &handle, &emptyIn, &signature), CM_SUCCESS);
    EXPECT_EQ(signature.size, RSA2048_SIGNATURE_LEN);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CM_SUCCESS);

    /* abort tears down a running session */
    handleValue = 0;
    ASSERT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CM_SUCCESS);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CM_SUCCESS);

    /* verify the signature produced above */
    InitSignatureSpec(&spec, CM_KEY_PURPOSE_VERIFY);
    handleValue = 0;
    ASSERT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CM_SUCCESS);
    ASSERT_EQ(CmServiceUpdate(&context, &handle, &message), CM_SUCCESS);
    struct CmBlob sigIn = { signature.size, signature.data };
    struct CmBlob verifyOut = { 0, nullptr };
    EXPECT_EQ(CmServiceFinish(&context, &handle, &sigIn, &verifyOut), CM_SUCCESS);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CM_SUCCESS);

    /* a modified signature fails the verification */
    signature.data[0] = static_cast<uint8_t>(signature.data[0] ^ 0x01);
    handleValue = 0;
    ASSERT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CM_SUCCESS);
    ASSERT_EQ(CmServiceUpdate(&context, &handle, &message), CM_SUCCESS);
    sigIn = { signature.size, signature.data };
    verifyOut = { 0, nullptr };
    EXPECT_EQ(CmServiceFinish(&context, &handle, &sigIn, &verifyOut), CMR_ERROR_KEY_OPERATION_FAILED);
    EXPECT_EQ(CmServiceAbort(&context, &handle), CM_SUCCESS);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineSignVerifyAuthedApp_001
 * @tc.desc: a granted app signs with the auth uri while strangers stay rejected.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineSignVerifyAuthedApp_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext producer = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(InstallP12Cert("EngineAuthSign", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &producer, &keyUri), CM_SUCCESS);

    uint8_t authUriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ASSERT_EQ(CmServiceGrantAppCertificate(&producer, &keyUri, TEST_APPCERT_OTHER_UID, &authUri),
        CM_SUCCESS);

    /* the granted app initializes the session through the auth uri */
    struct CmContext grantee = BuildContext(0, TEST_APPCERT_OTHER_UID);
    struct CmSignatureSpec spec;
    InitSignatureSpec(&spec, CM_KEY_PURPOSE_SIGN);
    struct CmBlob message;
    MakeMessageBlob(&message);
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
    uint8_t signData[1024] = { 0 };
    struct CmBlob signature = { sizeof(signData), signData };
    struct CmBlob emptyIn = { 0, nullptr };

    ASSERT_EQ(CmServiceInit(&grantee, &authUri, &spec, &handle), CM_SUCCESS);
    ASSERT_EQ(CmServiceUpdate(&grantee, &handle, &message), CM_SUCCESS);
    ASSERT_EQ(CmServiceFinish(&grantee, &handle, &emptyIn, &signature), CM_SUCCESS);
    EXPECT_EQ(signature.size, RSA2048_SIGNATURE_LEN);
    EXPECT_EQ(CmServiceAbort(&grantee, &handle), CM_SUCCESS);

    /* an app that is neither producer nor grantee is rejected */
    struct CmContext stranger = BuildContext(0, TEST_APPCERT_THIRD_UID);
    handleValue = 0;
    EXPECT_EQ(CmServiceInit(&stranger, &authUri, &spec, &handle), CMR_ERROR_NOT_PERMITTED);

    ASSERT_EQ(CmServiceRemoveGrantedApp(&producer, &keyUri, TEST_APPCERT_OTHER_UID), CM_SUCCESS);
    ASSERT_EQ(CmRemoveAppCert(&producer, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineRemoveAllAppCert_001
 * @tc.desc: remove-all sweeps the private and system credentials of the caller user.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineRemoveAllAppCert_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_UID);

    uint8_t priUriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob priKeyUri = { sizeof(priUriBuf), priUriBuf };
    ASSERT_EQ(InstallP12Cert("EngineRmPri", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &priKeyUri), CM_SUCCESS);

    uint8_t sysUriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob sysKeyUri = { sizeof(sysUriBuf), sysUriBuf };
    ASSERT_EQ(InstallP12Cert("EngineRmSys", CM_SYS_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &sysKeyUri), CM_SUCCESS);

    /* the caller needs the full permission set */
    {
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        EXPECT_EQ(CmRemoveAllAppCert(&context), CMR_ERROR_PERMISSION_DENIED);
    }

    ASSERT_EQ(CmRemoveAllAppCert(&context), CM_SUCCESS);

    const std::string priDir = std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);
    const std::string sysDir = std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);
    EXPECT_NE(CmIsFileExist(priDir.c_str(), (char *)priUriBuf), CMR_OK);
    EXPECT_NE(CmIsFileExist(sysDir.c_str(), (char *)sysUriBuf), CMR_OK);

    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&priKeyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&sysKeyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
}
