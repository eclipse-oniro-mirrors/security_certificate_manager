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
#include "cert_manager_permission_check.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cm_cert_data_chain_key.h"
#include "cm_cert_data_ecc.h"
#include "cm_cert_data_ed25519.h"
#include "cm_cert_data_ed448.h"
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
/* EL2 key imports carry the uri user into HUKS, which only accepts an existing
 * foreground device user for the across-accounts check */
constexpr uint32_t TEST_APPCERT_FRONT_USER = 100;
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
        /* the EL2 private-credential case must borrow the real front user,
         * so it only ever owns its synthetic uid directories under it */
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_FRONT_USER) + "/" +
            std::to_string(TEST_APPCERT_UID),
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_FRONT_USER) + "/" +
            std::to_string(TEST_APPCERT_OTHER_UID),
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
        g_installedUris.emplace_back(reinterpret_cast<char *>(keyUri->data));
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
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
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
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
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
    /* keep the message at a valid digest length: the shared digest-none spec lets
     * huks map the message size to the openssl digest (16/20/28/32/48/64 bytes) */
    static uint8_t msg[] = "This_is_test_message_for_sign_32";
    static_assert(sizeof(msg) - 1 == 32, "digest-none ecc sign needs a 32-byte digest");
    message->size = sizeof(msg) - 1;
    message->data = msg;
}

/* copy a nul terminated string into the caller supplied buffer and wrap it as
   a blob; returns a size 0 blob on a bad copy so the follow-up call fails loudly */
struct CmBlob StringBlobOn(const char *text, uint8_t *buf, uint32_t bufSize)
{
    struct CmBlob blob = { 0, nullptr };
    size_t len = strlen(text) + 1;
    if (len <= bufSize && memcpy_s(buf, bufSize, text, len) == EOK) {
        blob.size = len;
        blob.data = buf;
    }
    return blob;
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
        /* the borrowed front-user store directory is only removed when it
         * became empty, so any real device content under it survives */
        (void)rmdir((std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_FRONT_USER)).c_str());
        DeleteInstalledRdbRowsQuietly();
    }
};

/**
 * @tc.name: CmEngineInstallCredAppCert_001
 * @tc.desc: install a public credential, check its level and reinstall it idempotently.
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
    EXPECT_EQ(std::string(reinterpret_cast<char *>(uriBuf)), expectUri);
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);

    /* the public credential defaults to level el2 when the row is fresh */
    enum CmAuthStorageLevel level = static_cast<enum CmAuthStorageLevel>(ERROR_LEVEL);
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL2);

    /* re-installing the very same credential is idempotent */
    uint8_t uriBuf2[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri2 = { sizeof(uriBuf2), uriBuf2 };
    ASSERT_EQ(InstallP12Cert("EngineCred", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri2), CM_SUCCESS);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(uriBuf2), reinterpret_cast<char *>(uriBuf)), 0);
}

/**
 * @tc.name: CmEngineInstallCredAppCert_002
 * @tc.desc: read an installed public credential back and find it in the uid file list.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallCredAppCert_002, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    /* install the credential the queries below read back */
    ASSERT_EQ(InstallP12Cert("EngineCred", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* the producer reads the stored app cert back */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    struct AppCert *appCert = reinterpret_cast<struct AppCert *>(certBlob.data);
    EXPECT_GE(appCert->certCount, 1u);
    EXPECT_EQ(appCert->keyCount, 1u);
    EXPECT_GT(appCert->certSize, 0u);
    EXPECT_EQ(uriCopy.size, strlen(reinterpret_cast<char *>(uriBuf)) + 1);
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
        seen = seen || (strstr(reinterpret_cast<char *>(fileNames[i].data),
            reinterpret_cast<char *>(uriBuf)) != nullptr);
    }
    EXPECT_TRUE(seen);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
}

/**
 * @tc.name: CmEngineInstallCredAppCert_003
 * @tc.desc: uninstall a public credential and observe the removed file, row and empty list.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallCredAppCert_003, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    const std::string uidDir = std::string(CREDNTIAL_STORE) + "0/" + std::to_string(TEST_APPCERT_UID);

    /* install the credential the uninstall below removes */
    ASSERT_EQ(InstallP12Cert("EngineCred", CM_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* uninstall removes file and rdb row and stays observable */
    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);

    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);

    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy2 = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &uriCopy2, &certBlob),
        CMR_ERROR_NOT_EXIST);

    /* a second uninstall finds nothing left and reports it */
    EXPECT_NE(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);

    /* the list is empty again for this caller */
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    (void)memset_s(fileNames, sizeof(fileNames), 0, sizeof(fileNames));
    uint32_t fileCount = 0;
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
    /* EL2 installs import the key under the uri user: use the real front user
       instead of the synthetic one so the HUKS across-accounts check passes */
    struct CmContext context = BuildContext(TEST_APPCERT_FRONT_USER, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    const std::string uidDir = std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_FRONT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);

    ASSERT_EQ(InstallP12Cert("EnginePri", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);
    EXPECT_EQ(std::string(reinterpret_cast<char *>(uriBuf)), "oh:t=ak;o=EnginePri;u=100;a=889901");
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);

    enum CmAuthStorageLevel level = static_cast<enum CmAuthStorageLevel>(ERROR_LEVEL);
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL2);

    /* producer reads the private credential */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    EXPECT_EQ((reinterpret_cast<struct AppCert *>(certBlob.data))->keyCount, 1u);
    CmFree(certBlob.data);
    certBlob = { 0, nullptr };

    /* a privileged non producer caller is allowed to read it too */
    struct CmContext otherContext = BuildContext(TEST_APPCERT_FRONT_USER, TEST_APPCERT_OTHER_UID);
    struct CmBlob uriCopy2 = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&otherContext, CM_PRI_CREDENTIAL_STORE, &uriCopy2, &certBlob),
        CM_SUCCESS);
    EXPECT_EQ((reinterpret_cast<struct AppCert *>(certBlob.data))->keyCount, 1u);
    CmFree(certBlob.data);
    certBlob = { 0, nullptr };

    /* a caller with only the common permission is rejected */
    {
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        struct CmContext noPermContext = BuildContext(TEST_APPCERT_FRONT_USER, TEST_APPCERT_OTHER_UID);
        struct CmBlob uriCopy3 = { sizeof(uriBuf), uriBuf };
        EXPECT_EQ(CmServiceGetAppCert(&noPermContext, CM_PRI_CREDENTIAL_STORE, &uriCopy3, &certBlob),
            CMR_ERROR_PERMISSION_DENIED);
    }

    /* the scoped token removed the process token: restore the full permission set */
    MockHapToken mockHapAgain;

    /* re-installing with another level removes the old credential first */
    ASSERT_EQ(InstallP12Cert("EnginePri", CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE,
        CM_AUTH_STORAGE_LEVEL_EL1, &context, &keyUri), CM_SUCCESS);
    level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL1);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(uriBuf)), CMR_OK);
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
    EXPECT_EQ(std::string(reinterpret_cast<char *>(uriBuf)), "oh:t=sk;o=EngineSys;u=8899;a=889901");

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
    EXPECT_EQ(std::string(reinterpret_cast<char *>(uriBuf2)), "oh:t=sk;o=EngineSysSa;u=8899;a=889902");

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
    EXPECT_EQ((reinterpret_cast<struct AppCert *>(certBlob.data))->keyCount, 1u);
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
    EXPECT_EQ(std::string(reinterpret_cast<char *>(uriBuf)), "oh:t=ak;o=EngineChain;u=8899;a=889901");

    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_PRI_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    struct AppCert *appCert = reinterpret_cast<struct AppCert *>(certBlob.data);
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
    const std::string authUriStr(reinterpret_cast<char *>(authUriBuf));
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
    struct CmBlob tamperedUri = StringBlobOn(tampered.c_str(), tamperedBuf, sizeof(tamperedBuf));
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &tamperedUri), CMR_ERROR_AUTH_FAILED_MAC_MISMATCH);

    /* an uri without client app and mac is not an auth uri */
    uint8_t plainBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob plainUri = StringBlobOn("oh:t=ak;o=EngineGrant;u=0;a=889901", plainBuf, sizeof(plainBuf));
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &plainUri), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* revoke the grant */
    ASSERT_EQ(CmServiceRemoveGrantedApp(&context, &keyUri, TEST_APPCERT_OTHER_UID), CM_SUCCESS);
    appUidList = { AUTH_UID_CAPACITY, appUids };
    (void)memset_s(appUids, sizeof(appUids), 0, sizeof(appUids));
    ASSERT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, 0u);

    /* after the revocation the auth uri no longer authorizes: the grant removal
       deleted the mac key, so the mac calculation itself fails */
    EXPECT_EQ(CmServiceIsAuthorizedApp(&authedContext, &authUri), CMR_ERROR_AUTH_FAILED_MAC_FAILED);

    /* granting for a missing credential fails */
    uint8_t missingBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob missingUri = StringBlobOn("oh:t=ak;o=EngineMissing;u=0;a=889901", missingBuf, sizeof(missingBuf));
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
    struct CmBlob handle = { sizeof(handleValue), reinterpret_cast<uint8_t *>(&handleValue) };
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

    /* a modified signature fails the verification inside the key finish step */
    signature.data[0] = static_cast<uint8_t>(signature.data[0] ^ 0x01);
    handleValue = 0;
    ASSERT_EQ(CmServiceInit(&context, &keyUri, &spec, &handle), CM_SUCCESS);
    ASSERT_EQ(CmServiceUpdate(&context, &handle, &message), CM_SUCCESS);
    sigIn = { signature.size, signature.data };
    verifyOut = { 0, nullptr };
    EXPECT_EQ(CmServiceFinish(&context, &handle, &sigIn, &verifyOut), CMR_ERROR_KEY_FINISH_FAILED);
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
    struct CmBlob handle = { sizeof(handleValue), reinterpret_cast<uint8_t *>(&handleValue) };
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

    /* the scoped token removed the process token: restore the full permission set */
    MockHapToken mockHapAgain;
    ASSERT_EQ(CmRemoveAllAppCert(&context), CM_SUCCESS);

    const std::string priDir = std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);
    const std::string sysDir = std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_APPCERT_USER) +
        "/" + std::to_string(TEST_APPCERT_UID);
    EXPECT_NE(CmIsFileExist(priDir.c_str(), reinterpret_cast<char *>(priUriBuf)), CMR_OK);
    EXPECT_NE(CmIsFileExist(sysDir.c_str(), reinterpret_cast<char *>(sysUriBuf)), CMR_OK);

    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&priKeyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&sysKeyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);
}

namespace {
/* install a caller supplied p12 blob through the service entry point */
int32_t InstallP12Blob(struct CmBlob *appCert, struct CmBlob *appCertPwd, const std::string &alias,
    uint32_t store, enum CmAuthStorageLevel level, struct CmContext *context, struct CmBlob *keyUri)
{
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };
    struct CmBlob emptyKey = { 0, nullptr };

    struct CmAppCertParam param = BuildAppCertParam(appCert, appCertPwd, &certAlias,
        store, INIT_INVALID_VALUE, level, FILE_P12, &emptyKey);
    int32_t ret = CmServicInstallAppCert(context, &param, keyUri);
    if (ret == CM_SUCCESS) {
        TrackInstalledUri(keyUri);
    }
    return ret;
}

/* sign a fixed message with the installed credential and verify the signature
 * again; the plain spec { purpose, 0, 0 } matches the ecc/ed25519 hks calls */
int32_t SignAndVerifyRoundtrip(struct CmContext *context, struct CmBlob *keyUri)
{
    struct CmSignatureSpec spec;
    (void)memset_s(&spec, sizeof(spec), 0, sizeof(spec));
    struct CmBlob message;
    MakeMessageBlob(&message);
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(handleValue), reinterpret_cast<uint8_t *>(&handleValue) };
    uint8_t signData[1024] = { 0 };
    struct CmBlob signature = { sizeof(signData), signData };
    struct CmBlob emptyIn = { 0, nullptr };

    /* sign the message and abort the finished session */
    spec.purpose = CM_KEY_PURPOSE_SIGN;
    int32_t ret = CmServiceInit(context, keyUri, &spec, &handle);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = CmServiceUpdate(context, &handle, &message);
    if (ret != CM_SUCCESS) {
        (void)CmServiceAbort(context, &handle);
        return ret;
    }
    ret = CmServiceFinish(context, &handle, &emptyIn, &signature);
    (void)CmServiceAbort(context, &handle);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    /* verify the signature just produced */
    spec.purpose = CM_KEY_PURPOSE_VERIFY;
    handleValue = 0;
    ret = CmServiceInit(context, keyUri, &spec, &handle);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = CmServiceUpdate(context, &handle, &message);
    if (ret != CM_SUCCESS) {
        (void)CmServiceAbort(context, &handle);
        return ret;
    }
    struct CmBlob sigIn = { signature.size, signature.data };
    struct CmBlob verifyOut = { 0, nullptr };
    ret = CmServiceFinish(context, &handle, &sigIn, &verifyOut);
    (void)CmServiceAbort(context, &handle);
    return ret;
}
} // namespace

/**
 * @tc.name: CmEngineInstallEccP256AndSign_001
 * @tc.desc: an ecc p256 p12 installs and completes a sign and verify roundtrip.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallEccP256AndSign_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    struct CmBlob appCert = { sizeof(g_eccP256P12CertInfo), const_cast<uint8_t *>(g_eccP256P12CertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    ASSERT_EQ(InstallP12Blob(&appCert, &appCertPwd, "EngineEcc", CM_CREDENTIAL_STORE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* the ecc import path is exercised through the sign and verify session */
    ASSERT_EQ(SignAndVerifyRoundtrip(&context, &keyUri), CM_SUCCESS);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineInstallEd25519AndSign_001
 * @tc.desc: an ed25519 p12 installs and completes a sign and verify roundtrip.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallEd25519AndSign_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    struct CmBlob appCert = { sizeof(g_ed25519P12CertInfo),
        const_cast<uint8_t *>(g_ed25519P12CertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    ASSERT_EQ(InstallP12Blob(&appCert, &appCertPwd, "EngineEd25519", CM_CREDENTIAL_STORE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* the certificate has no CN: the alias is used and the install still works */
    ASSERT_EQ(SignAndVerifyRoundtrip(&context, &keyUri), CM_SUCCESS);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineInstallSm2_001
 * @tc.desc: an sm2 p12 installs through the sm2 curve branch of the ecc import.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallSm2_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    struct CmBlob appCert = { sizeof(g_sm2PfxCertInfo), const_cast<uint8_t *>(g_sm2PfxCertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_sm2certPwd), const_cast<uint8_t *>(g_sm2certPwd) };
    ASSERT_EQ(InstallP12Blob(&appCert, &appCertPwd, "EngineSm2", CM_CREDENTIAL_STORE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_SUCCESS);

    /* the sm2 credential is visible as an installed credential */
    uint8_t certBuf[MAX_LEN_APP_CERT] = { 0 };
    struct CmBlob certBlob = { sizeof(certBuf), certBuf };
    struct CmBlob uriCopy = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmServiceGetAppCert(&context, CM_CREDENTIAL_STORE, &uriCopy, &certBlob), CM_SUCCESS);
    EXPECT_EQ((reinterpret_cast<struct AppCert *>(certBlob.data))->keyCount, 1u);
    CmFree(certBlob.data);

    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineInstallUnsupportedEd448_001
 * @tc.desc: a self consistent but unsupported ed448 key pair stops at the import switch.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallUnsupportedEd448_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(TEST_APPCERT_USER, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };

    /* the chain and the key match each other, so parsing succeeds and the
     * unsupported key type rejects the import before anything is stored */
    struct CmBlob certChain = { strlen(g_ed448PEMCertChain) + 1,
        reinterpret_cast<uint8_t *>(g_ed448PEMCertChain) };
    struct CmBlob privKey = { strlen(g_ed448PEMPrivKey) + 1,
        reinterpret_cast<uint8_t *>(g_ed448PEMPrivKey) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob certAlias = StringBlobOn("EngineEd448", aliasBuf, sizeof(aliasBuf));

    struct CmAppCertParam param = BuildAppCertParam(&certChain, &appCertPwd, &certAlias,
        CM_PRI_CREDENTIAL_STORE, INIT_INVALID_VALUE, CM_AUTH_STORAGE_LEVEL_EL1, CHAIN_KEY, &privKey);
    EXPECT_EQ(CmServicInstallAppCert(&context, &param, &keyUri), CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
}

/**
 * @tc.name: CmEngineInstallCredUserMapping_001
 * @tc.desc: credentials of a live front user resolve the service uid, unknown users fail.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallCredUserMapping_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    struct CmBlob goodPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t wrongPwdBuf[] = "12345678";
    struct CmBlob wrongPwd = { sizeof(wrongPwdBuf), wrongPwdBuf };

    /* the front user exists: the service uid is resolved and parsing continues
     * until the wrong password is rejected by the p12 parser; the uid mapping
     * relies on the bundle manager, which rejects a test process token, so the
     * install fails at the mapping and the failure contract is asserted */
    {
        struct CmContext context = BuildContext(TEST_APPCERT_FRONT_USER, TEST_APPCERT_UID);
        uint8_t uriBuf[MAX_LEN_URI] = { 0 };
        struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
        int32_t certManagerUid = -1;
        bool mapped = CmGetCertManagerAppUid(&certManagerUid,
            static_cast<int32_t>(TEST_APPCERT_FRONT_USER));
        int32_t expected = mapped ? CMR_ERROR_PASSWORD_IS_ERR : CM_FAILURE;
        EXPECT_EQ(InstallP12Blob(&appCert, &wrongPwd, "EngineFront", CM_CREDENTIAL_STORE,
            CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), expected);
    }

    /* a user without the certmanager app cannot be mapped to a service uid */
    {
        struct CmContext context = BuildContext(TEST_APPCERT_USER + 1100, TEST_APPCERT_UID);
        uint8_t uriBuf[MAX_LEN_URI] = { 0 };
        struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
        EXPECT_EQ(InstallP12Blob(&appCert, &goodPwd, "EngineGhost", CM_CREDENTIAL_STORE,
            CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CM_FAILURE);
    }
}

/**
 * @tc.name: CmEngineInstallKeyUriTooSmall_001
 * @tc.desc: a caller key uri buffer smaller than the constructed uri is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineAppCertTest, CmEngineInstallKeyUriTooSmall_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_APPCERT_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { 1, uriBuf }; /* smaller than any constructed uri */

    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    EXPECT_EQ(InstallP12Blob(&appCert, &appCertPwd, "EngineSmall", CM_CREDENTIAL_STORE,
        CM_AUTH_STORAGE_LEVEL_EL2, &context, &keyUri), CMR_ERROR_BUFFER_TOO_SMALL);
}
