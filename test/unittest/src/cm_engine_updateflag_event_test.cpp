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

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "cert_manager.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_service.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cert_manager_updateflag.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_user.h"
#include "cm_cert_property_rdb.h"
#include "cm_event_process.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_UE_USER = 8899;
constexpr uint32_t TEST_UE_UID = 889901;
constexpr uint32_t TEST_UE_OTHER_UID = 889902;
constexpr int NFTW_MAX_OPEN_FDS = 16;
constexpr uint32_t AUTH_UID_CAPACITY = 8;
/* mirrors the private constants of cert_manager_updateflag.c */
const char UPDATE_FLAG_DIR_PATH[] = "/data/service/el1/public/cert_manager_service/certificates/user";
const char UPDATE_FLAG_FILE_NAME[] = "update.flag";

/* roots owned by the SA that are created here only when missing */
const std::vector<std::string> NEEDED_ROOTS = {
    USER_CA_STORE,
    CREDNTIAL_STORE,
    PRI_CREDNTIAL_STORE,
    SYS_CREDNTIAL_STORE,
    "/data/service/el1/public/cert_manager_service/rdb",
};
std::vector<std::string> g_createdRoots;

/* rdb rows created directly by the cases below; the event cleanup only
 * removes rows of user ca certificates, so the rest is deleted here */
std::vector<std::string> g_trackedUris;

/* snapshot of the global update.flag state, restored after every case */
bool g_flagSnapshotted = false;
bool g_flagExisted = false;
uint8_t g_flagContent = 0;

/* isolated user subtrees touched by the cases below; the credential user 0
 * case only owns its private uid directory under the real user 0 store */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(USER_CA_STORE) + std::to_string(TEST_UE_USER),
        std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_UE_USER),
        std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_UE_USER),
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_UE_USER),
        std::string(CREDNTIAL_STORE) + std::to_string(TEST_UE_USER),
        std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_UE_USER),
        std::string(CREDNTIAL_STORE) + "0/" + std::to_string(TEST_UE_UID),
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

/* builds {storeRoot}/{userId}/{uid} with both levels created on demand */
std::string MakeStoreUidDir(const char *storeRoot, uint32_t userId, uint32_t uid)
{
    const std::string userIdDir = std::string(storeRoot) + std::to_string(userId);
    const std::string uidDir = userIdDir + "/" + std::to_string(uid);
    MakeDirOrExists(userIdDir);
    MakeDirOrExists(uidDir);
    return uidDir;
}

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}

void SnapshotUpdateFlag()
{
    g_flagExisted = (CmIsFileExist(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME) == CMR_OK);
    if (g_flagExisted) {
        uint8_t content = 0;
        uint32_t readSize = CmFileRead(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &content, sizeof(content));
        g_flagContent = (readSize == sizeof(content)) ? content : 0;
    }
    (void)CmFileRemove(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME);
    g_flagSnapshotted = true;
}

void RestoreUpdateFlag()
{
    if (!g_flagSnapshotted) {
        return;
    }
    if (g_flagExisted) {
        (void)CmFileWrite(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &g_flagContent, sizeof(g_flagContent));
    } else {
        (void)CmFileRemove(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME);
    }
    g_flagSnapshotted = false;
}

int CountRegularFiles(const std::string &dir)
{
    DIR *handle = opendir(dir.c_str());
    if (handle == nullptr) {
        return -1;
    }
    int count = 0;
    struct dirent *entry = nullptr;
    while ((entry = readdir(handle)) != nullptr) {
        if (entry->d_type == DT_REG) {
            count++;
        }
    }
    closedir(handle);
    return count;
}

void CreateEmptyFile(const std::string &path)
{
    FILE *fp = fopen(path.c_str(), "w");
    ASSERT_NE(fp, nullptr) << "create empty file failed for " << path;
    (void)fclose(fp);
}

void TrackRdbUri(const std::string &uri)
{
    g_trackedUris.emplace_back(uri);
}

void DeleteTrackedRdbRows()
{
    for (const auto &uri : g_trackedUris) {
        (void)DeleteCertProperty(uri.c_str());
    }
    g_trackedUris.clear();
}

/* inserts one row into the cert property table the way the install flows do */
int32_t InsertCertRow(const struct CmContext *context, const std::string &uri, const std::string &alias,
    uint32_t store, enum CmAuthStorageLevel level)
{
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    uint8_t subjectBuf[MAX_LEN_SUBJECT_NAME] = { 0 };
    const std::string subject = "CN=" + alias;
    if (strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strcpy_s(reinterpret_cast<char *>(subjectBuf), sizeof(subjectBuf), subject.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob uriBlob = { uri.size() + 1, uriBuf };
    struct CmBlob aliasBlob = { alias.size() + 1, aliasBuf };
    struct CmBlob subjectBlob = { subject.size() + 1, subjectBuf };
    struct CertPropertyOri propertyOri = { context, &uriBlob, &aliasBlob, &subjectBlob, store, level };
    return RdbInsertCertProperty(&propertyOri);
}

/* install one public (rsa2048 p12) credential through the service entry point */
int32_t InstallPublicCredential(const std::string &alias, struct CmContext *context, struct CmBlob *keyUri)
{
    struct CmBlob appCert = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };
    struct CmBlob emptyKey = { 0, nullptr };

    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_CREDENTIAL_STORE;
    param.userId = INIT_INVALID_VALUE;
    param.level = CM_AUTH_STORAGE_LEVEL_EL2;
    param.credFormat = FILE_P12;
    param.appCertPrivKey = &emptyKey;
    param.aliasFormat = DEFAULT_FORMAT;
    int32_t ret = CmServicInstallAppCert(context, &param, keyUri);
    if (ret == CM_SUCCESS) {
        TrackRdbUri(std::string(reinterpret_cast<char *>(keyUri->data)));
    }
    return ret;
}
} // namespace

class CmEngineUpdateEventTest : public testing::Test {
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
        ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
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
        RestoreUpdateFlag();
        for (const auto &subtree : UserSubtrees()) {
            RemoveTree(subtree);
        }
        DeleteTrackedRdbRows();
    }
};

/**
 * @tc.name: CmEngineConstructContextFromUri_001
 * @tc.desc: rebuild a context from a certificate uri and reject malformed ones.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineConstructContextFromUri_001, TestSize.Level0)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));

    /* a well formed user ca uri fills every context field */
    ASSERT_EQ(CmConstructContextFromUri("oh:t=c;o=EngineCtx;u=8899;a=889901", &context), CM_SUCCESS);
    EXPECT_EQ(context.userId, TEST_UE_USER);
    EXPECT_EQ(context.uid, TEST_UE_UID);
    EXPECT_STREQ(context.packageName, "EngineCtx");

    /* null pointers are rejected */
    EXPECT_EQ(CmConstructContextFromUri(nullptr, &context), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmConstructContextFromUri("oh:t=c;o=EngineCtx;u=8899;a=889901", nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* the scheme is checked before anything else */
    uint8_t garbage[] = "garbage";
    EXPECT_EQ(CmConstructContextFromUri(reinterpret_cast<char *>(garbage), &context), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* non numeric user field */
    EXPECT_EQ(CmConstructContextFromUri("oh:t=c;o=EngineCtx;u=abc;a=889901", &context),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* missing app field leaves the decoded uri incomplete */
    EXPECT_EQ(CmConstructContextFromUri("oh:t=c;o=EngineCtx;u=8899", &context), CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmEngineIsCertNeedBackup_001
 * @tc.desc: the config file decides whether a certificate still needs a backup.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineIsCertNeedBackup_001, TestSize.Level0)
{
    const std::string uri = "oh:t=c;o=EngineNeedBk;u=8899;a=889901";
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    bool needUpdate = false;

    /* null output pointer */
    EXPECT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &certUri, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* invalid uri blob */
    struct CmBlob emptyUri = { 0, nullptr };
    EXPECT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &emptyUri, &needUpdate), CMR_ERROR_INVALID_ARGUMENT);

    /* no config file: the certificate needs a backup */
    ASSERT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &certUri, &needUpdate), CM_SUCCESS);
    EXPECT_TRUE(needUpdate);

    /* a config file pointing at an existing backup: no update needed */
    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_UE_USER, TEST_UE_UID, confUidDir, sizeof(confUidDir)), CM_SUCCESS);
    const std::string confFile = std::string(confUidDir) + "/" + uri + CERT_CONFIG_FILE_SUFFIX;

    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_UE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    const std::string backupName = "manualbackup.0";
    const std::string backupPath = std::string(backupDir) + "/" + backupName;
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(backupDir, backupName.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(CmFileWrite(nullptr, confFile.c_str(), 0,
        reinterpret_cast<const uint8_t *>(backupPath.c_str()), backupPath.size()), CMR_OK);

    ASSERT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &certUri, &needUpdate), CM_SUCCESS);
    EXPECT_FALSE(needUpdate);

    /* the backup file disappears: update again */
    ASSERT_EQ(CmFileRemove(backupDir, backupName.c_str()), CMR_OK);
    ASSERT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &certUri, &needUpdate), CM_SUCCESS);
    EXPECT_TRUE(needUpdate);

    /* an empty config cannot be evaluated: update again */
    ASSERT_EQ(CmFileRemove(nullptr, confFile.c_str()), CMR_OK);
    CreateEmptyFile(confFile);
    ASSERT_EQ(IsCertNeedBackup(TEST_UE_USER, TEST_UE_UID, &certUri, &needUpdate), CM_SUCCESS);
    EXPECT_TRUE(needUpdate);
}

/**
 * @tc.name: CmEngineBackupUserCert_001
 * @tc.desc: backup converts a der certificate to pem and records the config file.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineBackupUserCert_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_UE_USER, TEST_UE_UID);
    struct CmBlob derCert = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };

    /* invalid arguments */
    struct CmBlob emptyBlob = { 0, nullptr };
    EXPECT_EQ(CmBackupUserCert(nullptr, &emptyBlob, &emptyBlob), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmBackupUserCert(&context, nullptr, &derCert), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmBackupUserCert(&context, &emptyBlob, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* unparsable certificate data */
    uint8_t garbage[] = "garbage";
    struct CmBlob garbageBlob = { sizeof(garbage) - 1, garbage };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), "oh:t=c;o=EngineBkDer;u=8899;a=889901"), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmBackupUserCert(&context, &certUri, &garbageBlob), CMR_ERROR_INVALID_CERT_FORMAT);

    /* a der certificate is converted to pem and stored with a config file */
    ASSERT_EQ(CmBackupUserCert(&context, &certUri, &derCert), CM_SUCCESS);

    char confPath[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfPath(TEST_UE_USER, TEST_UE_UID, &certUri, confPath, sizeof(confPath)), CM_SUCCESS);
    EXPECT_EQ(CmIsFileExist(nullptr, confPath), CMR_OK);

    char backupPath[CERT_MAX_PATH_LEN] = { 0 };
    uint32_t readSize = CmFileRead(nullptr, confPath, 0,
        reinterpret_cast<uint8_t *>(backupPath), sizeof(backupPath) - 1);
    EXPECT_GT(readSize, 0u);
    EXPECT_EQ(CmIsFileExist(nullptr, backupPath), CMR_OK);

    uint8_t head[16] = { 0 };
    readSize = CmFileRead(nullptr, backupPath, 0, head, sizeof(head));
    EXPECT_EQ(readSize, sizeof(head));
    EXPECT_EQ(memcmp(head, "-----BEGIN CERT", sizeof(head) - 1), 0);

    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_UE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    EXPECT_EQ(CountRegularFiles(backupDir), 1);

    /* a pem certificate passes through without conversion */
    struct CmBlob pemCert = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };
    uint8_t pemUriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(pemUriBuf), sizeof(pemUriBuf),
        "oh:t=c;o=EngineBkPem;u=8899;a=889901"), EOK);
    struct CmBlob pemUri = { sizeof(pemUriBuf), pemUriBuf };
    ASSERT_EQ(CmBackupUserCert(&context, &pemUri, &pemCert), CM_SUCCESS);
    EXPECT_EQ(CountRegularFiles(backupDir), 2);
}

/**
 * @tc.name: CmEngineReadCertData_001
 * @tc.desc: read user certificate data from the store and reject bad requests.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineReadCertData_001, TestSize.Level0)
{
    const std::string uri = "oh:t=c;o=EngineRd;u=8899;a=889901";
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_UE_USER, TEST_UE_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    struct CmContext context = BuildContext(TEST_UE_USER, TEST_UE_UID);

    /* the stored data is returned as-is */
    struct CmBlob certData = { 0, nullptr };
    ASSERT_EQ(CmReadCertData(CM_USER_TRUSTED_STORE, &context, &certUri, &certData), CM_SUCCESS);
    EXPECT_EQ(certData.size, strlen(g_certData06));
    EXPECT_EQ(memcmp(certData.data, pemData, strlen(g_certData06)), 0);
    CMFree(certData.data);

    /* a missing certificate file is an error */
    uint8_t missBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(missBuf), sizeof(missBuf),
        "oh:t=c;o=EngineRdMiss;u=8899;a=889901"), EOK);
    struct CmBlob missUri = { sizeof(missBuf), missBuf };
    struct CmBlob missData = { 0, nullptr };
    EXPECT_NE(CmReadCertData(CM_USER_TRUSTED_STORE, &context, &missUri, &missData), CM_SUCCESS);

    /* an unknown store type has no root path */
    EXPECT_EQ(CmReadCertData(99, &context, &certUri, &missData), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
}

/**
 * @tc.name: CmEngineBackupAllSaUserCerts_001
 * @tc.desc: the one shot update flag drives the backup of all user certificates.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineBackupAllSaUserCerts_001, TestSize.Level0)
{
    SnapshotUpdateFlag();
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_UE_USER, TEST_UE_UID);
    const uint8_t *derData = reinterpret_cast<const uint8_t *>(g_certData01);

    const std::string uri1 = "oh:t=c;o=EngineFlagOne;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri1.c_str(), 0, derData, sizeof(g_certData01)), CMR_OK);
    const std::string uri2 = "oh:t=c;o=EngineFlagTwo;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri2.c_str(), 0, derData, sizeof(g_certData01)), CMR_OK);
    const std::string uri3 = "oh:t=c;o=EngineFlagThree;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri3.c_str(), 0, derData, sizeof(g_certData01)), CMR_OK);

    char confDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_UE_USER, TEST_UE_UID, confDir, sizeof(confDir)), CM_SUCCESS);

    /* an already done flag skips the whole migration */
    const uint8_t alreadyUpdated = '1';
    ASSERT_EQ(CmFileWrite(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &alreadyUpdated, sizeof(alreadyUpdated)),
        CMR_OK);
    ASSERT_EQ(CmBackupAllSaUserCerts(), CM_SUCCESS);
    const std::string conf1 = std::string(confDir) + "/" + uri1 + CERT_CONFIG_FILE_SUFFIX;
    EXPECT_NE(CmIsFileExist(nullptr, conf1.c_str()), CMR_OK);

    /* without the flag every user certificate is backed up and the flag is set */
    ASSERT_EQ(CmFileRemove(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME), CMR_OK);
    ASSERT_EQ(CmBackupAllSaUserCerts(), CM_SUCCESS);
    const std::string conf2 = std::string(confDir) + "/" + uri2 + CERT_CONFIG_FILE_SUFFIX;
    EXPECT_EQ(CmIsFileExist(nullptr, conf2.c_str()), CMR_OK);

    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_UE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    EXPECT_GE(CountRegularFiles(backupDir), 1);

    uint8_t flag = 0;
    uint32_t readSize = CmFileRead(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &flag, sizeof(flag));
    EXPECT_EQ(readSize, sizeof(flag));
    EXPECT_EQ(flag, '1');

    /* the migration run above already backed up every certificate of the user
       (including uri3): prove the next run is a no-op by the untouched backup set */
    const uint32_t backupCount = CountRegularFiles(backupDir);
    ASSERT_EQ(CmBackupAllSaUserCerts(), CM_SUCCESS);
    EXPECT_EQ(CountRegularFiles(backupDir), backupCount);

    uint8_t flagAgain = 0;
    readSize = CmFileRead(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &flagAgain, sizeof(flagAgain));
    EXPECT_EQ(readSize, sizeof(flagAgain));
    EXPECT_EQ(flagAgain, '1');
}

/**
 * @tc.name: CmEngineSetStatusBackupCert_001
 * @tc.desc: enabling a certificate creates the backup, disabling removes it again.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineSetStatusBackupCert_001, TestSize.Level0)
{
    const std::string uri = "oh:t=c;o=EngineStatus;u=8899;a=889901";
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_UE_USER, TEST_UE_UID);
    const uint8_t *derData = reinterpret_cast<const uint8_t *>(g_certData01);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri.c_str(), 0, derData, sizeof(g_certData01)), CMR_OK);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    struct CmContext context = BuildContext(TEST_UE_USER, TEST_UE_UID);

    char confDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_UE_USER, TEST_UE_UID, confDir, sizeof(confDir)), CM_SUCCESS);
    const std::string confFile = std::string(confDir) + "/" + uri + CERT_CONFIG_FILE_SUFFIX;
    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_UE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);

    /* invalid input combination for the remove helper */
    EXPECT_EQ(CmRemoveBackupUserCert(nullptr, nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* an unknown status changes nothing */
    ASSERT_EQ(CmSetStatusBackupCert(&context, &certUri, CM_USER_TRUSTED_STORE, 42), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);

    /* enabling backs the certificate up */
    ASSERT_EQ(CmSetStatusBackupCert(&context, &certUri, CM_USER_TRUSTED_STORE, CERT_STATUS_ENANLED), CM_SUCCESS);
    EXPECT_EQ(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);
    EXPECT_EQ(CountRegularFiles(backupDir), 1);

    /* enabling twice is a no-op because no update is needed anymore */
    ASSERT_EQ(CmSetStatusBackupCert(&context, &certUri, CM_USER_TRUSTED_STORE, CERT_STATUS_ENANLED), CM_SUCCESS);
    EXPECT_EQ(CountRegularFiles(backupDir), 1);

    /* disabling removes the config and the backup file */
    ASSERT_EQ(CmSetStatusBackupCert(&context, &certUri, CM_USER_TRUSTED_STORE, CERT_STATUS_DISABLED), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);
    EXPECT_EQ(CountRegularFiles(backupDir), 0);

    /* enabling a certificate whose file is gone fails */
    ASSERT_EQ(CmFileRemove(uidDir.c_str(), uri.c_str()), CMR_OK);
    EXPECT_EQ(CmSetStatusBackupCert(&context, &certUri, CM_USER_TRUSTED_STORE, CERT_STATUS_ENANLED), CM_FAILURE);
}

/**
 * @tc.name: CmEngineDeleteProcessInfoUser_001
 * @tc.desc: the user removed event wipes the whole user subtree including backups.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineDeleteProcessInfoUser_001, TestSize.Level0)
{
    /* user ca certificate with a property row and a backup */
    const std::string caUri = "oh:t=c;o=EngineEvCa;u=8899;a=889901";
    const std::string caUidDir = MakeStoreUidDir(USER_CA_STORE, TEST_UE_USER, TEST_UE_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(caUidDir.c_str(), caUri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    struct CmContext context = BuildContext(TEST_UE_USER, TEST_UE_UID);
    ASSERT_EQ(InsertCertRow(&context, caUri, "EngineEvCa", CM_USER_TRUSTED_STORE, CM_AUTH_STORAGE_LEVEL_EL1),
        CM_SUCCESS);

    uint8_t caUriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(caUriBuf), sizeof(caUriBuf), caUri.c_str()), EOK);
    struct CmBlob caUriBlob = { sizeof(caUriBuf), caUriBuf };
    struct CmBlob caCertData = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };
    ASSERT_EQ(CmBackupUserCert(&context, &caUriBlob, &caCertData), CM_SUCCESS);

    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(caUri.c_str(), &prop), CM_SUCCESS);
    EXPECT_STRNE(prop.uri, "");

    /* private credential with a property row; the event cleanup keeps its row */
    const std::string priUri = "oh:t=ak;o=EngineEvPri;u=8899;a=889901";
    const std::string priUidDir = MakeStoreUidDir(PRI_CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    ASSERT_EQ(CmFileWrite(priUidDir.c_str(), priUri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(InsertCertRow(&context, priUri, "EngineEvPri", CM_PRI_CREDENTIAL_STORE, CM_AUTH_STORAGE_LEVEL_EL1),
        CM_SUCCESS);
    TrackRdbUri(priUri);

    /* public and system credentials without rows */
    const std::string pubUri = "oh:t=ak;o=EngineEvPub;u=8899;a=889901";
    const std::string pubUidDir = MakeStoreUidDir(CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    ASSERT_EQ(CmFileWrite(pubUidDir.c_str(), pubUri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    const std::string sysUri = "oh:t=sk;o=EngineEvSys;u=8899;a=889901";
    const std::string sysUidDir = MakeStoreUidDir(SYS_CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    ASSERT_EQ(CmFileWrite(sysUidDir.c_str(), sysUri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    /* the user removed event uses the invalid uid marker */
    struct CmContext userEvent = BuildContext(TEST_UE_USER, INVALID_VALUE);
    ASSERT_EQ(CmDeleteProcessInfo(&userEvent), CM_SUCCESS);

    /* every user ca file, row, backup and config directory is gone */
    EXPECT_NE(CmIsFileExist(caUidDir.c_str(), caUri.c_str()), CMR_OK);
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(caUri.c_str(), &prop), CM_SUCCESS);
    EXPECT_STREQ(prop.uri, "");
    EXPECT_NE(CmIsDirExist((std::string(USER_CA_STORE) + std::to_string(TEST_UE_USER)).c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist((std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_UE_USER)).c_str()),
        CMR_OK);
    EXPECT_NE(CmIsDirExist((std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_UE_USER)).c_str()),
        CMR_OK);

    /* all credential stores of the user are empty again */
    EXPECT_NE(CmIsDirExist((std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_UE_USER)).c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist((std::string(CREDNTIAL_STORE) + std::to_string(TEST_UE_USER)).c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist((std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_UE_USER)).c_str()), CMR_OK);

    /* the private credential row outlives the event cleanup and is removed by TearDown */
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(priUri.c_str(), &prop), CM_SUCCESS);
    EXPECT_STRNE(prop.uri, "");
}

/**
 * @tc.name: CmEngineDeleteProcessInfoPackage_001
 * @tc.desc: the package removed event only deletes data of the calling uid.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineDeleteProcessInfoPackage_001, TestSize.Level0)
{
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    const uint32_t pemLen = strlen(g_certData06);

    /* private credentials of the deleted uid and of another uid */
    const std::string priSelfDir = MakeStoreUidDir(PRI_CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    const std::string priSelfUri = "oh:t=ak;o=EvPriSelf;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(priSelfDir.c_str(), priSelfUri.c_str(), 0, pemData, pemLen), CMR_OK);
    const std::string priOtherDir = MakeStoreUidDir(PRI_CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_OTHER_UID);
    const std::string priOtherUri = "oh:t=ak;o=EvPriOther;u=8899;a=889902";
    ASSERT_EQ(CmFileWrite(priOtherDir.c_str(), priOtherUri.c_str(), 0, pemData, pemLen), CMR_OK);

    /* system credential of the deleted uid */
    const std::string sysSelfDir = MakeStoreUidDir(SYS_CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    const std::string sysSelfUri = "oh:t=sk;o=EvSysSelf;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(sysSelfDir.c_str(), sysSelfUri.c_str(), 0, pemData, pemLen), CMR_OK);

    /* public credential of the deleted uid with an authlist directory */
    const std::string pubSelfDir = MakeStoreUidDir(CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_UID);
    const std::string pubSelfUri = "oh:t=ak;o=EvPubSelf;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(pubSelfDir.c_str(), pubSelfUri.c_str(), 0, pemData, pemLen), CMR_OK);
    const std::string authListDir = pubSelfDir + "/authlist";
    MakeDirOrExists(authListDir);
    ASSERT_EQ(CmFileWrite(authListDir.c_str(), "dummy.auth", 0, pemData, pemLen), CMR_OK);

    /* public credential of another uid: only its authlist is inspected */
    const std::string pubOtherDir = MakeStoreUidDir(CREDNTIAL_STORE, TEST_UE_USER, TEST_UE_OTHER_UID);
    const std::string pubOtherUri = "oh:t=ak;o=EvPubOther;u=8899;a=889902";
    ASSERT_EQ(CmFileWrite(pubOtherDir.c_str(), pubOtherUri.c_str(), 0, pemData, pemLen), CMR_OK);

    struct CmContext packageEvent = BuildContext(TEST_UE_USER, TEST_UE_UID);
    ASSERT_EQ(CmDeleteProcessInfo(&packageEvent), CM_SUCCESS);

    /* the deleted uid lost everything, including its authlist directory */
    EXPECT_NE(CmIsDirExist(priSelfDir.c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist(sysSelfDir.c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist(pubSelfDir.c_str()), CMR_OK);

    /* the other uid keeps its credentials */
    EXPECT_EQ(CmIsFileExist(priOtherDir.c_str(), priOtherUri.c_str()), CMR_OK);
    EXPECT_EQ(CmIsFileExist(pubOtherDir.c_str(), pubOtherUri.c_str()), CMR_OK);
}

/**
 * @tc.name: CmEngineDeleteProcessInfoGrant_001
 * @tc.desc: removing the grantee package revokes its grants but keeps the credential.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUpdateEventTest, CmEngineDeleteProcessInfoGrant_001, TestSize.Level0)
{
    MockHapToken mockHap;
    struct CmContext context = BuildContext(0, TEST_UE_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(InstallPublicCredential("EngineEvGrant", &context, &keyUri), CM_SUCCESS);

    /* grant access to another app */
    uint8_t authUriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob authUri = { sizeof(authUriBuf), authUriBuf };
    ASSERT_EQ(CmServiceGrantAppCertificate(&context, &keyUri, TEST_UE_OTHER_UID, &authUri), CM_SUCCESS);

    uint32_t appUids[AUTH_UID_CAPACITY] = { 0 };
    struct CmAppUidList appUidList = { AUTH_UID_CAPACITY, appUids };
    ASSERT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, 1u);

    /* the grantee package is removed */
    struct CmContext granteeEvent = BuildContext(0, TEST_UE_OTHER_UID);
    ASSERT_EQ(CmDeleteProcessInfo(&granteeEvent), CM_SUCCESS);

    /* the credential itself survives, only the grant is gone */
    EXPECT_EQ(CmIsFileExist((std::string(CREDNTIAL_STORE) + "0/" + std::to_string(TEST_UE_UID)).c_str(),
        reinterpret_cast<char *>(uriBuf)), CMR_OK);
    appUids[0] = 0;
    appUidList.appUidCount = AUTH_UID_CAPACITY;
    ASSERT_EQ(CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList), CM_SUCCESS);
    EXPECT_EQ(appUidList.appUidCount, 0u);

    /* remove the credential again */
    ASSERT_EQ(CmRemoveAppCert(&context, &keyUri, CM_CREDENTIAL_STORE), CM_SUCCESS);
}
