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

#include <cstring>
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "cert_manager.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_storage.h"
#include "cm_cert_data_user.h"
#include "cm_cert_property_rdb.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_CM_USER = 8899;
constexpr uint32_t TEST_CM_UID = 889901;
constexpr uint32_t TEST_CM_OTHER_UID = 889902;
constexpr int NFTW_MAX_OPEN_FDS = 16;
/* base64url length of a sha256 digest: ceil(256 bits / 6) + terminator */
/* the base64url encoding of a sha256 digest is 44 chars: the final pad char is 'A' */
constexpr uint32_t BASE64URL_SHA256_LEN = 44;
/* number of files needed to reach the store wide certificate cap */
constexpr uint32_t MAX_CERT_FILE_COUNT = 256;

/* exported by cert_manager.c but only declared locally by its callers */
extern "C" int32_t CmBackupRemove(uint32_t userId, const char *path, const struct CmBlob *certUri);

/* roots owned by the SA that are created here only when missing */
const std::vector<std::string> NEEDED_ROOTS = {
    USER_CA_STORE,
    CREDNTIAL_STORE,
    PRI_CREDNTIAL_STORE,
    SYS_CREDNTIAL_STORE,
    "/data/service/el1/public/cert_manager_service/rdb",
};
std::vector<std::string> g_createdRoots;

/* rdb rows created directly by the cases below; rows deleted by the remove
 * flows themselves are not tracked here */
std::vector<std::string> g_trackedUris;

/* isolated user subtrees touched by the cases below */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(USER_CA_STORE) + std::to_string(TEST_CM_USER),
        std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_CM_USER),
        std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_CM_USER),
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_CM_USER),
        std::string(CREDNTIAL_STORE) + std::to_string(TEST_CM_USER),
        std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_CM_USER),
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

void CreateEmptyFile(const std::string &path)
{
    FILE *fp = fopen(path.c_str(), "w");
    ASSERT_NE(fp, nullptr) << "create empty file failed for " << path;
    (void)fclose(fp);
}

/* builds the config + backup pair the remove helpers expect */
void MakeConfigAndBackup(const std::string &uri, const std::string &backupName, std::string &confFile)
{
    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_CM_USER, TEST_CM_UID, confUidDir, sizeof(confUidDir)), CM_SUCCESS);
    confFile = std::string(confUidDir) + "/" + uri + CERT_CONFIG_FILE_SUFFIX;

    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_CM_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    const std::string backupPath = std::string(backupDir) + "/" + backupName;
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(backupDir, backupName.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(CmFileWrite(nullptr, confFile.c_str(), 0,
        reinterpret_cast<const uint8_t *>(backupPath.c_str()), backupPath.size()), CMR_OK);
}
} // namespace

class CmEngineCertMgrTest : public testing::Test {
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
        for (const auto &subtree : UserSubtrees()) {
            RemoveTree(subtree);
        }
        DeleteTrackedRdbRows();
    }
};

/**
 * @tc.name: CmEngineInitialize_001
 * @tc.desc: the one shot initialization prepares huks, the store and the rdb tables.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineInitialize_001, TestSize.Level0)
{
    /* the first call initializes everything, a second call is a no-op */
    ASSERT_EQ(CertManagerInitialize(), CM_SUCCESS);
    EXPECT_EQ(CertManagerInitialize(), CM_SUCCESS);
    EXPECT_EQ(CmIsDirExist(CERT_DIR), CMR_OK);
}

/**
 * @tc.name: CmEngineGetUri_001
 * @tc.desc: extract the file name of a path and reject malformed input.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineGetUri_001, TestSize.Level0)
{
    uint8_t uriBuf[CM_MAX_FILE_NAME_LEN] = { 0 };
    struct CmBlob uriBlob = { sizeof(uriBuf), uriBuf };

    /* null pointers are rejected */
    const std::string filePath = "/data/service/certificates/oh:t=c;o=GetUri;u=8899;a=889901";
    EXPECT_EQ(CmGetUri(nullptr, &uriBlob), CM_FAILURE);
    EXPECT_EQ(CmGetUri(filePath.c_str(), nullptr), CM_FAILURE);
    struct CmBlob noData = { sizeof(uriBuf), nullptr };
    EXPECT_EQ(CmGetUri(filePath.c_str(), &noData), CM_FAILURE);

    /* empty and oversized paths are rejected */
    EXPECT_EQ(CmGetUri("", &uriBlob), CMR_ERROR_INVALID_ARGUMENT);
    const std::string longPath(CM_MAX_FILE_NAME_LEN + 10, 'x');
    EXPECT_EQ(CmGetUri(longPath.c_str(), &uriBlob), CMR_ERROR_INVALID_ARGUMENT);

    /* the basename behind the last slash becomes the uri */
    ASSERT_EQ(CmGetUri(filePath.c_str(), &uriBlob), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(uriBlob.data), "oh:t=c;o=GetUri;u=8899;a=889901");
    EXPECT_EQ(uriBlob.size, strlen("oh:t=c;o=GetUri;u=8899;a=889901") + 1);

    /* a path without any slash is taken as a whole */
    ASSERT_EQ(CmGetUri("plainname", &uriBlob), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(uriBlob.data), "plainname");
    EXPECT_EQ(uriBlob.size, strlen("plainname") + 1);

    /* a trailing slash yields an empty uri */
    ASSERT_EQ(CmGetUri("/data/dir/", &uriBlob), CM_SUCCESS);
    EXPECT_EQ(uriBlob.size, 1u);
    EXPECT_EQ(uriBuf[0], 0);

    /* a too small output buffer is reported */
    struct CmBlob small = { 2, uriBuf };
    EXPECT_EQ(CmGetUri(filePath.c_str(), &small), CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: CmEngineFindCertFileNameByUri_001
 * @tc.desc: locate a stored certificate file by its uri in the supported stores.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineFindCertFileNameByUri_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uri = "oh:t=c;o=EngineFind;u=8899;a=889901";
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    /* the matcher compares the blob against the file names byte by byte:
       the size must cover exactly the stored uri string */
    struct CmBlob certUri = { uri.size() + 1, uriBuf };

    char pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    struct CmMutableBlob path = { sizeof(pathBuf), reinterpret_cast<uint8_t *>(pathBuf) };

    /* null pointers are rejected */
    EXPECT_EQ(CertManagerFindCertFileNameByUri(nullptr, &certUri, CM_USER_TRUSTED_STORE, false, &path),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, nullptr, CM_USER_TRUSTED_STORE, false, &path),
        CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob noData = { sizeof(uriBuf), nullptr };
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &noData, CM_USER_TRUSTED_STORE, false, &path),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &certUri, CM_USER_TRUSTED_STORE, false, nullptr),
        CMR_ERROR_NULL_POINTER);

    /* an unknown store has no root path */
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &certUri, 99, false, &path),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* the stored file is found by its full uri and by a uri prefix */
    ASSERT_EQ(CertManagerFindCertFileNameByUri(&context, &certUri, CM_USER_TRUSTED_STORE, false, &path), CM_SUCCESS);
    EXPECT_EQ(strlen(pathBuf) > 0, true);

    uint8_t prefix[] = "oh:t=";
    struct CmBlob prefixUri = { sizeof(prefix) - 1, prefix };
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &prefixUri, CM_USER_TRUSTED_STORE, false, &path),
        CM_SUCCESS);

    /* an unknown uri is not found */
    uint8_t missBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(missBuf), sizeof(missBuf),
        "oh:t=c;o=EngineFindMiss;u=8899;a=889901"), EOK);
    struct CmBlob missUri = { strlen("oh:t=c;o=EngineFindMiss;u=8899;a=889901") + 1, missBuf };
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &missUri, CM_USER_TRUSTED_STORE, false, &path),
        CMR_ERROR_NOT_FOUND);

    /* the gm system store is absent on regular builds */
    EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &certUri, CM_SYSTEM_TRUSTED_STORE, true, &path),
        CMR_ERROR_NOT_FOUND);

    /* the plain system store is enumerated but the uri does not match */
    if (CmIsDirExist(SYSTEM_CA_STORE) == CMR_OK) {
        EXPECT_EQ(CertManagerFindCertFileNameByUri(&context, &certUri, CM_SYSTEM_TRUSTED_STORE, false, &path),
            CMR_ERROR_NOT_FOUND);
    }
}

/**
 * @tc.name: CmEngineCheckCertCount_001
 * @tc.desc: the store wide certificate counter validates its arguments and the store type.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineCheckCertCount_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    uint32_t certCount = 0;

    /* null pointers are rejected */
    EXPECT_EQ(CmCheckCertCount(nullptr, CM_USER_TRUSTED_STORE, "enginecnt000"), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmCheckCertCount(&context, CM_USER_TRUSTED_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetCertOrCredCount(nullptr, CM_USER_TRUSTED_STORE, &certCount), CMR_ERROR_NULL_POINTER);
    EXPECT_EQ(GetCertOrCredCount(&context, CM_USER_TRUSTED_STORE, nullptr), CMR_ERROR_NULL_POINTER);

    /* an unknown store cannot be counted */
    EXPECT_EQ(CmCheckCertCount(&context, 99, "enginecnt000"), CM_FAILURE);

    /* an empty store stays below the cap */
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    ASSERT_EQ(CmCheckCertCount(&context, CM_USER_TRUSTED_STORE, "enginecnt000"), CM_SUCCESS);

    /* a single file is counted and still accepted */
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), "enginecnt000", 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(GetCertOrCredCount(&context, CM_USER_TRUSTED_STORE, &certCount), CM_SUCCESS);
    EXPECT_EQ(certCount, 1u);
    EXPECT_EQ(CmCheckCertCount(&context, CM_USER_TRUSTED_STORE, "enginecnt001"), CM_SUCCESS);
}

/**
 * @tc.name: CmEngineCheckCertCountMax_001
 * @tc.desc: at the certificate cap only overwrites of known files are allowed.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineCheckCertCountMax_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    const std::string overwriteUri = "oh:t=c;o=EngineOvr;u=8899;a=889901";
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);

    /* fill the store up to the cap: 255 numbered files plus the overwrite target */
    for (uint32_t i = 0; i < MAX_CERT_FILE_COUNT - 1; i++) {
        const std::string name = "enginecnt" + std::to_string(i);
        ASSERT_EQ(CmFileWrite(uidDir.c_str(), name.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK)
            << "fill file failed at " << i;
    }
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), overwriteUri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    uint32_t certCount = 0;
    ASSERT_EQ(GetCertOrCredCount(&context, CM_USER_TRUSTED_STORE, &certCount), CM_SUCCESS);
    EXPECT_EQ(certCount, MAX_CERT_FILE_COUNT);

    /* an existing file may still be overwritten, a new file is rejected */
    EXPECT_EQ(CmCheckCertCount(&context, CM_USER_TRUSTED_STORE, overwriteUri.c_str()), CM_SUCCESS);
    EXPECT_EQ(CmCheckCertCount(&context, CM_USER_TRUSTED_STORE, "enginecnt999"), CM_FAILURE);

    /* the write helper enforces the same rule */
    char pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(strcpy_s(pathBuf, sizeof(pathBuf), uidDir.c_str()), EOK);
    struct CmMutableBlob pathBlob = { strlen(pathBuf) + 1, reinterpret_cast<uint8_t *>(pathBuf) };
    struct CmBlob userCert = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };

    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineOvr"), EOK);
    struct CmBlob certAlias = { strlen("EngineOvr") + 1, aliasBuf };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    ASSERT_EQ(CmWriteUserCert(&context, &pathBlob, &userCert, &certAlias, &certUri), CM_SUCCESS);

    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineNew"), EOK);
    struct CmBlob newAlias = { strlen("EngineNew") + 1, aliasBuf };
    struct CmBlob newUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmWriteUserCert(&context, &pathBlob, &userCert, &newAlias, &newUri),
        CMR_ERROR_MAX_CERT_COUNT_REACHED);
}

/**
 * @tc.name: CmEngineWriteUserCert_001
 * @tc.desc: write a user certificate below its uri and reject oversized input.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineWriteUserCert_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    char pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(strcpy_s(pathBuf, sizeof(pathBuf), uidDir.c_str()), EOK);
    struct CmMutableBlob pathBlob = { strlen(pathBuf) + 1, reinterpret_cast<uint8_t *>(pathBuf) };
    struct CmBlob userCert = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };

    /* an alias beyond the maximum length is rejected */
    uint8_t longAliasBuf[MAX_LEN_CERT_ALIAS + 4] = { 0 };
    (void)memset_s(longAliasBuf, sizeof(longAliasBuf), 'A', sizeof(longAliasBuf) - 1);
    struct CmBlob longAlias = { sizeof(longAliasBuf), longAliasBuf };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmWriteUserCert(&context, &pathBlob, &userCert, &longAlias, &certUri),
        CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT);

    /* a too small uri buffer is rejected */
    uint8_t tinyBuf[4] = { 0 };
    struct CmBlob tinyUri = { sizeof(tinyBuf), tinyBuf };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineWrite"), EOK);
    struct CmBlob certAlias = { strlen("EngineWrite") + 1, aliasBuf };
    EXPECT_EQ(CmWriteUserCert(&context, &pathBlob, &userCert, &certAlias, &tinyUri), CMR_ERROR_BUFFER_TOO_SMALL);

    /* a regular write stores the certificate below its uri */
    ASSERT_EQ(CmWriteUserCert(&context, &pathBlob, &userCert, &certAlias, &certUri), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(certUri.data), "oh:t=c;o=EngineWrite;u=8899;a=889901");
    EXPECT_EQ(certUri.size, strlen("oh:t=c;o=EngineWrite;u=8899;a=889901") + 1);
    EXPECT_EQ(CmIsFileExist(uidDir.c_str(), reinterpret_cast<char *>(certUri.data)), CMR_OK);

    uint8_t readBack[sizeof(g_certData06)] = { 0 };
    uint32_t readSize = CmFileRead(uidDir.c_str(), reinterpret_cast<char *>(certUri.data), 0,
        readBack, sizeof(readBack));
    EXPECT_EQ(readSize, strlen(g_certData06) + 1);
    EXPECT_EQ(memcmp(readBack, g_certData06, strlen(g_certData06)), 0);

    /* a path outside the created directories cannot be written */
    const std::string missingDir = uidDir + "/missing";
    ASSERT_EQ(strcpy_s(pathBuf, sizeof(pathBuf), missingDir.c_str()), EOK);
    struct CmMutableBlob missingBlob = { strlen(pathBuf) + 1, reinterpret_cast<uint8_t *>(pathBuf) };
    struct CmBlob againUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmWriteUserCert(&context, &missingBlob, &userCert, &certAlias, &againUri),
        CMR_ERROR_WRITE_FILE_FAIL);
}

/**
 * @tc.name: CmEngineGetObjNameFromCertData_001
 * @tc.desc: derive the stored object name from the alias or the certificate data.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineGetObjNameFromCertData_001, TestSize.Level0)
{
    struct CmBlob certData = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineObjAlias"), EOK);
    struct CmBlob certAlias = { strlen("EngineObjAlias") + 1, aliasBuf };
    uint8_t nameBuf1[MAX_LEN_BASE64URL_SHA256 + 1] = { 0 };
    struct CmBlob objectName1 = { sizeof(nameBuf1), nameBuf1 };
    uint8_t nameBuf2[MAX_LEN_BASE64URL_SHA256 + 1] = { 0 };
    struct CmBlob objectName2 = { sizeof(nameBuf2), nameBuf2 };

    /* invalid input combinations */
    struct CmBlob noData = { 0, nullptr };
    EXPECT_EQ(GetObjNameFromCertData(&noData, &certAlias, &objectName1, DEFAULT_FORMAT), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetObjNameFromCertData(&certData, &noData, &objectName1, DEFAULT_FORMAT), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetObjNameFromCertData(&certData, &certAlias, nullptr, DEFAULT_FORMAT), CMR_ERROR_INVALID_ARGUMENT);

    /* the default format keeps the alias as the object name */
    ASSERT_EQ(GetObjNameFromCertData(&certData, &certAlias, &objectName1, DEFAULT_FORMAT), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(objectName1.data), "EngineObjAlias");
    EXPECT_EQ(objectName1.size, strlen("EngineObjAlias") + 1);

    /* a too small object name buffer is rejected */
    uint8_t tinyBuf[2] = { 0 };
    struct CmBlob tinyName = { sizeof(tinyBuf), tinyBuf };
    EXPECT_EQ(GetObjNameFromCertData(&certData, &certAlias, &tinyName, DEFAULT_FORMAT), CMR_ERROR_MEM_OPERATION_COPY);

    /* the sha256 format hashes the alias into a base64url string */
    ASSERT_EQ(GetObjNameFromCertData(&certData, &certAlias, &objectName1, SHA256_FORMAT), CM_SUCCESS);
    EXPECT_EQ(strlen(reinterpret_cast<char *>(objectName1.data)), BASE64URL_SHA256_LEN);
    EXPECT_STRNE(reinterpret_cast<char *>(objectName1.data), "EngineObjAlias");
    ASSERT_EQ(GetObjNameFromCertData(&certData, &certAlias, &objectName2, SHA256_FORMAT), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(objectName1.data), reinterpret_cast<char *>(objectName2.data));

    /* an empty alias derives the object name from the certificate data */
    uint8_t emptyAliasBuf[1] = { 0 };
    struct CmBlob emptyAlias = { sizeof(emptyAliasBuf), emptyAliasBuf };
    ASSERT_EQ(GetObjNameFromCertData(&certData, &emptyAlias, &objectName2, DEFAULT_FORMAT), CM_SUCCESS);
    EXPECT_EQ(strlen(reinterpret_cast<char *>(objectName2.data)), BASE64URL_SHA256_LEN);
    /* the hashed alias differs from the hashed certificate data */
    EXPECT_STRNE(reinterpret_cast<char *>(objectName1.data), reinterpret_cast<char *>(objectName2.data));
    ASSERT_EQ(GetObjNameFromCertData(&certData, &emptyAlias, &objectName1, DEFAULT_FORMAT), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(objectName1.data), reinterpret_cast<char *>(objectName2.data));

    /* a too small object name buffer is rejected for the empty alias as well */
    EXPECT_EQ(GetObjNameFromCertData(&certData, &emptyAlias, &tinyName, DEFAULT_FORMAT), CMR_ERROR_MEM_OPERATION_COPY);
}

/**
 * @tc.name: CmEngineGetDisplayNameByURI_001
 * @tc.desc: the display name comes from the rdb row or falls back to the object.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineGetDisplayNameByURI_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uri = "oh:t=c;o=EngineDisp;u=8899;a=889901";
    ASSERT_EQ(InsertCertRow(&context, uri, "EngineDisp", CM_USER_TRUSTED_STORE, CM_AUTH_STORAGE_LEVEL_EL1),
        CM_SUCCESS);
    TrackRdbUri(uri);

    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    struct CmBlob uriBlob = { sizeof(uriBuf), uriBuf };
    uint8_t nameBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob displayName = { sizeof(nameBuf), nameBuf };

    /* invalid input combinations */
    struct CmBlob noData = { 0, nullptr };
    EXPECT_EQ(CmGetDisplayNameByURI(&noData, "object", &displayName), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetDisplayNameByURI(&uriBlob, nullptr, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob noName = { 0, nullptr };
    EXPECT_EQ(CmGetDisplayNameByURI(&uriBlob, "object", &noName), CMR_ERROR_INVALID_ARGUMENT);

    /* the uri must be null terminated */
    struct CmBlob noTerm = { uri.size(), uriBuf };
    EXPECT_EQ(CmGetDisplayNameByURI(&noTerm, "object", &displayName), CMR_ERROR_INVALID_ARGUMENT);

    /* a row resolves the display name to the stored alias */
    ASSERT_EQ(CmGetDisplayNameByURI(&uriBlob, "EngineDispObject", &displayName), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(displayName.data), "EngineDisp");
    EXPECT_EQ(displayName.size, strlen("EngineDisp") + 1);

    /* without a row the object is used */
    uint8_t missBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(missBuf), sizeof(missBuf),
        "oh:t=c;o=EngineDispMiss;u=8899;a=889901"), EOK);
    struct CmBlob missUri = { sizeof(missBuf), missBuf };
    /* the previous call shrank displayName.size to the alias length: restore the capacity */
    displayName.size = sizeof(nameBuf);
    ASSERT_EQ(CmGetDisplayNameByURI(&missUri, "EngineDispObject", &displayName), CM_SUCCESS);
    EXPECT_STREQ(reinterpret_cast<char *>(displayName.data), "EngineDispObject");

    /* a too small output buffer is rejected */
    uint8_t tinyBuf[2] = { 0 };
    struct CmBlob tinyName = { sizeof(tinyBuf), tinyBuf };
    EXPECT_EQ(CmGetDisplayNameByURI(&uriBlob, "EngineDispObject", &tinyName), CMR_ERROR_MEM_OPERATION_COPY);
}

/**
 * @tc.name: CmEngineRdbInsertCertProperty_001
 * @tc.desc: the row insert validates store type and field sizes.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineRdbInsertCertProperty_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), "oh:t=c;o=EngineRdb;u=8899;a=889901"), EOK);
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "EngineRdb"), EOK);
    uint8_t subjectBuf[MAX_LEN_SUBJECT_NAME] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(subjectBuf), sizeof(subjectBuf), "CN=EngineRdb"), EOK);
    struct CmBlob uriBlob = { sizeof(uriBuf), uriBuf };
    struct CmBlob aliasBlob = { strlen("EngineRdb") + 1, aliasBuf };
    struct CmBlob subjectBlob = { strlen("CN=EngineRdb") + 1, subjectBuf };

    /* an unsupported store has no certificate type */
    struct CertPropertyOri propertyOri = { &context, &uriBlob, &aliasBlob, &subjectBlob, 99,
        CM_AUTH_STORAGE_LEVEL_EL1 };
    EXPECT_EQ(RdbInsertCertProperty(&propertyOri), CMR_ERROR_INVALID_ARGUMENT);

    /* an oversized uri is rejected */
    uint8_t longUriBuf[MAX_LEN_URI + 64] = { 0 };
    (void)memset_s(longUriBuf, sizeof(longUriBuf), 'u', sizeof(longUriBuf) - 1);
    struct CmBlob longUri = { sizeof(longUriBuf), longUriBuf };
    propertyOri.uri = &longUri;
    propertyOri.store = CM_USER_TRUSTED_STORE;
    EXPECT_EQ(RdbInsertCertProperty(&propertyOri), CMR_ERROR_MEM_OPERATION_COPY);

    /* an oversized alias is rejected */
    uint8_t longAliasBuf[MAX_LEN_CERT_ALIAS + 64] = { 0 };
    (void)memset_s(longAliasBuf, sizeof(longAliasBuf), 'a', sizeof(longAliasBuf) - 1);
    struct CmBlob longAlias = { sizeof(longAliasBuf), longAliasBuf };
    propertyOri.uri = &uriBlob;
    propertyOri.alias = &longAlias;
    EXPECT_EQ(RdbInsertCertProperty(&propertyOri), CMR_ERROR_MEM_OPERATION_COPY);

    /* an oversized subject is rejected */
    uint8_t longSubjectBuf[MAX_LEN_SUBJECT_NAME + 64] = { 0 };
    (void)memset_s(longSubjectBuf, sizeof(longSubjectBuf), 's', sizeof(longSubjectBuf) - 1);
    struct CmBlob longSubject = { sizeof(longSubjectBuf), longSubjectBuf };
    propertyOri.alias = &aliasBlob;
    propertyOri.subjectName = &longSubject;
    EXPECT_EQ(RdbInsertCertProperty(&propertyOri), CMR_ERROR_MEM_OPERATION_COPY);
}

/**
 * @tc.name: CmEngineStoreUserCertAndSaConf_001
 * @tc.desc: backup writes and the config generator cover success and failure.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineStoreUserCertAndSaConf_001, TestSize.Level0)
{
    char backupDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_CM_USER, backupDirBuf, sizeof(backupDirBuf)), CM_SUCCESS);
    const std::string backupDir = backupDirBuf;
    char confUidDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_CM_USER, TEST_CM_UID, confUidDirBuf, sizeof(confUidDirBuf)), CM_SUCCESS);
    const std::string confDir = confUidDirBuf;

    /* the certificate payload is stored in the backup directory */
    struct CmBlob userCert = { strlen(g_certData06) + 1, reinterpret_cast<uint8_t *>(g_certData06) };
    ASSERT_EQ(CmStoreUserCert(backupDir.c_str(), &userCert, "enginestore.0"), CM_SUCCESS);
    EXPECT_EQ(CmIsFileExist(backupDir.c_str(), "enginestore.0"), CMR_OK);
    uint8_t readBack[sizeof(g_certData06)] = { 0 };
    uint32_t readSize = CmFileRead(backupDir.c_str(), "enginestore.0", 0, readBack, sizeof(readBack));
    EXPECT_EQ(readSize, strlen(g_certData06) + 1);
    EXPECT_EQ(memcmp(readBack, g_certData06, strlen(g_certData06)), 0);

    /* a missing directory cannot host the backup */
    const std::string missingDir = backupDir + "/missing";
    EXPECT_EQ(CmStoreUserCert(missingDir.c_str(), &userCert, "enginestore.1"), CMR_ERROR_WRITE_FILE_FAIL);

    /* the config generator records the backup directory and name */
    const std::string confOne = confDir + "/enginestore1.config";
    ASSERT_EQ(CmGenerateSaConf(confOne.c_str(), backupDir.c_str(), "enginestore.0"), CM_SUCCESS);
    uint8_t confBuf[CERT_MAX_PATH_LEN] = { 0 };
    readSize = CmFileRead(nullptr, confOne.c_str(), 0, confBuf, sizeof(confBuf) - 1);
    const std::string expected = backupDir + "/enginestore.0";
    EXPECT_EQ(readSize, expected.size());
    EXPECT_EQ(memcmp(confBuf, expected.c_str(), expected.size()), 0);

    /* without a directory only the name is recorded */
    const std::string confTwo = confDir + "/enginestore2.config";
    ASSERT_EQ(CmGenerateSaConf(confTwo.c_str(), nullptr, "enginestore.0"), CM_SUCCESS);
    readSize = CmFileRead(nullptr, confTwo.c_str(), 0, confBuf, sizeof(confBuf) - 1);
    EXPECT_EQ(readSize, strlen("enginestore.0"));
    EXPECT_EQ(memcmp(confBuf, "enginestore.0", strlen("enginestore.0")), 0);

    /* a config path in a missing directory fails */
    const std::string missingConf = confDir + "/missing/enginestore3.config";
    EXPECT_EQ(CmGenerateSaConf(missingConf.c_str(), backupDir.c_str(), "enginestore.0"), CMR_ERROR_WRITE_FILE_FAIL);
}

/**
 * @tc.name: CmEngineRemoveUserCertFlow_001
 * @tc.desc: removing a user certificate and its backup walks every helper branch.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineRemoveUserCertFlow_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uri = "oh:t=c;o=EngineRmU;u=8899;a=889901";
    const std::string uidDir = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uri.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    char pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(strcpy_s(pathBuf, sizeof(pathBuf), uidDir.c_str()), EOK);
    struct CmMutableBlob pathBlob = { strlen(pathBuf) + 1, reinterpret_cast<uint8_t *>(pathBuf) };
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(uriBuf), sizeof(uriBuf), uri.c_str()), EOK);
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    /* an invalid uri is rejected */
    struct CmBlob noData = { 0, nullptr };
    EXPECT_EQ(CmRemoveUserCert(&pathBlob, &noData), CMR_ERROR_INVALID_ARGUMENT_URI);
    uint8_t dotBuf[MAX_LEN_URI] = { 0 };
    ASSERT_EQ(strcpy_s(reinterpret_cast<char *>(dotBuf), sizeof(dotBuf), "oh:t=c;o=../x;u=8899;a=889901"), EOK);
    struct CmBlob dotUri = { sizeof(dotBuf), dotBuf };
    EXPECT_EQ(CmRemoveUserCert(&pathBlob, &dotUri), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* a stored file is removed, a missing file is reported */
    ASSERT_EQ(CmRemoveUserCert(&pathBlob, &certUri), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(uidDir.c_str(), uri.c_str()), CMR_OK);
    EXPECT_EQ(CmRemoveUserCert(&pathBlob, &certUri), CMR_ERROR_NOT_EXIST);

    /* the remove helpers treat a missing config as nothing to do */
    char confUidDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_CM_USER, TEST_CM_UID, confUidDirBuf, sizeof(confUidDirBuf)), CM_SUCCESS);
    const std::string absentConf = std::string(confUidDirBuf) + "/" + uri + CERT_CONFIG_FILE_SUFFIX;
    EXPECT_EQ(CmRmUserCert(absentConf.c_str()), CM_SUCCESS);
    EXPECT_EQ(CmRmSaConf(absentConf.c_str()), CMR_ERROR_NOT_EXIST);

    /* with a config and backup present everything is cleaned up through the context */
    std::string confFile;
    MakeConfigAndBackup(uri, "manualrm2.0", confFile);
    ASSERT_EQ(CmRemoveBackupUserCert(&context, &certUri, nullptr), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);
    char backupDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_CM_USER, backupDirBuf, sizeof(backupDirBuf)), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(backupDirBuf, "manualrm2.0"), CMR_OK);

    /* the same through an explicit config path */
    MakeConfigAndBackup(uri, "manualrm3.0", confFile);
    ASSERT_EQ(CmRemoveBackupUserCert(nullptr, nullptr, confFile.c_str()), CM_SUCCESS);
    EXPECT_NE(CmIsFileExist(nullptr, confFile.c_str()), CMR_OK);
    EXPECT_NE(CmIsFileExist(backupDirBuf, "manualrm3.0"), CMR_OK);

    /* an empty config cannot be evaluated */
    MakeConfigAndBackup(uri, "manualrm4.0", confFile);
    ASSERT_EQ(CmFileRemove(nullptr, confFile.c_str()), CMR_OK);
    CreateEmptyFile(confFile);
    EXPECT_EQ(CmRemoveBackupUserCert(nullptr, nullptr, confFile.c_str()), CMR_ERROR_READ_FILE_ERROR);

    /* the backup remove helper validates the uid directory */
    EXPECT_EQ(CmBackupRemove(TEST_CM_USER, nullptr, &certUri), CMR_ERROR_INVALID_ARGUMENT);
    const std::string nonNumericDir = std::string(USER_CA_STORE) + std::to_string(TEST_CM_USER) + "/notanumber";
    EXPECT_EQ(CmBackupRemove(TEST_CM_USER, nonNumericDir.c_str(), &certUri), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmEngineRemoveAllUserCert_001
 * @tc.desc: the bulk removal wipes files, backups, config dirs and rdb rows.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineRemoveAllUserCert_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);

    /* invalid path lists are rejected */
    EXPECT_EQ(CmRemoveAllUserCert(&context, CM_USER_TRUSTED_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    struct CmMutableBlob emptyList = { 0, nullptr };
    EXPECT_EQ(CmRemoveAllUserCert(&context, CM_USER_TRUSTED_STORE, &emptyList), CMR_ERROR_INVALID_ARGUMENT);

    /* first uid directory: certificate file, rdb row, config and backup */
    const std::string uriA = "oh:t=c;o=EngineRmA;u=8899;a=889901";
    const std::string uidDirA = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_UID);
    ASSERT_EQ(CmFileWrite(uidDirA.c_str(), uriA.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(InsertCertRow(&context, uriA, "EngineRmA", CM_USER_TRUSTED_STORE, CM_AUTH_STORAGE_LEVEL_EL1),
        CM_SUCCESS);
    char confUidDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_CM_USER, TEST_CM_UID, confUidDirBuf, sizeof(confUidDirBuf)), CM_SUCCESS);
    const std::string confFileA = std::string(confUidDirBuf) + "/" + uriA + CERT_CONFIG_FILE_SUFFIX;
    char backupDirBuf[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_CM_USER, backupDirBuf, sizeof(backupDirBuf)), CM_SUCCESS);
    const std::string backupPathA = std::string(backupDirBuf) + "/manualrmall.0";
    ASSERT_EQ(CmFileWrite(backupDirBuf, "manualrmall.0", 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(CmFileWrite(nullptr, confFileA.c_str(), 0,
        reinterpret_cast<const uint8_t *>(backupPathA.c_str()), backupPathA.size()), CMR_OK);

    /* second uid directory: certificate file and row only */
    const std::string uriB = "oh:t=c;o=EngineRmB;u=8899;a=889902";
    const std::string uidDirB = MakeStoreUidDir(USER_CA_STORE, TEST_CM_USER, TEST_CM_OTHER_UID);
    ASSERT_EQ(CmFileWrite(uidDirB.c_str(), uriB.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    struct CmContext otherContext = BuildContext(TEST_CM_USER, TEST_CM_OTHER_UID);
    ASSERT_EQ(InsertCertRow(&otherContext, uriB, "EngineRmB", CM_USER_TRUSTED_STORE, CM_AUTH_STORAGE_LEVEL_EL1),
        CM_SUCCESS);

    char pathA[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(strcpy_s(pathA, sizeof(pathA), uidDirA.c_str()), EOK);
    char pathB[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(strcpy_s(pathB, sizeof(pathB), uidDirB.c_str()), EOK);
    struct CmMutableBlob paths[2] = {
        { strlen(pathA) + 1, reinterpret_cast<uint8_t *>(pathA) },
        { strlen(pathB) + 1, reinterpret_cast<uint8_t *>(pathB) },
    };
    struct CmMutableBlob pathList = { 2, reinterpret_cast<uint8_t *>(paths) };

    ASSERT_EQ(CmRemoveAllUserCert(&context, CM_USER_TRUSTED_STORE, &pathList), CM_SUCCESS);

    /* files, uid directories, config directories and the backup are gone */
    EXPECT_NE(CmIsFileExist(uidDirA.c_str(), uriA.c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist(uidDirA.c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist(uidDirB.c_str()), CMR_OK);
    EXPECT_NE(CmIsDirExist(confUidDirBuf), CMR_OK);
    EXPECT_NE(CmIsFileExist(backupDirBuf, "manualrmall.0"), CMR_OK);

    /* both rdb rows are gone */
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(uriA.c_str(), &prop), CM_SUCCESS);
    EXPECT_STREQ(prop.uri, "");
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    ASSERT_EQ(QueryCertProperty(uriB.c_str(), &prop), CM_SUCCESS);
    EXPECT_STREQ(prop.uri, "");
}

/**
 * @tc.name: CmEngineAppCertListByUid_001
 * @tc.desc: the by-uid listing reads the uid layer of the credential stores.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCertMgrTest, CmEngineAppCertListByUid_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_CM_USER, TEST_CM_UID);
    const std::string uidDir = MakeStoreUidDir(PRI_CREDNTIAL_STORE, TEST_CM_USER, TEST_CM_UID);
    const uint8_t *pemData = reinterpret_cast<const uint8_t *>(g_certData06);
    const std::string uriA = "oh:t=ak;o=EngineByUidA;u=8899;a=889901";
    const std::string uriB = "oh:t=ak;o=EngineByUidB;u=8899;a=889901";
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uriA.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);
    ASSERT_EQ(CmFileWrite(uidDir.c_str(), uriB.c_str(), 0, pemData, strlen(g_certData06)), CMR_OK);

    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);
    uint32_t fileCount = 0;

    /* an unknown store has no root path */
    EXPECT_EQ(CmServiceGetAppCertListByUid(&context, 99, fileNames, MAX_COUNT_CERTIFICATE, &fileCount), CM_FAILURE);

    /* both files of the uid directory are listed with their full paths */
    ASSERT_EQ(CmServiceGetAppCertListByUid(&context, CM_PRI_CREDENTIAL_STORE, fileNames, MAX_COUNT_CERTIFICATE,
        &fileCount), CM_SUCCESS);
    EXPECT_EQ(fileCount, 2u);
    for (uint32_t i = 0; i < fileCount; i++) {
        const std::string filePath = reinterpret_cast<char *>(fileNames[i].data);
        EXPECT_EQ(filePath.compare(0, uidDir.size(), uidDir), 0);
        EXPECT_TRUE(filePath == uidDir + "/" + uriA || filePath == uidDir + "/" + uriB);
    }
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* the calling variant walks the same uid layer */
    (void)memset_s(fileNames, len, 0, len);
    fileCount = 0;
    ASSERT_EQ(CmServiceGetCallingAppCertList(&context, CM_PRI_CREDENTIAL_STORE, fileNames, MAX_COUNT_CERTIFICATE,
        &fileCount), CM_SUCCESS);
    EXPECT_EQ(fileCount, 2u);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* an absent uid directory simply yields an empty list */
    struct CmContext absentContext = BuildContext(TEST_CM_USER, TEST_CM_OTHER_UID);
    (void)memset_s(fileNames, len, 0, len);
    fileCount = 0;
    ASSERT_EQ(CmServiceGetAppCertListByUid(&absentContext, CM_PRI_CREDENTIAL_STORE, fileNames, MAX_COUNT_CERTIFICATE,
        &fileCount), CM_SUCCESS);
    EXPECT_EQ(fileCount, 0u);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* the free helper tolerates a null list */
    CmFreeFileNames(nullptr, 0);
}
