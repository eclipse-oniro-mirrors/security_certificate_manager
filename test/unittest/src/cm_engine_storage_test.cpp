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
#include <dirent.h>
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <openssl/x509.h>

#include "cert_manager_file_operator.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_user.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_STORAGE_USER = 8899;
constexpr uint32_t TEST_STORAGE_UID = 889901;
constexpr int NFTW_MAX_OPEN_FDS = 16;
/* sparse oversized file used to exercise the storage size guard */
constexpr off_t OVERSIZED_FILE_LEN = static_cast<off_t>(MAX_OUT_BLOB_SIZE) + 1;

/* engine store roots that must pre-exist (they belong to the SA lifecycle) */
const std::vector<std::string> STORE_ROOTS = {
    CREDNTIAL_STORE,
    USER_CA_STORE,
    PRI_CREDNTIAL_STORE,
    SYS_CREDNTIAL_STORE,
    CERT_BACKUP_CONFIG_ROOT_DIR,
    CERT_BACKUP_ROOT_DIR,
};
std::vector<std::string> g_createdRoots; /* roots this suite created itself */

/* the isolated user subtrees created by the cases below */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER),
        std::string(USER_CA_STORE) + std::to_string(TEST_STORAGE_USER),
        std::string(PRI_CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER),
        std::string(SYS_CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER),
        std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_STORAGE_USER),
        std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_STORAGE_USER),
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

std::string JoinPath(const std::string &a, const std::string &b)
{
    return a + "/" + b;
}

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}

/* parse the well known user CA certificate (DER) used by the suite */
X509 *ParseUserCaCert(void)
{
    const unsigned char *data = g_certData01;
    return d2i_X509(nullptr, &data, sizeof(g_certData01));
}
} // namespace

class CmEngineStorageTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        CmTestCommon::SetTestEnvironment(GetSelfTokenID());
        /* the certificates root must exist before any store root can be created */
        if (CmIsDirExist(CERT_DIR) != CMR_OK) {
            (void)CmMakeDir(CERT_DIR);
            g_createdRoots.emplace_back(CERT_DIR);
        }
        /* create the engine store roots only when the device has not set them up */
        for (const auto &root : STORE_ROOTS) {
            if (CmIsDirExist(root.c_str()) != CMR_OK) {
                (void)CmMakeDir(root.c_str());
                g_createdRoots.emplace_back(root);
            }
        }
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
        /* best effort removal of the store roots this suite created itself */
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
    }
};

/**
 * @tc.name: GetRootPath_001
 * @tc.desc: root path derivation for every store plus buffer and store validation
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, GetRootPath_001, TestSize.Level0)
{
    char rootPath[CERT_MAX_PATH_LEN] = { 0 };
    EXPECT_EQ(GetRootPath(CM_CREDENTIAL_STORE, rootPath, sizeof(rootPath)), CM_SUCCESS);
    EXPECT_STREQ(rootPath, CREDNTIAL_STORE);

    (void)memset_s(rootPath, sizeof(rootPath), 0, sizeof(rootPath));
    EXPECT_EQ(GetRootPath(CM_SYSTEM_TRUSTED_STORE, rootPath, sizeof(rootPath)), CM_SUCCESS);
    EXPECT_STREQ(rootPath, SYSTEM_CA_STORE);

    (void)memset_s(rootPath, sizeof(rootPath), 0, sizeof(rootPath));
    EXPECT_EQ(GetRootPath(CM_USER_TRUSTED_STORE, rootPath, sizeof(rootPath)), CM_SUCCESS);
    EXPECT_STREQ(rootPath, USER_CA_STORE);

    (void)memset_s(rootPath, sizeof(rootPath), 0, sizeof(rootPath));
    EXPECT_EQ(GetRootPath(CM_PRI_CREDENTIAL_STORE, rootPath, sizeof(rootPath)), CM_SUCCESS);
    EXPECT_STREQ(rootPath, PRI_CREDNTIAL_STORE);

    (void)memset_s(rootPath, sizeof(rootPath), 0, sizeof(rootPath));
    EXPECT_EQ(GetRootPath(CM_SYS_CREDENTIAL_STORE, rootPath, sizeof(rootPath)), CM_SUCCESS);
    EXPECT_STREQ(rootPath, SYS_CREDNTIAL_STORE);

    /* an unknown store is rejected */
    EXPECT_EQ(GetRootPath(99, rootPath, sizeof(rootPath)), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* a buffer that is too small fails the copy */
    char smallBuf[8] = { 0 };
    EXPECT_EQ(GetRootPath(CM_USER_TRUSTED_STORE, smallBuf, sizeof(smallBuf)), CMR_ERROR_MEM_OPERATION_COPY);
}

/**
 * @tc.name: ConstructUserUidAuthListPath_001
 * @tc.desc: user id, uid and auth list path construction creates the directories
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, ConstructUserUidAuthListPath_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_STORAGE_USER, TEST_STORAGE_UID);

    /* a null context is rejected */
    char pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    EXPECT_EQ(ConstructUidPath(nullptr, CM_CREDENTIAL_STORE, pathBuf, sizeof(pathBuf)),
        CMR_ERROR_INVALID_ARGUMENT);

    /* an unknown store is rejected */
    EXPECT_EQ(ConstructUserIdPath(&context, 99, pathBuf, sizeof(pathBuf)),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(ConstructUidPath(&context, 99, pathBuf, sizeof(pathBuf)),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(ConstructAuthListPath(&context, 99, pathBuf, sizeof(pathBuf)),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* user id path of the credential store */
    (void)memset_s(pathBuf, sizeof(pathBuf), 0, sizeof(pathBuf));
    EXPECT_EQ(ConstructUserIdPath(&context, CM_CREDENTIAL_STORE, pathBuf, sizeof(pathBuf)), CM_SUCCESS);
    EXPECT_STREQ(pathBuf, (std::string(CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER)).c_str());
    EXPECT_EQ(CmIsDirExist(pathBuf), CMR_OK);

    /* uid path nests below the user id path */
    (void)memset_s(pathBuf, sizeof(pathBuf), 0, sizeof(pathBuf));
    EXPECT_EQ(ConstructUidPath(&context, CM_CREDENTIAL_STORE, pathBuf, sizeof(pathBuf)), CM_SUCCESS);
    EXPECT_STREQ(pathBuf, (std::string(CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER) + "/" +
        std::to_string(TEST_STORAGE_UID)).c_str());
    EXPECT_EQ(CmIsDirExist(pathBuf), CMR_OK);

    /* the auth list path nests below the uid path */
    (void)memset_s(pathBuf, sizeof(pathBuf), 0, sizeof(pathBuf));
    EXPECT_EQ(ConstructAuthListPath(&context, CM_CREDENTIAL_STORE, pathBuf, sizeof(pathBuf)), CM_SUCCESS);
    EXPECT_STREQ(pathBuf, (std::string(CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER) + "/" +
        std::to_string(TEST_STORAGE_UID) + "/authlist").c_str());
    EXPECT_EQ(CmIsDirExist(pathBuf), CMR_OK);

    /* the user CA store derives from the user id alone */
    (void)memset_s(pathBuf, sizeof(pathBuf), 0, sizeof(pathBuf));
    EXPECT_EQ(ConstructUserIdPath(&context, CM_USER_TRUSTED_STORE, pathBuf, sizeof(pathBuf)), CM_SUCCESS);
    EXPECT_STREQ(pathBuf, (std::string(USER_CA_STORE) + std::to_string(TEST_STORAGE_USER)).c_str());

    /* too small output buffers fail the print */
    char tinyBuf[8] = { 0 };
    EXPECT_EQ(ConstructUserIdPath(&context, CM_CREDENTIAL_STORE, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
    EXPECT_EQ(ConstructUidPath(&context, CM_CREDENTIAL_STORE, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
    EXPECT_EQ(ConstructAuthListPath(&context, CM_CREDENTIAL_STORE, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
}

/**
 * @tc.name: CmStorageGetBuf_001
 * @tc.desc: storage buffer loading for an existing, missing and oversized file
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmStorageGetBuf_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_STORAGE_USER, TEST_STORAGE_UID);
    char uidPath[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(ConstructUidPath(&context, CM_CREDENTIAL_STORE, uidPath, sizeof(uidPath)), CM_SUCCESS);

    uint8_t payload[] = "storage buffer payload";
    uint32_t payloadLen = sizeof(payload) - 1;
    ASSERT_EQ(CmFileWrite(uidPath, "certfile", 0, payload, payloadLen), CMR_OK);

    /* an existing file is loaded with its exact content */
    struct CmBlob storageBuf = { 0, nullptr };
    EXPECT_EQ(CmStorageGetBuf(uidPath, "certfile", &storageBuf), CM_SUCCESS);
    ASSERT_NE(storageBuf.data, nullptr);
    EXPECT_EQ(storageBuf.size, payloadLen);
    EXPECT_EQ(memcmp(storageBuf.data, payload, payloadLen), 0);
    CM_FREE_BLOB(storageBuf);

    /* a missing file is reported as not existing */
    EXPECT_EQ(CmStorageGetBuf(uidPath, "missing", &storageBuf), CMR_ERROR_NOT_EXIST);

    /* an oversized file is rejected before allocation */
    std::string oversized = JoinPath(uidPath, "oversized");
    ASSERT_EQ(truncate(oversized.c_str(), OVERSIZED_FILE_LEN), 0);
    EXPECT_EQ(CmStorageGetBuf(uidPath, "oversized", &storageBuf), CMR_ERROR_STORAGE);
    (void)CmFileRemove(uidPath, "oversized");
}

/**
 * @tc.name: CmStorageGetAppCert_001
 * @tc.desc: app cert loading resolves the uri uid and the uri named file
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmStorageGetAppCert_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_STORAGE_USER, TEST_STORAGE_UID);
    char uidPath[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(ConstructUidPath(&context, CM_CREDENTIAL_STORE, uidPath, sizeof(uidPath)), CM_SUCCESS);

    /* the credential file name is the uri itself */
    uint8_t uriName[] = "oh:t=ak;o=cert8899;u=8899;a=889901";
    uint8_t payload[] = "app cert payload";
    uint32_t payloadLen = sizeof(payload) - 1;
    ASSERT_EQ(CmFileWrite(uidPath, reinterpret_cast<const char *>(uriName), 0, payload, payloadLen), CMR_OK);

    struct CmBlob keyUri = { sizeof(uriName), uriName };
    struct CmBlob certBlob = { 0, nullptr };
    EXPECT_EQ(CmStorageGetAppCert(&context, CM_CREDENTIAL_STORE, &keyUri, &certBlob), CM_SUCCESS);
    ASSERT_NE(certBlob.data, nullptr);
    EXPECT_EQ(certBlob.size, payloadLen);
    EXPECT_EQ(memcmp(certBlob.data, payload, payloadLen), 0);
    CM_FREE_BLOB(certBlob);

    /* a uri without an app field fails to resolve */
    uint8_t noAppUri[] = "oh:t=ak;o=cert8899;u=8899";
    struct CmBlob badUri = { sizeof(noAppUri), noAppUri };
    EXPECT_EQ(CmStorageGetAppCert(&context, CM_CREDENTIAL_STORE, &badUri, &certBlob),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* a uri whose file does not exist is reported as not existing */
    uint8_t missingUri[] = "oh:t=ak;o=missing8899;u=8899;a=889901";
    struct CmBlob missingBlob = { sizeof(missingUri), missingUri };
    EXPECT_EQ(CmStorageGetAppCert(&context, CM_CREDENTIAL_STORE, &missingBlob, &certBlob),
        CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmGetCertFilePath_001
 * @tc.desc: cert file path derivation validates its arguments and copies the path
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertFilePath_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_STORAGE_USER, TEST_STORAGE_UID);

    /* null pointer validation */
    EXPECT_EQ(CmGetCertFilePath(&context, CM_CREDENTIAL_STORE, nullptr), CMR_ERROR_NULL_POINTER);
    uint8_t pathData[CERT_MAX_PATH_LEN] = { 0 };
    struct CmMutableBlob nullData = { sizeof(pathData), nullptr };
    EXPECT_EQ(CmGetCertFilePath(&context, CM_CREDENTIAL_STORE, &nullData), CMR_ERROR_NULL_POINTER);

    /* an unknown store is rejected */
    struct CmMutableBlob pathBlob = { sizeof(pathData), pathData };
    EXPECT_EQ(CmGetCertFilePath(&context, 99, &pathBlob), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* the derived path points at the uid directory */
    EXPECT_EQ(CmGetCertFilePath(&context, CM_CREDENTIAL_STORE, &pathBlob), CM_SUCCESS);
    std::string expect = std::string(CREDNTIAL_STORE) + std::to_string(TEST_STORAGE_USER) + "/" +
        std::to_string(TEST_STORAGE_UID);
    EXPECT_STREQ(reinterpret_cast<char *>(pathData), expect.c_str());
    EXPECT_EQ(pathBlob.size, static_cast<uint32_t>(expect.size()) + 1);
}

/**
 * @tc.name: CmGetCertConfDirs_001
 * @tc.desc: config root, user id and uid directories are created and validated
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertConfDirs_001, TestSize.Level0)
{
    char dirBuf[CERT_MAX_PATH_LEN] = { 0 };

    /* null output buffers are rejected */
    EXPECT_EQ(CmGetCertConfUserIdDir(TEST_STORAGE_USER, nullptr, sizeof(dirBuf)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetCertConfUidDir(TEST_STORAGE_USER, TEST_STORAGE_UID, nullptr, sizeof(dirBuf)),
        CMR_ERROR_INVALID_ARGUMENT);

    /* the user id directory is created below user_config */
    EXPECT_EQ(CmGetCertConfUserIdDir(TEST_STORAGE_USER, dirBuf, sizeof(dirBuf)), CM_SUCCESS);
    EXPECT_STREQ(dirBuf, (std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" +
        std::to_string(TEST_STORAGE_USER)).c_str());
    EXPECT_EQ(CmIsDirExist(dirBuf), CMR_OK);

    /* the uid directory is created below the user id directory */
    (void)memset_s(dirBuf, sizeof(dirBuf), 0, sizeof(dirBuf));
    EXPECT_EQ(CmGetCertConfUidDir(TEST_STORAGE_USER, TEST_STORAGE_UID, dirBuf, sizeof(dirBuf)), CM_SUCCESS);
    EXPECT_STREQ(dirBuf, (std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" +
        std::to_string(TEST_STORAGE_USER) + "/" + std::to_string(TEST_STORAGE_UID)).c_str());
    EXPECT_EQ(CmIsDirExist(dirBuf), CMR_OK);

    /* too small output buffers fail the print */
    char tinyBuf[8] = { 0 };
    EXPECT_EQ(CmGetCertConfUserIdDir(TEST_STORAGE_USER, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
    EXPECT_EQ(CmGetCertConfUidDir(TEST_STORAGE_USER, TEST_STORAGE_UID, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
}

/**
 * @tc.name: CmGetCertConfPath_001
 * @tc.desc: config file path derivation validates its arguments and appends the suffix
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertConfPath_001, TestSize.Level0)
{
    uint8_t uriData[] = "oh:t=c;o=alias8899;u=8899;a=889901";
    struct CmBlob certUri = { sizeof(uriData), uriData };
    char confPath[CERT_MAX_PATH_LEN] = { 0 };

    /* invalid arguments */
    EXPECT_EQ(CmGetCertConfPath(TEST_STORAGE_USER, TEST_STORAGE_UID, nullptr, confPath, sizeof(confPath)),
        CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob badUri = { sizeof(uriData), nullptr };
    EXPECT_EQ(CmGetCertConfPath(TEST_STORAGE_USER, TEST_STORAGE_UID, &badUri, confPath, sizeof(confPath)),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetCertConfPath(TEST_STORAGE_USER, TEST_STORAGE_UID, &certUri, nullptr, sizeof(confPath)),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetCertConfPath(TEST_STORAGE_USER, TEST_STORAGE_UID, &certUri, confPath, 0),
        CMR_ERROR_INVALID_ARGUMENT);

    /* the config file path nests below user_config/user/uid and carries the suffix */
    EXPECT_EQ(CmGetCertConfPath(TEST_STORAGE_USER, TEST_STORAGE_UID, &certUri, confPath, sizeof(confPath)),
        CM_SUCCESS);
    std::string expect = std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" +
        std::to_string(TEST_STORAGE_USER) + "/" + std::to_string(TEST_STORAGE_UID) + "/" +
        reinterpret_cast<char *>(uriData) + CERT_CONFIG_FILE_SUFFIX;
    EXPECT_STREQ(confPath, expect.c_str());
}

/**
 * @tc.name: CmGetCertBackupDir_001
 * @tc.desc: backup directory derivation creates user_open/{userId}
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertBackupDir_001, TestSize.Level0)
{
    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    EXPECT_EQ(CmGetCertBackupDir(TEST_STORAGE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    EXPECT_STREQ(backupDir, (std::string(CERT_BACKUP_ROOT_DIR) + "/" +
        std::to_string(TEST_STORAGE_USER)).c_str());
    EXPECT_EQ(CmIsDirExist(backupDir), CMR_OK);

    /* a too small output buffer fails the print */
    char tinyBuf[8] = { 0 };
    EXPECT_EQ(CmGetCertBackupDir(TEST_STORAGE_USER, tinyBuf, sizeof(tinyBuf)),
        CMR_ERROR_MEM_OPERATION_PRINT);
}

/**
 * @tc.name: CmGetCertBackupFileName_001
 * @tc.desc: backup file names follow the subject hash and advance the sequence number
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertBackupFileName_001, TestSize.Level0)
{
    X509 *cert = ParseUserCaCert();
    ASSERT_NE(cert, nullptr);

    char backupFileName[CERT_MAX_PATH_LEN] = { 0 };

    /* invalid arguments */
    EXPECT_EQ(CmGetCertBackupFileName(nullptr, TEST_STORAGE_USER, backupFileName, sizeof(backupFileName)),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetCertBackupFileName(cert, TEST_STORAGE_USER, nullptr, sizeof(backupFileName)),
        CMR_ERROR_INVALID_ARGUMENT);

    /* the first name uses sequence number zero */
    ASSERT_EQ(CmGetCertBackupFileName(cert, TEST_STORAGE_USER, backupFileName, sizeof(backupFileName)),
        CM_SUCCESS);
    unsigned long subjectHash = X509_NAME_hash(X509_get_subject_name(cert));
    char expectName[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_GE(snprintf_s(expectName, sizeof(expectName), sizeof(expectName) - 1,
        CERT_BACKUP_FILENAME_FORMAT, subjectHash, 0), 0);
    EXPECT_STREQ(backupFileName, expectName);

    /* an existing backup file advances the sequence number */
    char backupDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertBackupDir(TEST_STORAGE_USER, backupDir, sizeof(backupDir)), CM_SUCCESS);
    uint8_t payload[] = "cert";
    ASSERT_EQ(CmFileWrite(backupDir, backupFileName, 0, payload, sizeof(payload) - 1), CMR_OK);

    (void)memset_s(backupFileName, sizeof(backupFileName), 0, sizeof(backupFileName));
    ASSERT_EQ(CmGetCertBackupFileName(cert, TEST_STORAGE_USER, backupFileName, sizeof(backupFileName)),
        CM_SUCCESS);
    ASSERT_GE(snprintf_s(expectName, sizeof(expectName), sizeof(expectName) - 1,
        CERT_BACKUP_FILENAME_FORMAT, subjectHash, 1), 0);
    EXPECT_STREQ(backupFileName, expectName);

    X509_free(cert);
}

/**
 * @tc.name: CmGetCertBackupFilePath_001
 * @tc.desc: backup file paths join the backup directory and the backup file name
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineStorageTest, CmGetCertBackupFilePath_001, TestSize.Level0)
{
    X509 *cert = ParseUserCaCert();
    ASSERT_NE(cert, nullptr);

    char backupFilePath[CERT_MAX_PATH_LEN] = { 0 };

    /* invalid arguments */
    EXPECT_EQ(CmGetCertBackupFilePath(nullptr, TEST_STORAGE_USER, backupFilePath, sizeof(backupFilePath)),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetCertBackupFilePath(cert, TEST_STORAGE_USER, nullptr, sizeof(backupFilePath)),
        CMR_ERROR_INVALID_ARGUMENT);

    /* the path joins the backup dir with the hashed file name */
    ASSERT_EQ(CmGetCertBackupFilePath(cert, TEST_STORAGE_USER, backupFilePath, sizeof(backupFilePath)),
        CM_SUCCESS);
    unsigned long subjectHash = X509_NAME_hash(X509_get_subject_name(cert));
    char expectPath[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_GE(snprintf_s(expectPath, sizeof(expectPath), sizeof(expectPath) - 1, "%s/" CERT_BACKUP_FILENAME_FORMAT,
        (std::string(CERT_BACKUP_ROOT_DIR) + "/" + std::to_string(TEST_STORAGE_USER)).c_str(),
        subjectHash, 0), 0);
    EXPECT_STREQ(backupFilePath, expectPath);

    X509_free(cert);
}
