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

#include "cert_manager.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
/* isolated scratch tree outside the certificate_manager service directories */
const char *TEST_FILE_OP_ROOT = "/data/local/tmp/cm_engine_fileop_test";
/* isolated user inside the engine config tree (user_config) */
constexpr uint32_t TEST_STATUS_USER = 8899;
constexpr uint32_t TEST_STATUS_UID = 889901;
constexpr int NFTW_MAX_OPEN_FDS = 16;

int RemoveTreeEntry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return (type == FTW_DP) ? rmdir(path) : remove(path);
}

void RemoveTree(const char *root)
{
    (void)nftw(root, RemoveTreeEntry, NFTW_MAX_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

void MakeDirOrExists(const char *path)
{
    int32_t ret = CmMakeDir(path);
    ASSERT_TRUE(ret == CMR_OK || ret == CMR_ERROR_ALREADY_EXISTS) << "mkdir failed for " << path;
}

std::string JoinPath(const std::string &a, const std::string &b)
{
    return a + "/" + b;
}
} // namespace

class CmEngineFileOpTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        CmTestCommon::SetTestEnvironment(GetSelfTokenID());
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
    }

    void SetUp() {}

    void TearDown()
    {
        /* remove the scratch tree and the isolated config user created by the cases */
        RemoveTree(TEST_FILE_OP_ROOT);
        RemoveTree(JoinPath(CERT_BACKUP_CONFIG_ROOT_DIR, std::to_string(TEST_STATUS_USER)).c_str());
    }
};

/**
 * @tc.name: CmFileWriteReadRemove_001
 * @tc.desc: write, size, read, exist and remove round trip on an isolated directory
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmFileWriteReadRemove_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);

    uint8_t payload[] = "cert manager file operator payload";
    uint32_t payloadLen = sizeof(payload) - 1;
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "file1", 0, payload, payloadLen), CMR_OK);

    EXPECT_EQ(CmFileSize(TEST_FILE_OP_ROOT, "file1"), payloadLen);
    EXPECT_EQ(CmIsFileExist(TEST_FILE_OP_ROOT, "file1"), CMR_OK);

    uint8_t readBuf[64] = { 0 };
    EXPECT_EQ(CmFileRead(TEST_FILE_OP_ROOT, "file1", 0, readBuf, sizeof(readBuf)), payloadLen);
    EXPECT_EQ(memcmp(readBuf, payload, payloadLen), 0);

    /* the inline wrappers forward to the same operators */
    EXPECT_EQ(CertManagerFileWrite(TEST_FILE_OP_ROOT, "file2", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CertManagerFileSize(TEST_FILE_OP_ROOT, "file2"), payloadLen);
    uint8_t wrapperBuf[64] = { 0 };
    EXPECT_EQ(CertManagerFileRead(TEST_FILE_OP_ROOT, "file2", 0, wrapperBuf, sizeof(wrapperBuf)), payloadLen);
    EXPECT_EQ(CertManagerFileRemove(TEST_FILE_OP_ROOT, "file2"), CMR_OK);

    /* removing a missing file reports not-exist */
    EXPECT_EQ(CmFileRemove(TEST_FILE_OP_ROOT, "file2"), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(CmIsFileExist(TEST_FILE_OP_ROOT, "file2"), CMR_ERROR_NOT_EXIST);

    /* removing through an absolute path with a null base directory */
    std::string fullPath = JoinPath(TEST_FILE_OP_ROOT, "file1");
    EXPECT_EQ(CertManagerFileRemove(nullptr, fullPath.c_str()), CMR_OK);
    EXPECT_EQ(CmIsFileExist(TEST_FILE_OP_ROOT, "file1"), CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: CmFileWriteReadRemove_002
 * @tc.desc: invalid arguments and hostile paths are rejected
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmFileWriteReadRemove_002, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    uint8_t payload[] = "data";
    uint32_t payloadLen = sizeof(payload) - 1;

    /* invalid arguments */
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, nullptr, 0, payload, payloadLen), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "f", 0, nullptr, payloadLen), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "f", 0, payload, 0), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmFileRead(TEST_FILE_OP_ROOT, nullptr, 0, payload, payloadLen), 0);
    EXPECT_EQ(CmFileRead(TEST_FILE_OP_ROOT, "f", 0, nullptr, payloadLen), 0);
    EXPECT_EQ(CmFileRead(TEST_FILE_OP_ROOT, "f", 0, payload, 0), 0);
    EXPECT_EQ(CmFileSize(TEST_FILE_OP_ROOT, nullptr), 0);
    EXPECT_EQ(CmIsFileExist(TEST_FILE_OP_ROOT, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmFileRemove(TEST_FILE_OP_ROOT, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* writing into a missing directory fails */
    std::string missingDir = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CmFileWrite(missingDir.c_str(), "f", 0, payload, payloadLen), CMR_ERROR_OPEN_FILE_FAIL);

    /* relative path segments are rejected */
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "a/../b", 0, payload, payloadLen), CMR_ERROR_NOT_EXIST);

    /* sizes and reads of missing files are zero */
    EXPECT_EQ(CmFileSize(TEST_FILE_OP_ROOT, "missing"), 0);
    EXPECT_EQ(CmFileRead(TEST_FILE_OP_ROOT, "missing", 0, payload, payloadLen), 0);

    /* the backup writer accepts the same arguments and stores the payload */
    EXPECT_EQ(CmUserBackupFileWrite(TEST_FILE_OP_ROOT, "backup", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmUserBackupFileWrite(TEST_FILE_OP_ROOT, nullptr, 0, payload, payloadLen),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmUserBackupFileWrite(TEST_FILE_OP_ROOT, "backup2", 0, payload, 0), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmFileSize(TEST_FILE_OP_ROOT, "backup"), payloadLen);
    EXPECT_EQ(CmFileRemove(TEST_FILE_OP_ROOT, "backup"), CMR_OK);
}

/**
 * @tc.name: CmMakeDir_001
 * @tc.desc: directory creation, existence short circuit and hostile paths
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmMakeDir_001, TestSize.Level0)
{
    EXPECT_EQ(CmMakeDir(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* an existing directory short circuits to success */
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    EXPECT_EQ(CmMakeDir(TEST_FILE_OP_ROOT), CMR_OK);

    /* relative path segments are rejected */
    std::string hostile = JoinPath(TEST_FILE_OP_ROOT, "a/../b");
    EXPECT_EQ(CmMakeDir(hostile.c_str()), CMR_ERROR_MAKE_DIR_FAIL);

    /* a path under an existing file fails */
    std::string notADir = JoinPath(TEST_FILE_OP_ROOT, "plain");
    uint8_t payload[] = "x";
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "plain", 0, payload, sizeof(payload) - 1), CMR_OK);
    std::string underFile = JoinPath(notADir, "child");
    EXPECT_EQ(CmMakeDir(underFile.c_str()), CMR_ERROR_MAKE_DIR_FAIL);

    /* the backup directory maker honours an explicit mode */
    std::string backupDir = JoinPath(TEST_FILE_OP_ROOT, "backup_dir");
    mode_t mode = S_IRWXU | S_IROTH | S_IXOTH; /* 0705 */
    EXPECT_EQ(CmUserBakupMakeDir(backupDir.c_str(), &mode), CMR_OK);
    EXPECT_EQ(CmUserBakupMakeDir(backupDir.c_str(), &mode), CMR_OK); /* exists short circuit */
    EXPECT_EQ(CmIsDirExist(backupDir.c_str()), CMR_OK);
}

/**
 * @tc.name: CmIsDirExist_001
 * @tc.desc: directory existence validation including null and relative paths
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmIsDirExist_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    EXPECT_EQ(CmIsDirExist(TEST_FILE_OP_ROOT), CMR_OK);

    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    /* a missing path fails the realpath validation before the existence check */
    EXPECT_EQ(CmIsDirExist(missing.c_str()), CMR_ERROR_INVALID_ARGUMENT);

    EXPECT_EQ(CmIsDirExist(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    std::string hostile = JoinPath(TEST_FILE_OP_ROOT, "a/../b");
    EXPECT_EQ(CmIsDirExist(hostile.c_str()), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmDirRemove_001
 * @tc.desc: directory removal for empty, missing, non-empty and file paths
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmDirRemove_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);

    /* null path */
    EXPECT_EQ(CmDirRemove(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* missing path fails the realpath validation */
    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CmDirRemove(missing.c_str()), CMR_ERROR_INVALID_ARGUMENT);

    /* a plain file is not a directory */
    uint8_t payload[] = "x";
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "plain", 0, payload, sizeof(payload) - 1), CMR_OK);
    std::string filePath = JoinPath(TEST_FILE_OP_ROOT, "plain");
    EXPECT_EQ(CmDirRemove(filePath.c_str()), CMR_ERROR_INVALID_ARGUMENT);

    /* a non empty directory is rejected */
    std::string nonEmpty = JoinPath(TEST_FILE_OP_ROOT, "nonempty");
    MakeDirOrExists(nonEmpty.c_str());
    EXPECT_EQ(CmFileWrite(nonEmpty.c_str(), "child", 0, payload, sizeof(payload) - 1), CMR_OK);
    EXPECT_EQ(CmDirRemove(nonEmpty.c_str()), CMR_ERROR_INVALID_ARGUMENT);

    /* an empty directory is removed */
    std::string empty = JoinPath(TEST_FILE_OP_ROOT, "empty");
    MakeDirOrExists(empty.c_str());
    EXPECT_EQ(CmDirRemove(empty.c_str()), CMR_OK);
    EXPECT_EQ(CmIsDirExist(empty.c_str()), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmDirEnumeration_001
 * @tc.desc: file and sub directory enumeration over an open directory
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmDirEnumeration_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "cert_a", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmFileWrite(TEST_FILE_OP_ROOT, "cert_b", 0, payload, payloadLen), CMR_OK);
    std::string subDir = JoinPath(TEST_FILE_OP_ROOT, "subdir");
    MakeDirOrExists(subDir.c_str());

    /* opening a missing directory fails */
    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CmOpenDir(missing.c_str()), nullptr);

    void *dir = CmOpenDir(TEST_FILE_OP_ROOT);
    ASSERT_NE(dir, nullptr);

    /* only regular files are reported by CmGetDirFile */
    uint32_t fileCount = 0;
    struct CmFileDirentInfo dire = { { 0 } };
    std::vector<std::string> names;
    while (CmGetDirFile(dir, &dire) == CMR_OK) {
        names.emplace_back(dire.fileName);
        fileCount++;
    }
    EXPECT_EQ(fileCount, 2u); /* cert_a and cert_b, the sub directory is skipped */
    EXPECT_EQ(names.size(), 2u);
    EXPECT_EQ((names[0] == "cert_a" && names[1] == "cert_b") ||
        (names[0] == "cert_b" && names[1] == "cert_a"), true);

    /* the file scan exhausted the shared DIR stream: reopen before scanning sub directories */
    EXPECT_EQ(CmCloseDir(dir), 0);
    dir = CmOpenDir(TEST_FILE_OP_ROOT);
    ASSERT_NE(dir, nullptr);

    /* CmGetSubDir reports only directories */
    struct CmFileDirentInfo subDire = { { 0 } };
    EXPECT_EQ(CmGetSubDir(dir, &subDire), CMR_OK);
    EXPECT_STREQ(subDire.fileName, "subdir");
    EXPECT_EQ(CmGetSubDir(dir, &subDire), CMR_ERROR_NOT_EXIST);

    EXPECT_EQ(CmCloseDir(dir), 0);
}

/**
 * @tc.name: CmUidLayerGetFileCountAndNames_001
 * @tc.desc: uid layer file collection with boundaries and missing directories
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmUidLayerGetFileCountAndNames_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string uidLayer = JoinPath(TEST_FILE_OP_ROOT, "uid_layer");
    MakeDirOrExists(uidLayer.c_str());

    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    EXPECT_EQ(CmFileWrite(uidLayer.c_str(), "cred_a", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmFileWrite(uidLayer.c_str(), "cred_b", 0, payload, payloadLen), CMR_OK);

    /* a missing directory collects nothing */
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE] = { { 0, nullptr } };
    uint32_t fileCount = 0;
    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CmUidLayerGetFileCountAndNames(missing.c_str(), fileNames, MAX_COUNT_CERTIFICATE, &fileCount),
        CM_SUCCESS);
    EXPECT_EQ(fileCount, 0u);

    /* two files are collected as absolute, null terminated paths */
    fileCount = 0;
    EXPECT_EQ(CmUidLayerGetFileCountAndNames(uidLayer.c_str(), fileNames, MAX_COUNT_CERTIFICATE, &fileCount),
        CM_SUCCESS);
    ASSERT_EQ(fileCount, 2u);
    for (uint32_t i = 0; i < fileCount; i++) {
        ASSERT_NE(fileNames[i].data, nullptr);
        std::string name = reinterpret_cast<char *>(fileNames[i].data);
        EXPECT_EQ(name.compare(0, uidLayer.size(), uidLayer), 0);
        EXPECT_EQ(name.find("cred_a") != std::string::npos || name.find("cred_b") != std::string::npos, true);
        EXPECT_EQ(fileNames[i].size, static_cast<uint32_t>(name.size()) + 1);
    }
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* a buffer that is too small stops the walk with an error */
    struct CmBlob smallNames[1] = { { 0, nullptr } };
    uint32_t smallCount = 0;
    EXPECT_EQ(CmUidLayerGetFileCountAndNames(uidLayer.c_str(), smallNames, 1, &smallCount),
        CMR_ERROR_BUFFER_TOO_SMALL);
    ASSERT_NE(smallNames[0].data, nullptr);
    CmFreeFileNames(smallNames, 1);
}

/**
 * @tc.name: CmUserIdLayerGetFileCountAndNames_001
 * @tc.desc: user id layer walks uid sub directories and reaps stray files
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmUserIdLayerGetFileCountAndNames_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string userLayer = JoinPath(TEST_FILE_OP_ROOT, "user_layer");
    MakeDirOrExists(userLayer.c_str());

    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    std::string uid1 = JoinPath(userLayer, "889901");
    std::string uid2 = JoinPath(userLayer, "889902");
    MakeDirOrExists(uid1.c_str());
    MakeDirOrExists(uid2.c_str());
    EXPECT_EQ(CmFileWrite(uid1.c_str(), "cred_a", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmFileWrite(uid2.c_str(), "cred_b", 0, payload, payloadLen), CMR_OK);

    /* a missing directory collects nothing */
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE] = { { 0, nullptr } };
    uint32_t fileCount = 0;
    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CmUserIdLayerGetFileCountAndNames(missing.c_str(), fileNames, MAX_COUNT_CERTIFICATE, &fileCount),
        CM_SUCCESS);
    EXPECT_EQ(fileCount, 0u);

    /* files of every uid sub directory are collected */
    fileCount = 0;
    EXPECT_EQ(CmUserIdLayerGetFileCountAndNames(userLayer.c_str(), fileNames, MAX_COUNT_CERTIFICATE, &fileCount),
        CM_SUCCESS);
    EXPECT_EQ(fileCount, 2u);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);

    /* a stray file directly in the user layer is removed by the walk */
    EXPECT_EQ(CmFileWrite(userLayer.c_str(), "stray", 0, payload, payloadLen), CMR_OK);
    fileCount = 0;
    EXPECT_EQ(CmUserIdLayerGetFileCountAndNames(userLayer.c_str(), fileNames, MAX_COUNT_CERTIFICATE, &fileCount),
        CM_SUCCESS);
    EXPECT_EQ(fileCount, 2u);
    EXPECT_EQ(CmIsFileExist(userLayer.c_str(), "stray"), CMR_ERROR_NOT_EXIST);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
}

/**
 * @tc.name: CertManagerGetFilenames_001
 * @tc.desc: file name listing, empty directories and invalid arguments
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CertManagerGetFilenames_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string listDir = JoinPath(TEST_FILE_OP_ROOT, "list");
    MakeDirOrExists(listDir.c_str());

    /* invalid arguments */
    EXPECT_EQ(CertManagerGetFilenames(nullptr, listDir.c_str()), CMR_ERROR_INVALID_ARGUMENT);
    struct CmMutableBlob out = { 0, nullptr };
    EXPECT_EQ(CertManagerGetFilenames(&out, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* a missing directory fails to open */
    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(CertManagerGetFilenames(&out, missing.c_str()), CMR_ERROR_FILE_OPEN_DIR);

    /* an empty directory yields success without any entry */
    EXPECT_EQ(CertManagerGetFilenames(&out, listDir.c_str()), CM_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    EXPECT_EQ(out.size, 0u);

    /* two files are listed with their names */
    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    EXPECT_EQ(CmFileWrite(listDir.c_str(), "cert_a", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmFileWrite(listDir.c_str(), "cert_b", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CertManagerGetFilenames(&out, listDir.c_str()), CM_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_EQ(out.size, 2u);
    struct CmMutableBlob *entries = reinterpret_cast<struct CmMutableBlob *>(out.data);
    std::string firstName = reinterpret_cast<char *>(entries[0].data);
    std::string secondName = reinterpret_cast<char *>(entries[1].data);
    EXPECT_EQ((firstName == "cert_a" && secondName == "cert_b") ||
        (firstName == "cert_b" && secondName == "cert_a"), true);
    FreeFileNames(entries, out.size);
}

/**
 * @tc.name: CertManagerGetFilenames_002
 * @tc.desc: the certificate count limit rejects a directory with too many files
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CertManagerGetFilenames_002, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string manyDir = JoinPath(TEST_FILE_OP_ROOT, "many");
    MakeDirOrExists(manyDir.c_str());

    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    for (uint32_t i = 0; i <= MAX_COUNT_CERTIFICATE; i++) {
        std::string name = "cert_" + std::to_string(i);
        ASSERT_EQ(CmFileWrite(manyDir.c_str(), name.c_str(), 0, payload, payloadLen), CMR_OK);
    }

    struct CmMutableBlob out = { 0, nullptr };
    EXPECT_EQ(CertManagerGetFilenames(&out, manyDir.c_str()), CMR_ERROR_MAX_CERT_COUNT_REACHED);

    /* the plain counters agree with the file count */
    EXPECT_EQ(GetCertCount(manyDir.c_str()), static_cast<int32_t>(MAX_COUNT_CERTIFICATE + 1));
}

/**
 * @tc.name: GetCertCountAndDirs_001
 * @tc.desc: file and sub directory counting including missing directories
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, GetCertCountAndDirs_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string dir = JoinPath(TEST_FILE_OP_ROOT, "counts");
    MakeDirOrExists(dir.c_str());

    uint8_t payload[] = "x";
    uint32_t payloadLen = sizeof(payload) - 1;
    EXPECT_EQ(CmFileWrite(dir.c_str(), "cert_a", 0, payload, payloadLen), CMR_OK);
    EXPECT_EQ(CmFileWrite(dir.c_str(), "cert_b", 0, payload, payloadLen), CMR_OK);
    std::string sub1 = JoinPath(dir, "uid1");
    std::string sub2 = JoinPath(dir, "uid2");
    MakeDirOrExists(sub1.c_str());
    MakeDirOrExists(sub2.c_str());

    EXPECT_EQ(GetCertCount(dir.c_str()), 2);
    EXPECT_EQ(GetNumberOfDirs(dir.c_str()), 2);

    std::string missing = JoinPath(TEST_FILE_OP_ROOT, "missing");
    EXPECT_EQ(GetCertCount(missing.c_str()), CMR_ERROR_FILE_OPEN_DIR);
    EXPECT_EQ(GetNumberOfDirs(missing.c_str()), CMR_ERROR_FILE_OPEN_DIR);
}

/**
 * @tc.name: CmGetCertConfigStatus_001
 * @tc.desc: config status is disabled without a config file and enabled with one
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmGetCertConfigStatus_001, TestSize.Level0)
{
    /* invalid arguments */
    uint32_t status = CERT_STATUS_ENABLED;
    EXPECT_EQ(CmGetCertConfigStatus(nullptr, &status), CMR_ERROR_INVALID_ARGUMENT);
    const char *validUri = "oh:t=c;o=alias8899;u=8899;a=889901";
    EXPECT_EQ(CmGetCertConfigStatus(validUri, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* a malformed uri fails to decode */
    const char *badUri = "xx:t=c;o=alias;u=0;a=0";
    EXPECT_EQ(CmGetCertConfigStatus(badUri, &status), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* build the config tree for the isolated user: user_config/8899/889901 */
    std::string confRoot(CERT_BACKUP_CONFIG_ROOT_DIR);
    MakeDirOrExists(confRoot.c_str());
    std::string userDir = JoinPath(confRoot, std::to_string(TEST_STATUS_USER));
    MakeDirOrExists(userDir.c_str());
    std::string uidDir = JoinPath(userDir, std::to_string(TEST_STATUS_UID));
    MakeDirOrExists(uidDir.c_str());

    /* without a config file the status is disabled */
    status = CERT_STATUS_ENABLED;
    EXPECT_EQ(CmGetCertConfigStatus(validUri, &status), CM_SUCCESS);
    EXPECT_EQ(status, CERT_STATUS_DISABLED);

    /* with a config file the status is enabled */
    std::string confFile = JoinPath(uidDir, std::string(validUri) + CERT_CONFIG_FILE_SUFFIX);
    uint8_t payload[] = "x";
    EXPECT_EQ(CmFileWrite(nullptr, confFile.c_str(), 0, payload, sizeof(payload) - 1), CMR_OK);
    status = CERT_STATUS_DISABLED;
    EXPECT_EQ(CmGetCertConfigStatus(validUri, &status), CM_SUCCESS);
    EXPECT_EQ(status, CERT_STATUS_ENABLED);
}

/**
 * @tc.name: CmFileRemoveDirectory_001
 * @tc.desc: removing a directory through the file remove helper is rejected
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmFileRemoveDirectory_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);
    std::string dir = JoinPath(TEST_FILE_OP_ROOT, "subdir");
    MakeDirOrExists(dir.c_str());

    /* a directory is not a certificate file: the remove must fail loudly */
    EXPECT_EQ(CmFileRemove(TEST_FILE_OP_ROOT, "subdir"), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CertManagerFileRemove(TEST_FILE_OP_ROOT, "subdir"), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmIsDirExist(dir.c_str()), CMR_OK);
}

/**
 * @tc.name: CmUserBakupMakeDirEdge_001
 * @tc.desc: the backup directory maker rejects dot-dot paths and applies the default mode
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineFileOpTest, CmUserBakupMakeDirEdge_001, TestSize.Level0)
{
    MakeDirOrExists(TEST_FILE_OP_ROOT);

    /* paths containing a dot-dot segment are rejected before mkdir */
    std::string hostile = JoinPath(TEST_FILE_OP_ROOT, "a..b");
    EXPECT_EQ(CmUserBakupMakeDir(hostile.c_str(), nullptr), CMR_ERROR_MAKE_DIR_FAIL);
    EXPECT_EQ(CmIsDirExist(hostile.c_str()), CMR_ERROR_NOT_EXIST);

    /* without an explicit mode the default 0705 is applied */
    std::string dir = JoinPath(TEST_FILE_OP_ROOT, "default_mode_dir");
    EXPECT_EQ(CmUserBakupMakeDir(dir.c_str(), nullptr), CMR_OK);
    EXPECT_EQ(CmIsDirExist(dir.c_str()), CMR_OK);

    /* creating it again short circuits through the existence check */
    EXPECT_EQ(CmUserBakupMakeDir(dir.c_str(), nullptr), CMR_OK);
}
