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

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "cm_cloud_policy_store.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
/* the three files that can live in forceCheck: the cfg/engine-owned user
 * policy this suite must not lose, plus the cloud policy and version state
 * this module owns and the cases exercise */
const std::string USER_POLICY_PATH = FORCE_CHECK_POLICY_FILE;
const std::string POLICY_PATH = FORCE_CHECK_POLICY_DIR "/" CM_CLOUD_POLICY_FILE_NAME;
const std::string VERSION_PATH = FORCE_CHECK_POLICY_DIR "/" CM_CLOUD_VERSION_FILE_NAME;
/* publish source staged outside forceCheck, as the real flow stages inside
 * cloud_tmp before publishing into forceCheck */
const char *SRC_PATH = "/data/local/tmp/cm_cloud_policy_store_test_src.tmp";

/* the preset policy content, hardcoded here byte-for-byte so a wrong
 * constant in the header cannot make the exactness test vacuous */
const char *PRESET_LINE_1 = "1,BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3\n";
const char *PRESET_LINE_2 = "1,8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782\n";

constexpr uint32_t READ_CHUNK = 4096;
constexpr mode_t MODE_0644 = 0644; /* published policy: readable by every consumer */
constexpr mode_t MODE_0600 = 0600; /* version counter: the service only */
constexpr mode_t MODE_0700 = 0700; /* staging dir: the service only */
constexpr mode_t MODE_0701 = 0701; /* forceCheck: the service cfg mode */

bool DirExists(const std::string &path)
{
    struct stat st = {};
    return (stat(path.c_str(), &st) == 0) && S_ISDIR(st.st_mode);
}

bool FileExists(const std::string &path)
{
    struct stat st = {};
    return (stat(path.c_str(), &st) == 0) && S_ISREG(st.st_mode);
}

bool ReadFileString(const std::string &path, std::string &out)
{
    FILE *fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) {
        return false;
    }
    out.clear();
    char chunk[READ_CHUNK] = {0};
    size_t readLen = 0;
    while ((readLen = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        out.append(chunk, readLen);
    }
    (void)fclose(fp);
    return true;
}

bool WriteFileString(const std::string &path, const std::string &content)
{
    FILE *fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        return false;
    }
    size_t written = content.empty() ? 0 : fwrite(content.data(), 1, content.size(), fp);
    int closeRet = fclose(fp);
    return (written == content.size()) && (closeRet == 0);
}

/* depth-first removal of a file or (small) directory tree; lstat based, so
 * a symlink is removed itself and never followed out of the tree */
void RemoveTree(const std::string &path)
{
    struct stat st = {};
    if (lstat(path.c_str(), &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path.c_str());
        return;
    }
    DIR *dp = opendir(path.c_str());
    if (dp != nullptr) {
        struct dirent *entry = nullptr;
        while ((entry = readdir(dp)) != nullptr) {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }
            RemoveTree(path + "/" + entry->d_name);
        }
        (void)closedir(dp);
    }
    (void)rmdir(path.c_str());
}
} // namespace

/* real paths, self-clean: the suite runs against the SA-owned forceCheck
 * directory, so SetUp stashes (and removes) everything present and TearDown
 * removes whatever the case left, then restores the stash -- a failed run
 * cannot leave a half-synced state behind on the device */
class CmCloudPolicyStoreTest : public testing::Test {
public:
    void SetUp() override
    {
        StashAndRemove(USER_POLICY_PATH, userPolicyStash_);
        StashAndRemove(POLICY_PATH, policyStash_);
        StashAndRemove(VERSION_PATH, versionStash_);
        /* "<file>.tmp" siblings are transient garbage on every path: removed,
         * never restored */
        (void)unlink((USER_POLICY_PATH + ".tmp").c_str());
        (void)unlink((POLICY_PATH + ".tmp").c_str());
        dirExisted_ = DirExists(FORCE_CHECK_POLICY_DIR);
        if (dirExisted_) {
            /* empty now: drop it so every case starts from a missing dir */
            (void)rmdir(FORCE_CHECK_POLICY_DIR);
        }
        /* no staging dir or src leftover from a crashed earlier run */
        RemoveTree(CmCloudStoreTmpDirPath());
        (void)unlink(SRC_PATH);
    }

    void TearDown() override
    {
        (void)unlink((USER_POLICY_PATH + ".tmp").c_str());
        (void)unlink((POLICY_PATH + ".tmp").c_str());
        (void)unlink(USER_POLICY_PATH.c_str());
        (void)unlink(POLICY_PATH.c_str());
        (void)unlink(VERSION_PATH.c_str());
        RemoveTree(CmCloudStoreTmpDirPath());
        (void)unlink(SRC_PATH);
        bool dirNow = DirExists(FORCE_CHECK_POLICY_DIR);
        if (dirExisted_ && !dirNow) {
            /* restore the cfg-owned directory the suite removed in SetUp */
            (void)mkdir(FORCE_CHECK_POLICY_DIR, MODE_0701);
        } else if (!dirExisted_ && dirNow) {
            /* leave no suite-created residue on a fresh device */
            (void)rmdir(FORCE_CHECK_POLICY_DIR);
        }
        RestoreStash(USER_POLICY_PATH, userPolicyStash_);
        RestoreStash(POLICY_PATH, policyStash_);
        RestoreStash(VERSION_PATH, versionStash_);
    }

private:
    struct Stash {
        bool present = false;
        std::string content;
        mode_t mode = 0;
    };

    static void StashAndRemove(const std::string &path, Stash &stash)
    {
        stash.present = false;
        struct stat st = {};
        if ((stat(path.c_str(), &st) != 0) || !S_ISREG(st.st_mode)) {
            return;
        }
        if (!ReadFileString(path, stash.content)) {
            return;
        }
        stash.present = true;
        stash.mode = st.st_mode & 0777;
        (void)unlink(path.c_str());
    }

    static void RestoreStash(const std::string &path, const Stash &stash)
    {
        if (!stash.present || !WriteFileString(path, stash.content)) {
            return;
        }
        (void)chmod(path.c_str(), stash.mode);
    }

    Stash userPolicyStash_;
    Stash policyStash_;
    Stash versionStash_;
    bool dirExisted_ = false;
};

/**
 * @tc.name: SelfHealCreatesAllThreeFiles
 * @tc.desc: from an empty forceCheck, self-heal creates the directory, the
 *           version file (0600, content "0") and the policy file (0644)
 */
HWTEST_F(CmCloudPolicyStoreTest, SelfHealCreatesAllThreeFiles, testing::ext::TestSize.Level0)
{
    EXPECT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);

    struct stat dirSt = {};
    EXPECT_EQ(stat(FORCE_CHECK_POLICY_DIR, &dirSt), 0);
    EXPECT_TRUE(S_ISDIR(dirSt.st_mode));

    struct stat policySt = {};
    ASSERT_EQ(stat(POLICY_PATH.c_str(), &policySt), 0);
    EXPECT_TRUE(S_ISREG(policySt.st_mode));
    EXPECT_EQ(policySt.st_mode & 0777, MODE_0644);

    struct stat versionSt = {};
    ASSERT_EQ(stat(VERSION_PATH.c_str(), &versionSt), 0);
    EXPECT_TRUE(S_ISREG(versionSt.st_mode));
    EXPECT_EQ(versionSt.st_mode & 0777, MODE_0600);

    std::string version;
    ASSERT_TRUE(ReadFileString(VERSION_PATH, version));
    EXPECT_EQ(version, std::string("0"));
}

/**
 * @tc.name: SelfHealWritesExactPresetLines
 * @tc.desc: the freshly healed policy file holds exactly the two preset
 *           lines, byte for byte, including both trailing newlines
 */
HWTEST_F(CmCloudPolicyStoreTest, SelfHealWritesExactPresetLines, testing::ext::TestSize.Level0)
{
    EXPECT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);

    std::string content;
    ASSERT_TRUE(ReadFileString(POLICY_PATH, content));
    EXPECT_EQ(content, std::string(PRESET_LINE_1) + PRESET_LINE_2);
}

/**
 * @tc.name: SelfHealIdempotentKeepsExisting
 * @tc.desc: a policy file and version that already exist are left untouched:
 *           the marker content and the stored version survive a re-run
 */
HWTEST_F(CmCloudPolicyStoreTest, SelfHealIdempotentKeepsExisting, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);

    const std::string marker = "1,SELFSYNCKEEPSTHISEXISTINGPOLICYCONTENTINTACT\n";
    ASSERT_TRUE(WriteFileString(POLICY_PATH, marker));
    ASSERT_EQ(CmCloudStoreWriteVersion(42), CM_SUCCESS);

    EXPECT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);

    std::string content;
    ASSERT_TRUE(ReadFileString(POLICY_PATH, content));
    EXPECT_EQ(content, marker);
    uint64_t version = 0;
    EXPECT_EQ(CmCloudStoreReadVersion(version), CM_SUCCESS);
    EXPECT_EQ(version, 42u);
}

/**
 * @tc.name: ReadVersionMissingReturnsZero
 * @tc.desc: a missing version.cfg reads as version 0 with CM_SUCCESS: the
 *           sync keeps gating on "no cloud content yet"
 */
HWTEST_F(CmCloudPolicyStoreTest, ReadVersionMissingReturnsZero, testing::ext::TestSize.Level0)
{
    /* the fixture removed the version file; nothing here re-creates it */
    uint64_t version = 12345; /* sentinel: the call must overwrite it */
    EXPECT_EQ(CmCloudStoreReadVersion(version), CM_SUCCESS);
    EXPECT_EQ(version, 0u);
}

/**
 * @tc.name: ReadVersionGarbageReturnsZero
 * @tc.desc: a malformed ("abc") or empty version.cfg reads as version 0
 */
HWTEST_F(CmCloudPolicyStoreTest, ReadVersionGarbageReturnsZero, testing::ext::TestSize.Level0)
{
    /* the fixture removed forceCheck; self-heal recreates the version file
     * this case overwrites with malformed content */
    ASSERT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);

    ASSERT_TRUE(WriteFileString(VERSION_PATH, "abc"));
    uint64_t version = 12345;
    EXPECT_EQ(CmCloudStoreReadVersion(version), CM_SUCCESS);
    EXPECT_EQ(version, 0u);

    ASSERT_TRUE(WriteFileString(VERSION_PATH, "")); /* empty file */
    version = 12345;
    EXPECT_EQ(CmCloudStoreReadVersion(version), CM_SUCCESS);
    EXPECT_EQ(version, 0u);
}

/**
 * @tc.name: VersionWriteReadRoundTrip
 * @tc.desc: a written version reads back unchanged
 */
HWTEST_F(CmCloudPolicyStoreTest, VersionWriteReadRoundTrip, testing::ext::TestSize.Level0)
{
    /* write targets forceCheck and does not create the dir itself */
    ASSERT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);
    ASSERT_EQ(CmCloudStoreWriteVersion(7), CM_SUCCESS);
    uint64_t version = 0;
    ASSERT_EQ(CmCloudStoreReadVersion(version), CM_SUCCESS);
    EXPECT_EQ(version, 7u);
}

/**
 * @tc.name: WriteVersionCreatesMode0600
 * @tc.desc: the version file lands as a regular file with mode 0600
 */
HWTEST_F(CmCloudPolicyStoreTest, WriteVersionCreatesMode0600, testing::ext::TestSize.Level0)
{
    /* write targets forceCheck and does not create the dir itself */
    ASSERT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);
    ASSERT_EQ(CmCloudStoreWriteVersion(3), CM_SUCCESS);

    struct stat st = {};
    ASSERT_EQ(stat(VERSION_PATH.c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_mode & 0777, MODE_0600);
}

/**
 * @tc.name: PublishFileReplacesAtomically
 * @tc.desc: publish replaces existing dest content with the source bytes,
 *           applies the requested mode, and leaves no ".tmp" behind
 */
HWTEST_F(CmCloudPolicyStoreTest, PublishFileReplacesAtomically, testing::ext::TestSize.Level0)
{
    /* publish targets forceCheck and does not create the directory itself */
    ASSERT_EQ(CmCloudStoreSelfHealPreset(), CM_SUCCESS);
    ASSERT_TRUE(WriteFileString(POLICY_PATH, "old content\n"));

    const std::string fresh = std::string(PRESET_LINE_1) + PRESET_LINE_2;
    ASSERT_TRUE(WriteFileString(SRC_PATH, fresh));
    /* an odd source mode proves the published mode comes from the argument,
     * not from the source file */
    ASSERT_EQ(chmod(SRC_PATH, MODE_0600), 0);

    EXPECT_EQ(CmCloudStorePublishFile(SRC_PATH, CM_CLOUD_POLICY_FILE_NAME, MODE_0644), CM_SUCCESS);

    std::string content;
    ASSERT_TRUE(ReadFileString(POLICY_PATH, content));
    EXPECT_EQ(content, fresh);
    EXPECT_FALSE(FileExists(POLICY_PATH + ".tmp"));
    struct stat st = {};
    ASSERT_EQ(stat(POLICY_PATH.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, MODE_0644);
}

/**
 * @tc.name: PublishFileFailsWhenDestDirMissing
 * @tc.desc: with forceCheck missing, publish fails and creates nothing
 */
HWTEST_F(CmCloudPolicyStoreTest, PublishFileFailsWhenDestDirMissing, testing::ext::TestSize.Level0)
{
    struct stat st = {};
    if (stat(FORCE_CHECK_POLICY_DIR, &st) == 0) {
        ASSERT_EQ(rmdir(FORCE_CHECK_POLICY_DIR), 0) << "forceCheck not empty, cannot stage missing-dir case";
    }
    ASSERT_TRUE(WriteFileString(SRC_PATH, "1,SOMEPOLICYCONTENT\n"));

    EXPECT_LT(CmCloudStorePublishFile(SRC_PATH, CM_CLOUD_POLICY_FILE_NAME, MODE_0644), 0);

    /* nothing was created under the missing directory */
    EXPECT_FALSE(DirExists(FORCE_CHECK_POLICY_DIR));
}

/**
 * @tc.name: TmpDirLifecycle
 * @tc.desc: prepare creates the staging dir 0700, cleanup removes it (also
 *           when absent, also with residual files inside)
 */
HWTEST_F(CmCloudPolicyStoreTest, TmpDirLifecycle, testing::ext::TestSize.Level0)
{
    EXPECT_STREQ(CmCloudStoreTmpDirPath(), REVOCATION_CACHE_BASE CM_CLOUD_TMP_DIR_NAME);

    EXPECT_EQ(CmCloudStorePrepareTmpDir(), CM_SUCCESS);
    struct stat st = {};
    ASSERT_EQ(stat(CmCloudStoreTmpDirPath(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));
    EXPECT_EQ(st.st_mode & 0777, MODE_0700);

    EXPECT_EQ(CmCloudStoreCleanupTmpDir(), CM_SUCCESS);
    EXPECT_FALSE(DirExists(CmCloudStoreTmpDirPath()));

    /* cleanup when absent is also success: the steady state between syncs */
    EXPECT_EQ(CmCloudStoreCleanupTmpDir(), CM_SUCCESS);
    EXPECT_FALSE(DirExists(CmCloudStoreTmpDirPath()));

    /* residual staged files are removed with the directory */
    ASSERT_EQ(CmCloudStorePrepareTmpDir(), CM_SUCCESS);
    ASSERT_TRUE(WriteFileString(std::string(CmCloudStoreTmpDirPath()) + "/staged.cfg", "staged\n"));
    EXPECT_EQ(CmCloudStoreCleanupTmpDir(), CM_SUCCESS);
    EXPECT_FALSE(DirExists(CmCloudStoreTmpDirPath()));
}
