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

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "zip.h"

#include "cm_cloud_zip.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
/* the suite owns a scratch child of the revocation cache base: production
 * code never looks here, so leftovers cannot poison later runs */
const char *DEST_DIR = REVOCATION_CACHE_BASE "zip_test_tmp";
/* sibling the "../evil" member would land in if extraction ever escaped
 * destDir; it must never exist */
const char *ESCAPED_SIBLING = REVOCATION_CACHE_BASE "evil";
/* the bundle carries exactly one whitelisted member: the force-check
 * policy file name used by the real sync flow */
const char *POLICY_MEMBER = "certRevocationPolicy_cloud.cfg";
/* MakeZipBlob stages the built archive here before reading it back */
const char *ZIP_SRC_TMP = "/data/local/tmp/cm_cloud_zip_test_src.tmp";
/* two-line policy payload: <seq>,<64 uppercase hex pk hash> per line */
const char *POLICY_LINE_1 = "1,A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90\n";
const char *POLICY_LINE_2 = "2,0F1E2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A69788796A5B4C3D2E1F\n";
constexpr uint32_t READ_CHUNK = 4096;
constexpr mode_t EXPECTED_MEMBER_MODE = 0644; /* rw-r--r-- per the contract */
constexpr mode_t ENSURE_DIR_MODE = 0755; /* plain mode for the suite's own scratch dirs */

struct ZipEntry {
    std::string name;
    std::string data;
};

/* mkdir -p semantics; true when the full path exists as a directory */
bool EnsureDir(const std::string &path)
{
    size_t pos = 0;
    while (pos < path.size()) {
        size_t next = path.find('/', pos + 1);
        if (next == std::string::npos) {
            next = path.size();
        }
        std::string partial = path.substr(0, next);
        if (!partial.empty() && mkdir(partial.c_str(), ENSURE_DIR_MODE) != 0 && errno != EEXIST) {
            return false;
        }
        pos = next;
    }
    struct stat st = {};
    return (stat(path.c_str(), &st) == 0) && S_ISDIR(st.st_mode);
}

/* names of everything directly inside dir, "." and ".." excluded */
std::vector<std::string> ListDirEntries(const std::string &dir)
{
    std::vector<std::string> names;
    DIR *dp = opendir(dir.c_str());
    if (dp == nullptr) {
        return names;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dp)) != nullptr) {
        std::string name = entry->d_name;
        if ((name != ".") && (name != "..")) {
            names.push_back(name);
        }
    }
    (void)closedir(dp);
    return names;
}

/* depth-first removal of a file or (small) directory tree */
void RemoveTree(const std::string &path)
{
    struct stat st = {};
    if (stat(path.c_str(), &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path.c_str());
        return;
    }
    for (const auto &name : ListDirEntries(path)) {
        RemoveTree(path + "/" + name);
    }
    (void)rmdir(path.c_str());
}

bool FileExists(const std::string &path)
{
    struct stat st = {};
    return (stat(path.c_str(), &st) == 0) && S_ISREG(st.st_mode);
}

std::vector<uint8_t> ReadFileBytes(const std::string &path)
{
    std::vector<uint8_t> bytes;
    FILE *fp = fopen(path.c_str(), "rb");
    EXPECT_NE(fp, nullptr);
    if (fp == nullptr) {
        return bytes;
    }
    uint8_t chunk[READ_CHUNK] = {0};
    size_t readLen = 0;
    while ((readLen = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        bytes.insert(bytes.end(), chunk, chunk + readLen);
    }
    (void)fclose(fp);
    return bytes;
}

/* build a real zip on the fly with minizip's zip.c side, then read the
 * archive bytes back: the suite never trusts hand-rolled zip layouts */
std::vector<uint8_t> MakeZipBlob(const std::vector<ZipEntry> &entries)
{
    std::vector<uint8_t> bytes;
    zipFile zip = zipOpen(ZIP_SRC_TMP, APPEND_STATUS_CREATE);
    EXPECT_NE(zip, nullptr);
    if (zip == nullptr) {
        return bytes;
    }
    for (const auto &entry : entries) {
        EXPECT_EQ(zipOpenNewFileInZip(zip, entry.name.c_str(), nullptr, nullptr, 0, nullptr, 0,
            nullptr, Z_DEFLATED, Z_DEFAULT_COMPRESSION), ZIP_OK);
        if (!entry.data.empty()) {
            EXPECT_EQ(zipWriteInFileInZip(zip, entry.data.data(),
                static_cast<unsigned int>(entry.data.size())), ZIP_OK);
        }
        EXPECT_EQ(zipCloseFileInZip(zip), ZIP_OK);
    }
    EXPECT_EQ(zipClose(zip, nullptr), ZIP_OK);
    bytes = ReadFileBytes(ZIP_SRC_TMP);
    (void)unlink(ZIP_SRC_TMP);
    return bytes;
}

std::string PolicyContent()
{
    return std::string(POLICY_LINE_1) + POLICY_LINE_2;
}

struct CmBlob MakeBlob(std::vector<uint8_t> &bytes)
{
    return { static_cast<uint32_t>(bytes.size()), bytes.data() };
}
} // namespace

class CmCloudZipTest : public testing::Test {
public:
    void SetUp() override
    {
        RemoveTree(DEST_DIR); /* self-heal a crashed earlier run */
        ASSERT_TRUE(EnsureDir(DEST_DIR));
    }

    void TearDown() override
    {
        RemoveTree(DEST_DIR);
        (void)unlink(ESCAPED_SIBLING); /* must never exist; defensive only */
    }
};

/**
 * @tc.name: ExtractWhitelistedMemberSuccess
 * @tc.desc: single-member bundle: the whitelisted member lands in destDir,
 *           byte-identical, with mode 0644
 */
HWTEST_F(CmCloudZipTest, ExtractWhitelistedMemberSuccess, testing::ext::TestSize.Level0)
{
    std::string policy = PolicyContent();
    std::vector<uint8_t> blob = MakeZipBlob({ { POLICY_MEMBER, policy } });
    ASSERT_FALSE(blob.empty());
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_EQ(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), CM_SUCCESS);

    std::string destPath = std::string(DEST_DIR) + "/" + POLICY_MEMBER;
    EXPECT_TRUE(FileExists(destPath));
    std::vector<uint8_t> extracted = ReadFileBytes(destPath);
    ASSERT_EQ(extracted.size(), policy.size());
    EXPECT_EQ(memcmp(extracted.data(), policy.data(), policy.size()), 0);

    struct stat st = {};
    ASSERT_EQ(stat(destPath.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, EXPECTED_MEMBER_MODE);
}

/**
 * @tc.name: ExtractOnlyWhitelistedAmongOthers
 * @tc.desc: multi-member bundle: exactly the whitelisted member is written,
 *           every other member is ignored
 */
HWTEST_F(CmCloudZipTest, ExtractOnlyWhitelistedAmongOthers, testing::ext::TestSize.Level0)
{
    std::string policy = PolicyContent();
    std::vector<uint8_t> blob = MakeZipBlob({
        { "readme.txt", "not the policy\n" },
        { POLICY_MEMBER, policy },
        { "nested.bin", std::string(32, 0x7A) },
    });
    ASSERT_FALSE(blob.empty());
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_EQ(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), CM_SUCCESS);

    std::vector<std::string> left = ListDirEntries(DEST_DIR);
    ASSERT_EQ(left.size(), static_cast<size_t>(1));
    EXPECT_EQ(left[0], POLICY_MEMBER);
    std::vector<uint8_t> extracted = ReadFileBytes(std::string(DEST_DIR) + "/" + POLICY_MEMBER);
    ASSERT_EQ(extracted.size(), policy.size());
    EXPECT_EQ(memcmp(extracted.data(), policy.data(), policy.size()), 0);
}

/**
 * @tc.name: MissingWhitelistedMemberFails
 * @tc.desc: whitelist miss returns a negative code and leaves destDir empty
 */
HWTEST_F(CmCloudZipTest, MissingWhitelistedMemberFails, testing::ext::TestSize.Level0)
{
    std::vector<uint8_t> blob = MakeZipBlob({ { "unrelated.txt", "no policy here\n" } });
    ASSERT_FALSE(blob.empty());
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
}

/**
 * @tc.name: PathMemberNamesRejected
 * @tc.desc: traversal ("../evil") and nested ("sub/dir/f") member names
 *           never match the whitelist: no file lands inside or outside destDir
 */
HWTEST_F(CmCloudZipTest, PathMemberNamesRejected, testing::ext::TestSize.Level0)
{
    std::vector<uint8_t> blob = MakeZipBlob({
        { "../evil", "escape attempt\n" },
        { "sub/dir/f", "nested attempt\n" },
    });
    ASSERT_FALSE(blob.empty());
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
    EXPECT_FALSE(FileExists(ESCAPED_SIBLING));
    EXPECT_FALSE(FileExists(std::string(DEST_DIR) + "/sub"));
}

/**
 * @tc.name: OversizedMemberRejected
 * @tc.desc: a whitelisted member above CM_CLOUD_ZIP_MAX_MEMBER_SIZE is
 *           rejected before extraction starts; destDir stays empty
 */
HWTEST_F(CmCloudZipTest, OversizedMemberRejected, testing::ext::TestSize.Level0)
{
    std::vector<uint8_t> blob = MakeZipBlob(
        { { POLICY_MEMBER, std::string(CM_CLOUD_ZIP_MAX_MEMBER_SIZE + 1, 'A') } });
    ASSERT_FALSE(blob.empty());
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
}

/**
 * @tc.name: OversizedArchiveRejected
 * @tc.desc: a blob above CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE is rejected up front:
 *           not even the staged bundle.tmp appears in destDir
 */
HWTEST_F(CmCloudZipTest, OversizedArchiveRejected, testing::ext::TestSize.Level0)
{
    /* genuinely incompressible payload so the resulting zip file itself
     * exceeds the 1 MiB archive cap: xorshift64 over a fixed seed yields
     * deterministic, reproducible pseudo-random bytes DEFLATE cannot
     * shrink (stored blocks), and the shift/xor-only state arithmetic
     * cannot trip the unsigned-overflow sanitizer this binary is built
     * with; the production archive cap check fires before staging, so
     * this case exercises exactly the pre-stage rejection */
    uint64_t prngState = 0x9E3779B97F4A7C15ULL; /* fixed seed: reproducible */
    std::string big;
    big.reserve(CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE + 4096);
    for (size_t i = 0; i < static_cast<size_t>(CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE) + 4096; i++) {
        prngState ^= prngState << 13;
        prngState ^= prngState >> 7;
        prngState ^= prngState << 17;
        big.push_back(static_cast<char>(prngState & 0xFF));
    }
    std::vector<uint8_t> blob = MakeZipBlob({ { POLICY_MEMBER, big } });
    ASSERT_GT(blob.size(), static_cast<size_t>(CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE));
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
}

/**
 * @tc.name: GarbageInputFails
 * @tc.desc: non-zip bytes fail cleanly: negative code, no leftover file
 */
HWTEST_F(CmCloudZipTest, GarbageInputFails, testing::ext::TestSize.Level0)
{
    const char *garbage = "certainly not a zip archive, no local header at all";
    std::vector<uint8_t> blob(garbage, garbage + strlen(garbage));
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
}

/**
 * @tc.name: TruncatedZipFails
 * @tc.desc: a valid bundle cut in half fails cleanly: negative code, no
 *           leftover file
 */
HWTEST_F(CmCloudZipTest, TruncatedZipFails, testing::ext::TestSize.Level0)
{
    std::vector<uint8_t> blob = MakeZipBlob({ { POLICY_MEMBER, PolicyContent() } });
    /* the built bundle is far above 2x the 22-byte EOCD record, so the cut
     * half keeps the local header but definitely loses the central dir */
    ASSERT_GE(blob.size(), static_cast<size_t>(44));
    blob.resize(blob.size() / 2); /* cut away the central directory */
    struct CmBlob zipBlob = MakeBlob(blob);

    EXPECT_LT(CmCloudZipExtractWhitelisted(&zipBlob, POLICY_MEMBER, DEST_DIR), 0);
    EXPECT_TRUE(ListDirEntries(DEST_DIR).empty());
}
