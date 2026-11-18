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
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "message_parcel.h"

#include "cm_cloud_policy_store.h"
#include "cm_cloud_zip.h"
#include "cm_hsdr_protocol.h"
#include "cm_mem.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
/* the reply fd is staged through this scratch file, removed again in every
 * SetUp/TearDown: production code never looks here, so leftovers cannot
 * poison later runs */
const char *REPLY_ZIP_TMP = "/data/local/tmp/cm_hsdr_protocol_test_src.tmp";
/* an arbitrary token: pack/parse treat it as opaque, so any value
 * exercises the round trip and the mismatch branch */
const std::u16string TEST_TOKEN = u"ohos.hsdr.test.service";
const std::u16string OTHER_TOKEN = u"ohos.some.other.service";

/* write payload to the scratch file, truncating any previous run */
bool WriteReplyFile(const std::string &payload)
{
    FILE *fp = fopen(REPLY_ZIP_TMP, "wb");
    if (fp == nullptr) {
        return false;
    }
    size_t written = fwrite(payload.data(), 1, payload.size(), fp);
    (void)fclose(fp);
    return written == payload.size();
}

/* the fd handed to WriteFileDescriptor: the scratch file opened for
 * reading, positioned at its start */
int OpenReplyFile()
{
    return open(REPLY_ZIP_TMP, O_RDONLY);
}
} // namespace

class CmHsdrProtocolTest : public testing::Test {
public:
    void SetUp() override
    {
        (void)unlink(REPLY_ZIP_TMP);
    }

    void TearDown() override
    {
        (void)unlink(REPLY_ZIP_TMP);
    }
};

/* the scene table is the protocol contract, asserted field by field
 * against the requirement spec values */
HWTEST_F(CmHsdrProtocolTest, SceneTableMatchesSpec, TestSize.Level0)
{
    EXPECT_STREQ(CLOUD_POLICY_SCENE.bundleName, "com.huawei.hmos.hsdr");
    EXPECT_STREQ(CLOUD_POLICY_SCENE.abilityName, "HSDRService");
    EXPECT_EQ(CLOUD_POLICY_SCENE.cmdId, 4U);
    EXPECT_EQ(std::u16string(CLOUD_POLICY_SCENE.callerParam), std::u16string(u"com.huawei.certmanager"));
    EXPECT_EQ(std::u16string(CLOUD_POLICY_SCENE.resourceParam), std::u16string(u"certManagerConfig"));
    EXPECT_STREQ(CLOUD_POLICY_SCENE.zipMember, CM_CLOUD_POLICY_FILE_NAME);
    EXPECT_STREQ(CLOUD_POLICY_SCENE.destDir, FORCE_CHECK_POLICY_DIR);
    EXPECT_STREQ(CLOUD_POLICY_SCENE.destFile, CM_CLOUD_POLICY_FILE_NAME);
    EXPECT_EQ(CLOUD_POLICY_SCENE.destMode, static_cast<mode_t>(0644));
}

/* pack writes exactly token + the scene's two u16 parameters, in order */
HWTEST_F(CmHsdrProtocolTest, PackRequestWritesTokenAndParams, TestSize.Level0)
{
    MessageParcel data;
    int32_t ret = CmHsdrPackRequest(data, TEST_TOKEN, CLOUD_POLICY_SCENE);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(data.ReadInterfaceToken(), TEST_TOKEN);
    EXPECT_EQ(data.ReadString16(), std::u16string(u"com.huawei.certmanager"));
    EXPECT_EQ(data.ReadString16(), std::u16string(u"certManagerConfig"));
}

/* the happy path: token + result 0 + fd, the blob comes back byte-exact
 * and exactly as long as the file behind the fd */
HWTEST_F(CmHsdrProtocolTest, ParseReplySuccessReadsZipBytes, TestSize.Level0)
{
    const std::string zipBytes = "PK\003\004-fake-zip-payload";
    ASSERT_TRUE(WriteReplyFile(zipBytes));
    int fd = OpenReplyFile();
    ASSERT_GE(fd, 0);

    MessageParcel reply;
    ASSERT_TRUE(reply.WriteInterfaceToken(TEST_TOKEN));
    ASSERT_TRUE(reply.WriteInt32(0));
    ASSERT_TRUE(reply.WriteFileDescriptor(fd));

    struct CmBlob zipOut = { 0, nullptr };
    int32_t ret = CmHsdrParseReply(reply, TEST_TOKEN, CLOUD_POLICY_SCENE, zipOut);
    EXPECT_EQ(ret, CM_SUCCESS);
    ASSERT_NE(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, static_cast<uint32_t>(zipBytes.size()));
    EXPECT_EQ(memcmp(zipOut.data, zipBytes.data(), zipBytes.size()), 0);
    CM_FREE_BLOB(zipOut);
    (void)close(fd);
}

/* a reply token other than the request token is rejected before anything
 * else is consumed */
HWTEST_F(CmHsdrProtocolTest, ParseReplyTokenMismatchFails, TestSize.Level0)
{
    MessageParcel reply;
    ASSERT_TRUE(reply.WriteInterfaceToken(OTHER_TOKEN));
    ASSERT_TRUE(reply.WriteInt32(0));

    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_NE(CmHsdrParseReply(reply, TEST_TOKEN, CLOUD_POLICY_SCENE, zipOut), CM_SUCCESS);
    EXPECT_EQ(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, 0U);
}

/* any non-zero execution result is rejected */
HWTEST_F(CmHsdrProtocolTest, ParseReplyNonZeroRetFails, TestSize.Level0)
{
    MessageParcel reply;
    ASSERT_TRUE(reply.WriteInterfaceToken(TEST_TOKEN));
    ASSERT_TRUE(reply.WriteInt32(42));

    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_NE(CmHsdrParseReply(reply, TEST_TOKEN, CLOUD_POLICY_SCENE, zipOut), CM_SUCCESS);
    EXPECT_EQ(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, 0U);
}

/* a reply without the zip fd is rejected */
HWTEST_F(CmHsdrProtocolTest, ParseReplyMissingFdFails, TestSize.Level0)
{
    MessageParcel reply;
    ASSERT_TRUE(reply.WriteInterfaceToken(TEST_TOKEN));
    ASSERT_TRUE(reply.WriteInt32(0));

    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_NE(CmHsdrParseReply(reply, TEST_TOKEN, CLOUD_POLICY_SCENE, zipOut), CM_SUCCESS);
    EXPECT_EQ(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, 0U);
}

/* a fd behind a file one byte over the archive cap is rejected and no
 * blob is handed out */
HWTEST_F(CmHsdrProtocolTest, ParseReplyOversizedFdFails, TestSize.Level0)
{
    std::string oversized(static_cast<size_t>(CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE) + 1, 'x');
    ASSERT_TRUE(WriteReplyFile(oversized));
    int fd = OpenReplyFile();
    ASSERT_GE(fd, 0);

    MessageParcel reply;
    ASSERT_TRUE(reply.WriteInterfaceToken(TEST_TOKEN));
    ASSERT_TRUE(reply.WriteInt32(0));
    ASSERT_TRUE(reply.WriteFileDescriptor(fd));

    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_NE(CmHsdrParseReply(reply, TEST_TOKEN, CLOUD_POLICY_SCENE, zipOut), CM_SUCCESS);
    EXPECT_EQ(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, 0U);
    (void)close(fd);
}
