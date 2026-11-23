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

#include "message_option.h"
#include "message_parcel.h"
#include "iremote_object.h"

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
    EXPECT_EQ(std::u16string(CLOUD_POLICY_SCENE.resourceParam), std::u16string(u"certRevocationPolicy"));
    EXPECT_STREQ(CLOUD_POLICY_SCENE.zipMember, CM_CLOUD_POLICY_FILE_NAME);
    EXPECT_STREQ(CLOUD_POLICY_SCENE.destDir, FORCE_CHECK_POLICY_DIR);
    EXPECT_STREQ(CLOUD_POLICY_SCENE.destFile, CM_CLOUD_POLICY_FILE_NAME);
    EXPECT_EQ(CLOUD_POLICY_SCENE.destMode, static_cast<mode_t>(0644));
}

/* a service-side stand-in for the process-internal round trip: it
 * records, field by field, the parcel the proxy forwarded */
class CmHsdrServiceStub : public IRemoteStub<CmHsdrInterface> {
public:
    /* the interface's forwarding entry is never driven in-process: the
     * test drives OnRemoteRequest below instead */
    int32_t InvokeHsdrAsync(const CloudResourceScene &scene,
        const sptr<IRemoteObject> &callback) override
    {
        (void)scene;
        (void)callback;
        return CMR_ERROR;
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        (void)reply;
        (void)option;
        code_ = code;
        token_ = data.ReadInterfaceToken();
        callerParam_ = data.ReadString16();
        resourceParam_ = data.ReadString16();
        callback_ = data.ReadRemoteObject();
        return CM_SUCCESS;
    }

    uint32_t code_ = 0;
    std::u16string token_;
    std::u16string callerParam_;
    std::u16string resourceParam_;
    sptr<IRemoteObject> callback_;
};

/*
 * RED: the proxy forwards the scene request as token (the proxy's own
 * descriptor, the fixed OHOS.Security.HSDR identity the service's
 * permission check keys on) + callerParam + resourceParam + the
 * callback object
 */
HWTEST_F(CmHsdrProtocolTest, ProxyRequestCarriesServiceTokenAndSceneParams, TestSize.Level0)
{
    sptr<CmHsdrServiceStub> service = new CmHsdrServiceStub();
    ASSERT_NE(service, nullptr);
    /* the local-interface shortcut: iface_cast hands out the stub itself
     * when the object locally implements the interface (the in-process
     * fast path), so the round trip builds the proxy directly; the
     * production caller gets the same proxy from iface_cast because its
     * remote comes from a cross-process connect */
    sptr<CmHsdrInterface> proxy = new CmHsdrProxy(service);
    ASSERT_NE(proxy, nullptr);

    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(CLOUD_POLICY_SCENE);
    ASSERT_NE(callback, nullptr);
    int32_t ret = proxy->InvokeHsdrAsync(CLOUD_POLICY_SCENE, callback->AsObject());
    EXPECT_EQ(ret, CM_SUCCESS);

    /* the request code is the scene's command */
    EXPECT_EQ(service->code_, CLOUD_POLICY_SCENE.cmdId);
    /* the token is the proxy's own descriptor, never a runtime-queried
     * value: the service's permission check keys on this identity */
    EXPECT_EQ(service->token_, std::u16string(u"OHOS.Security.HSDR"));
    EXPECT_EQ(service->callerParam_, std::u16string(u"com.huawei.certmanager"));
    EXPECT_EQ(service->resourceParam_, std::u16string(u"certRevocationPolicy"));
    /* the trailing remote object must arrive as a live binder object */
    ASSERT_NE(service->callback_, nullptr);
    EXPECT_EQ(service->callback_->GetInterfaceDescriptor(),
        std::u16string(u"OHOS.Security.CloudConnectCallback"));
}

/*
 * RED: a request without a callback object is refused on the spot, so
 * nothing is forwarded at all
 */
HWTEST_F(CmHsdrProtocolTest, ProxyRequestRejectsNullCallback, TestSize.Level0)
{
    sptr<CmHsdrServiceStub> service = new CmHsdrServiceStub();
    ASSERT_NE(service, nullptr);
    /* same direct construction as above: exercise the proxy itself */
    sptr<CmHsdrInterface> proxy = new CmHsdrProxy(service);
    ASSERT_NE(proxy, nullptr);

    EXPECT_NE(proxy->InvokeHsdrAsync(CLOUD_POLICY_SCENE, nullptr), CM_SUCCESS);
    EXPECT_EQ(service->code_, 0U);
    EXPECT_TRUE(service->token_.empty());
}

/*
 * RED: a callback parcel (token + result 0 + fd) driven straight into the
 * stub's OnRemoteRequest hands the byte-exact blob to the reader
 */
HWTEST_F(CmHsdrProtocolTest, CallbackStubDeliversZipBlob, TestSize.Level0)
{
    const std::string zipBytes = "PK\003\004-callback-fake-zip";
    ASSERT_TRUE(WriteReplyFile(zipBytes));
    int fd = OpenReplyFile();
    ASSERT_GE(fd, 0);

    MessageParcel callbackData;
    ASSERT_TRUE(callbackData.WriteInterfaceToken(
        std::u16string(u"OHOS.Security.CloudConnectCallback")));
    ASSERT_TRUE(callbackData.WriteInt32(0));
    ASSERT_TRUE(callbackData.WriteFileDescriptor(fd));

    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(CLOUD_POLICY_SCENE);
    ASSERT_NE(callback, nullptr);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = callback->OnRemoteRequest(0, callbackData, reply, option);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_TRUE(callback->HasResult());
    EXPECT_EQ(callback->GetResult(), CM_SUCCESS);

    struct CmBlob zipOut = { 0, nullptr };
    ASSERT_TRUE(callback->TakeZipBlob(zipOut));
    ASSERT_NE(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, static_cast<uint32_t>(zipBytes.size()));
    EXPECT_EQ(memcmp(zipOut.data, zipBytes.data(), zipBytes.size()), 0);
    CM_FREE_BLOB(zipOut);
    (void)close(fd);
}

/*
 * RED: a callback carrying a non-zero result code reports the failure
 * without ever touching the blob out slot
 */
HWTEST_F(CmHsdrProtocolTest, CallbackStubRejectsNonZeroResult, TestSize.Level0)
{
    MessageParcel callbackData;
    ASSERT_TRUE(callbackData.WriteInterfaceToken(
        std::u16string(u"OHOS.Security.CloudConnectCallback")));
    ASSERT_TRUE(callbackData.WriteInt32(42));

    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(CLOUD_POLICY_SCENE);
    ASSERT_NE(callback, nullptr);
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(callback->OnRemoteRequest(0, callbackData, reply, option), CM_SUCCESS);
    EXPECT_TRUE(callback->HasResult());
    EXPECT_NE(callback->GetResult(), CM_SUCCESS);

    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_FALSE(callback->TakeZipBlob(zipOut));
    EXPECT_EQ(zipOut.data, nullptr);
    EXPECT_EQ(zipOut.size, 0U);
}

/*
 * RED: a callback arriving with the wrong descriptor token is rejected
 * before any payload byte is consumed
 */
HWTEST_F(CmHsdrProtocolTest, CallbackStubRejectsForeignToken, TestSize.Level0)
{
    MessageParcel callbackData;
    ASSERT_TRUE(callbackData.WriteInterfaceToken(OTHER_TOKEN));
    ASSERT_TRUE(callbackData.WriteInt32(0));

    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(CLOUD_POLICY_SCENE);
    ASSERT_NE(callback, nullptr);
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(callback->OnRemoteRequest(0, callbackData, reply, option), CM_SUCCESS);
    EXPECT_TRUE(callback->HasResult());
    EXPECT_NE(callback->GetResult(), CM_SUCCESS);
}

/*
 * RED: Abandon before the callback arrives; a late callback then lands on
 * the abandoned stub and its blob is discarded without crashing the
 * reader that gave up
 */
HWTEST_F(CmHsdrProtocolTest, LateCallbackOnAbandonedStubIsDropped, TestSize.Level0)
{
    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(CLOUD_POLICY_SCENE);
    ASSERT_NE(callback, nullptr);
    callback->Abandon();
    EXPECT_FALSE(callback->HasResult());

    const std::string zipBytes = "PK\003\004-late-fake-zip";
    ASSERT_TRUE(WriteReplyFile(zipBytes));
    int fd = OpenReplyFile();
    ASSERT_GE(fd, 0);
    MessageParcel callbackData;
    ASSERT_TRUE(callbackData.WriteInterfaceToken(
        std::u16string(u"OHOS.Security.CloudConnectCallback")));
    ASSERT_TRUE(callbackData.WriteInt32(0));
    ASSERT_TRUE(callbackData.WriteFileDescriptor(fd));

    MessageParcel reply;
    MessageOption option;
    /* the late callback returns its parse status; the abandoned stub
     * reports no result either way and never hands out a blob */
    (void)callback->OnRemoteRequest(0, callbackData, reply, option);
    EXPECT_FALSE(callback->HasResult());
    struct CmBlob zipOut = { 0, nullptr };
    EXPECT_FALSE(callback->TakeZipBlob(zipOut));
    (void)close(fd);
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
