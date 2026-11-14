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

#include <climits>
#include <cstring>
#include <string>

#include "cert_manager_check.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_double_list.h"
#include "cert_manager_mem.h"
#include "cert_manager_uri.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;

namespace {
constexpr uint32_t TEST_URI_USER = 8899;
constexpr uint32_t TEST_URI_UID = 889901;

struct TestListNode {
    struct DoubleList listHead;
    uint32_t value;
};
} // namespace

class CmEngineUriTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}

    static void TearDownTestCase(void) {}

    void SetUp() {}

    void TearDown() {}
};

/**
 * @tc.name: CertManagerUriEncode_001
 * @tc.desc: encode a uri with all path and query components, then verify the string
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriEncode_001, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("objName");
    uri.type = CM_URI_TYPE_APP_KEY;
    uri.user = const_cast<char *>("8899");
    uri.app = const_cast<char *>("889901");
    uri.clientUser = const_cast<char *>("100");
    uri.clientApp = const_cast<char *>("200");
    uri.mac = const_cast<char *>("aabb");

    uint32_t needLen = 0;
    int32_t ret = CertManagerUriEncode(nullptr, &needLen, &uri);
    EXPECT_EQ(ret, CM_SUCCESS);
    const char *expect = "oh:t=ak;o=objName;u=8899;a=889901?cu=100&ca=200&m=aabb";
    EXPECT_EQ(needLen, static_cast<uint32_t>(strlen(expect)) + 1); /* include '\0' */

    char buf[MAX_LEN_URI] = { 0 };
    uint32_t bufLen = sizeof(buf);
    ret = CertManagerUriEncode(buf, &bufLen, &uri);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(strcmp(buf, expect), 0);
    EXPECT_EQ(bufLen, static_cast<uint32_t>(strlen(expect))); /* returned len excludes '\0' */
}

/**
 * @tc.name: CertManagerUriEncode_002
 * @tc.desc: encode with invalid arguments
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriEncode_002, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("obj");
    uri.type = CM_URI_TYPE_CERTIFICATE;
    uri.user = const_cast<char *>("0");
    uri.app = const_cast<char *>("0");

    char buf[MAX_LEN_URI] = { 0 };
    uint32_t bufLen = sizeof(buf);
    /* type beyond CM_URI_TYPE_MAX */
    struct CMUri badType = uri;
    badType.type = CM_URI_TYPE_MAX + 1;
    EXPECT_EQ(CertManagerUriEncode(buf, &bufLen, &badType), CMR_ERROR_INVALID_ARGUMENT);
    /* null length out */
    EXPECT_EQ(CertManagerUriEncode(buf, nullptr, &uri), CMR_ERROR_INVALID_ARGUMENT);
    /* null uri */
    EXPECT_EQ(CertManagerUriEncode(buf, &bufLen, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CertManagerUriEncode_003
 * @tc.desc: encode with a buffer that is too small
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriEncode_003, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("objName");
    uri.type = CM_URI_TYPE_APP_KEY;
    uri.user = const_cast<char *>("8899");
    uri.app = const_cast<char *>("889901");

    uint32_t needLen = 0;
    (void)CertManagerUriEncode(nullptr, &needLen, &uri);
    char buf[MAX_LEN_URI] = { 0 };
    uint32_t bufLen = needLen - 1; /* one byte short */
    EXPECT_EQ(CertManagerUriEncode(buf, &bufLen, &uri), CMR_ERROR_BUFFER_TOO_SMALL);
}

/**
 * @tc.name: CertManagerUriEncode_004
 * @tc.desc: reserved characters are percent-encoded in path and query
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriEncode_004, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("a#b"); /* '#' is reserved in path */
    uri.type = CM_URI_TYPE_CERTIFICATE;
    uri.user = const_cast<char *>("0");
    uri.app = const_cast<char *>("0");
    uri.mac = const_cast<char *>("m n"); /* ' ' is reserved in query */

    char buf[MAX_LEN_URI] = { 0 };
    uint32_t bufLen = sizeof(buf);
    EXPECT_EQ(CertManagerUriEncode(buf, &bufLen, &uri), CM_SUCCESS);
    EXPECT_EQ(strcmp(buf, "oh:t=c;o=a%23b;u=0;a=0?m=m%20n"), 0);
}

/**
 * @tc.name: CertManagerUriDecode_001
 * @tc.desc: decode a well formed uri and check every field
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_001, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    const char *encoded = "oh:t=sk;o=mySysCert;u=0;a=0?cu=100&ca=200&m=deadbeef";
    EXPECT_EQ(CertManagerUriDecode(&uri, encoded), CM_SUCCESS);
    EXPECT_EQ(uri.type, CM_URI_TYPE_SYS_KEY);
    ASSERT_NE(uri.object, nullptr);
    EXPECT_EQ(strcmp(uri.object, "mySysCert"), 0);
    ASSERT_NE(uri.user, nullptr);
    EXPECT_EQ(strcmp(uri.user, "0"), 0);
    ASSERT_NE(uri.app, nullptr);
    EXPECT_EQ(strcmp(uri.app, "0"), 0);
    ASSERT_NE(uri.clientUser, nullptr);
    EXPECT_EQ(strcmp(uri.clientUser, "100"), 0);
    ASSERT_NE(uri.clientApp, nullptr);
    EXPECT_EQ(strcmp(uri.clientApp, "200"), 0);
    ASSERT_NE(uri.mac, nullptr);
    EXPECT_EQ(strcmp(uri.mac, "deadbeef"), 0);
    EXPECT_EQ(CertManagerFreeUri(&uri), CMR_OK);
}

/**
 * @tc.name: CertManagerUriDecode_002
 * @tc.desc: decode rejects null args, oversized input and bad scheme
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_002, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    EXPECT_EQ(CertManagerUriDecode(nullptr, "oh:t=c;o=a;u=0;a=0"), CMR_ERROR_INVALID_ARGUMENT_URI);
    EXPECT_EQ(CertManagerUriDecode(&uri, nullptr), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* longer than MAX_AUTH_LEN_URI */
    std::string tooLong = "oh:t=c;o=";
    tooLong.append(MAX_AUTH_LEN_URI, 'x');
    EXPECT_EQ(CertManagerUriDecode(&uri, tooLong.c_str()), CMR_ERROR_INVALID_ARGUMENT_URI);

    /* wrong scheme */
    EXPECT_EQ(CertManagerUriDecode(&uri, "xx:t=c;o=a;u=0;a=0"), CMR_ERROR_INVALID_ARGUMENT_URI);
    /* empty string (scheme mismatch) */
    EXPECT_EQ(CertManagerUriDecode(&uri, ""), CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CertManagerUriDecode_003
 * @tc.desc: decode rejects malformed path/query fields
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_003, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    /* unknown path field */
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:x=1;t=c;o=a;u=0;a=0"), CMR_ERROR_INVALID_ARGUMENT_URI);
    /* component starts with separator */
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:;t=c;o=a;u=0;a=0"), CMR_ERROR_INVALID_ARGUMENT_URI);
    /* unknown query field */
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=c;o=a;u=0;a=0?z=1"), CMR_ERROR_INVALID_ARGUMENT_URI);
    /* query component starts with separator */
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=c;o=a;u=0;a=0?&ca=1"), CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CertManagerUriDecode_004
 * @tc.desc: unknown type string decodes to an invalid type value
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_004, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=zz;o=a;u=0;a=0"), CM_SUCCESS);
    /* TYPE_COUNT + 1 is returned when no type string matches */
    EXPECT_EQ(uri.type, TYPE_COUNT + 1);
    EXPECT_EQ(CertManagerFreeUri(&uri), CMR_OK);
}

/**
 * @tc.name: CertManagerUriDecode_005
 * @tc.desc: percent escape sequences are decoded in component values
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_005, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=ak;o=%41%42;u=0;a=0"), CM_SUCCESS);
    ASSERT_NE(uri.object, nullptr);
    EXPECT_EQ(strcmp(uri.object, "AB"), 0);
    EXPECT_EQ(CertManagerFreeUri(&uri), CMR_OK);
}

/**
 * @tc.name: CertManagerUriDecode_006
 * @tc.desc: repeated fields keep the last value, empty values decode to null
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerUriDecode_006, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=ak;o=first;o=second;u=0;a=0"), CM_SUCCESS);
    ASSERT_NE(uri.object, nullptr);
    EXPECT_EQ(strcmp(uri.object, "second"), 0);
    EXPECT_EQ(CertManagerFreeUri(&uri), CMR_OK);

    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    EXPECT_EQ(CertManagerUriDecode(&uri, "oh:t=ak;o=;u=0;a=0"), CM_SUCCESS);
    EXPECT_EQ(uri.object, nullptr);
    EXPECT_EQ(CertManagerFreeUri(&uri), CMR_OK);
}

/**
 * @tc.name: CertManagerGetUidFromUri_001
 * @tc.desc: extract the numeric uid from the app field
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerGetUidFromUri_001, TestSize.Level0)
{
    uint8_t validUri[] = "oh:t=ak;o=keyA;u=8899;a=889901";
    struct CmBlob uri = { sizeof(validUri), validUri };
    uint32_t uid = 0;
    EXPECT_EQ(CertManagerGetUidFromUri(&uri, &uid), CM_SUCCESS);
    EXPECT_EQ(uid, TEST_URI_UID);

    uint8_t noAppUri[] = "oh:t=ak;o=keyA;u=8899";
    struct CmBlob noApp = { sizeof(noAppUri), noAppUri };
    EXPECT_EQ(CertManagerGetUidFromUri(&noApp, &uid), CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t badAppUri[] = "oh:t=ak;o=keyA;u=8899;a=xyz";
    struct CmBlob badApp = { sizeof(badAppUri), badAppUri };
    EXPECT_EQ(CertManagerGetUidFromUri(&badApp, &uid), CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmConstructUri_001
 * @tc.desc: build a heap uri blob that carries the terminating zero
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmConstructUri_001, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("keyA");
    uri.type = CM_URI_TYPE_APP_KEY;
    uri.user = const_cast<char *>("8899");
    uri.app = const_cast<char *>("889901");

    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmConstructUri(&uri, &out), CM_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(out.data), "oh:t=ak;o=keyA;u=8899;a=889901"), 0);
    EXPECT_EQ(out.size, static_cast<uint32_t>(strlen("oh:t=ak;o=keyA;u=8899;a=889901")) + 1);
    CM_FREE_BLOB(out);
}

/**
 * @tc.name: CmConstructUri_002
 * @tc.desc: constructing with an invalid type fails
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmConstructUri_002, TestSize.Level0)
{
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));
    uri.object = const_cast<char *>("keyA");
    uri.type = CM_URI_TYPE_MAX + 1;
    uri.user = const_cast<char *>("8899");
    uri.app = const_cast<char *>("889901");
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmConstructUri(&uri, &out), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmConstructCommonUri_001
 * @tc.desc: build the common uri from a context and an alias
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmConstructCommonUri_001, TestSize.Level0)
{
    struct CmContext context = { TEST_URI_USER, TEST_URI_UID, { 0 } };
    uint8_t aliasBuf[] = "alias8899";
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmConstructCommonUri(&context, CM_URI_TYPE_CERTIFICATE, &alias, &out), CM_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(out.data), "oh:t=c;o=alias8899;u=8899;a=889901"), 0);
    CM_FREE_BLOB(out);
}

/**
 * @tc.name: CertManagerIsKeyObjectType_001
 * @tc.desc: only app-key and wlan-key are key object types
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CertManagerIsKeyObjectType_001, TestSize.Level0)
{
    EXPECT_TRUE(CertManagerIsKeyObjectType(CM_URI_TYPE_APP_KEY));
    EXPECT_TRUE(CertManagerIsKeyObjectType(CM_URI_TYPE_WLAN_KEY));
    EXPECT_FALSE(CertManagerIsKeyObjectType(CM_URI_TYPE_CERTIFICATE));
    EXPECT_FALSE(CertManagerIsKeyObjectType(CM_URI_TYPE_MAC_KEY));
    EXPECT_FALSE(CertManagerIsKeyObjectType(CM_URI_TYPE_SYS_KEY));
}

/**
 * @tc.name: CmDoubleList_001
 * @tc.desc: init/add-tail/remove keeps the ring consistent
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmDoubleList_001, TestSize.Level0)
{
    struct DoubleList head;
    CmInitList(&head);
    EXPECT_EQ(head.next, &head);
    EXPECT_EQ(head.prev, &head);

    struct TestListNode node1 = { { nullptr, nullptr }, 1 };
    struct TestListNode node2 = { { nullptr, nullptr }, 2 };
    struct TestListNode node3 = { { nullptr, nullptr }, 3 };
    CmAddNodeAtListTail(&head, &node1.listHead);
    CmAddNodeAtListTail(&head, &node2.listHead);
    CmAddNodeAtListTail(&head, &node3.listHead);

    /* head -> node1 -> node2 -> node3 -> head */
    uint32_t values[3] = { 0 };
    struct DoubleList *p = head.next;
    for (uint32_t i = 0; i < 3 && p != &head; i++, p = p->next) {
        values[i] = (reinterpret_cast<struct TestListNode *>(p))->value;
    }
    EXPECT_EQ(values[0], 1);
    EXPECT_EQ(values[1], 2);
    EXPECT_EQ(values[2], 3);

    /* remove the middle node, the ring must stay walkable */
    CmRemoveNodeFromList(&node2.listHead);
    EXPECT_EQ(node2.listHead.next, nullptr);
    EXPECT_EQ(node2.listHead.prev, nullptr);
    EXPECT_EQ(head.next, &node1.listHead);
    EXPECT_EQ(node1.listHead.next, &node3.listHead);
    EXPECT_EQ(node3.listHead.next, &head);

    /* null args are tolerated */
    CmInitList(nullptr);
    CmAddNodeAtListTail(nullptr, &node1.listHead);
    CmAddNodeAtListTail(&head, nullptr);
    CmRemoveNodeFromList(nullptr);
}

/**
 * @tc.name: CmDoubleList_002
 * @tc.desc: add-after-head inserts in stack order and repairs a null next
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmDoubleList_002, TestSize.Level0)
{
    struct DoubleList head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head)); /* next/prev are null */
    struct TestListNode node1 = { { nullptr, nullptr }, 1 };
    struct TestListNode node2 = { { nullptr, nullptr }, 2 };

    /* head.next == null is repaired to point at itself first */
    CmAddNodeAfterListHead(&head, &node1.listHead);
    EXPECT_EQ(head.next, &node1.listHead);
    EXPECT_EQ(node1.listHead.next, &head);
    EXPECT_EQ(node1.listHead.prev, &head);

    CmAddNodeAfterListHead(&head, &node2.listHead);
    EXPECT_EQ(head.next, &node2.listHead);
    EXPECT_EQ(node2.listHead.next, &node1.listHead);

    /* null args are tolerated */
    CmAddNodeAfterListHead(nullptr, &node1.listHead);
    CmAddNodeAfterListHead(&head, nullptr);
}

/**
 * @tc.name: CmMem_001
 * @tc.desc: CMMalloc/CMFree wrap the libc allocator and accept null
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmMem_001, TestSize.Level0)
{
    uint8_t *buf = static_cast<uint8_t *>(CMMalloc(16));
    ASSERT_NE(buf, nullptr);
    (void)memset_s(buf, 16, 0xAB, 16);
    EXPECT_EQ(buf[0], 0xAB);
    CMFree(buf);
    CMFree(nullptr); /* must not crash */

    EXPECT_EQ(CMMalloc(SIZE_MAX), nullptr); /* allocation of a huge size fails */
}

/**
 * @tc.name: CmGetRandom_001
 * @tc.desc: random generation validates its blob and fills the buffer
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmGetRandom_001, TestSize.Level0)
{
    uint8_t buf[DIGEST_SHA256_LEN] = { 0 };
    struct CmBlob random = { sizeof(buf), buf };
    EXPECT_EQ(CmGetRandom(&random), CM_SUCCESS);

    struct CmBlob invalid = { sizeof(buf), nullptr };
    EXPECT_EQ(CmGetRandom(&invalid), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetHash_001
 * @tc.desc: sha256 hash requires a 32 byte output buffer
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, CmGetHash_001, TestSize.Level0)
{
    uint8_t data[] = "hello world";
    struct CmBlob in = { sizeof(data) - 1, data };

    uint8_t hashBuf[DIGEST_SHA256_LEN] = { 0 };
    struct CmBlob hash = { sizeof(hashBuf), hashBuf };
    EXPECT_EQ(CmGetHash(&in, &hash), CM_SUCCESS);
    EXPECT_EQ(hash.size, DIGEST_SHA256_LEN);

    uint8_t smallBuf[DIGEST_SHA256_LEN - 1] = { 0 };
    struct CmBlob small = { sizeof(smallBuf), smallBuf };
    EXPECT_EQ(CmGetHash(&in, &small), CMR_ERROR_INVALID_ARGUMENT);

    EXPECT_EQ(CmGetHash(nullptr, &hash), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: GetNameEncode_001
 * @tc.desc: name encoding is sha256 + base64url and is deterministic
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUriTest, GetNameEncode_001, TestSize.Level0)
{
    uint8_t inBuf[100] = { 0 };
    for (uint32_t i = 0; i < sizeof(inBuf); i++) {
        inBuf[i] = static_cast<uint8_t>(i);
    }
    struct CmBlob in = { sizeof(inBuf), inBuf };

    uint8_t outBuf1[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob out1 = { sizeof(outBuf1), outBuf1 };
    EXPECT_EQ(GetNameEncode(&in, &out1), CM_SUCCESS);
    /* sha256 base64url fills 44 chars: the final char of the partial group is
       the zero-value table entry 'A' (no NUL is written inside the size) */
    EXPECT_EQ(out1.size, 44);
    EXPECT_EQ(out1.data[43], 'A');

    uint8_t outBuf2[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob out2 = { sizeof(outBuf2), outBuf2 };
    EXPECT_EQ(GetNameEncode(&in, &out2), CM_SUCCESS);
    EXPECT_EQ(memcmp(out1.data, out2.data, out1.size), 0);

    EXPECT_EQ(GetNameEncode(nullptr, &out1), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetNameEncode(&in, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}
