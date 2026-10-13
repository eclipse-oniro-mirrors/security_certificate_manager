/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "message_parcel.h"

#include "cm_type_free.h"
#include "cm_ipc_response_type.h"
#include "cm_type.h"
#include "cm_mem.h"

namespace {
const uint32_t INVALID_LEN = 9000;
}

using namespace testing::ext;
namespace OHOS {
class CmIpcResponseTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmIpcResponseTypeTest::SetUpTestCase(void)
{
}

void CmIpcResponseTypeTest::TearDownTestCase(void)
{
}

void CmIpcResponseTypeTest::SetUp()
{
}

void CmIpcResponseTypeTest::TearDown()
{
}

/**
* @tc.name: CredentialDetailListMarshallingTest001
* @tc.desc: test Marshalling
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListMarshallingTest001, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    MessageParcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest001
* @tc.desc: test UnMarshalling
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest001, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    MessageParcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
    struct CredentialDetailListParcelInfo *credentialDetailListParcelInfo2 =
        CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_NE(credentialDetailListParcelInfo2, nullptr);
    CM_FREE_BLOB(credList.credential->credData);
    CM_FREE_PTR(credList.credential);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest002
* @tc.desc: test UnMarshalling abnormal
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest002, TestSize.Level0)
{
    struct CredentialDetailList *credListAbnormal = nullptr;
    CmFreeUkeyCertList(credListAbnormal);
    EXPECT_EQ(credListAbnormal, nullptr);
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(INVALID_LEN));
    credList.credential->credData.size = INVALID_LEN;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    MessageParcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
    struct CredentialDetailListParcelInfo *credentialDetailListParcelInfo2 =
        CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(credentialDetailListParcelInfo2, nullptr);
    CM_FREE_BLOB(credList.credential->credData);
    CM_FREE_PTR(credList.credential);
}


/**
* @tc.name: CredentialDetailListTransportTest001
* @tc.desc: test TransportCredential
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest001, TestSize.Level0)
{
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    struct CredentialDetailList destParcelInfo;
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    struct CredentialDetailList credList = {0, nullptr};
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credentialDetailListParcelInfo.credentialDetailList->credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    credList.credential->isExist = 1;
    (void)memset_s(credList.credential->type, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
    (void)memset_s(credList.credential->alias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    (void)memset_s(credList.credential->keyUri, MAX_LEN_URI, 0, MAX_LEN_URI);
    credList.credential->certNum = 1;
    credList.credential->keyNum = 1;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(1));
    credList.credential->credData.size = 1;
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(&destParcelInfo);
}

/**
* @tc.name: CredentialDetailListTransportTest002
* @tc.desc: test TransPortUkeyCertList with null this->credentialDetailList
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest002, TestSize.Level0)
{
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    /* credentialDetailList is nullptr by default */
    struct CredentialDetailList destParcelInfo = {0, nullptr};
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CredentialDetailListTransportTest003
* @tc.desc: test TransPortUkeyCertList with null credential in source
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest003, TestSize.Level0)
{
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    struct CredentialDetailList credList = {1, nullptr};
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    /* credential is nullptr */
    struct CredentialDetailList destParcelInfo = {0, nullptr};
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CredentialDetailListTransportTest004
* @tc.desc: test TransPortUkeyCertList with null dest argument
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest004, TestSize.Level0)
{
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    struct CredentialDetailList credList = {0, nullptr};
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    (void)memset_s(credList.credential, sizeof(struct Credential), 0, sizeof(struct Credential));
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    CM_FREE_PTR(credList.credential);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest003
* @tc.desc: test Unmarshalling with credentialCount > MAX_COUNT_UKEY_CERTIFICATE
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest003, TestSize.Level0)
{
    MessageParcel reply;
    /* Write an invalid credentialCount that exceeds MAX_COUNT_UKEY_CERTIFICATE */
    reply.WriteUint32(MAX_COUNT_UKEY_CERTIFICATE + 1);
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest004
* @tc.desc: test Unmarshalling with empty parcel (no credentialCount)
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest004, TestSize.Level0)
{
    MessageParcel reply;
    /* Empty parcel - ReadUint32 will fail */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListMarshallingTest002
* @tc.desc: test Marshalling with zero credentialCount
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListMarshallingTest002, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    MessageParcel reply;
    int32_t ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest005
* @tc.desc: test Unmarshalling with zero credentialCount
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest005, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(0); /* credentialCount = 0 */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_NE(info, nullptr);
    delete info;
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest006
* @tc.desc: test Unmarshalling with credentialCount=1 but no isExist data (ReadUint32 fails at L80)
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest006, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1, but no more data */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest007
* @tc.desc: test Unmarshalling - ReadCertInfoFromParcel fails (ReadUnpadBuffer returns nullptr at L27)
*           Write isExist but not enough data for type buffer
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest007, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    /* No more data - ReadUnpadBuffer(MAX_LEN_SUBJECT_NAME) returns nullptr */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest008
* @tc.desc: test Unmarshalling - ReadUnpadBuffer returns nullptr for alias (L35 B1)
*           Write type buffer but not alias buffer
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest008, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    /* Write type data (MAX_LEN_SUBJECT_NAME bytes) but no alias */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest009
* @tc.desc: test Unmarshalling - ReadUnpadBuffer returns nullptr for keyUri (L43 B1)
*           Write type and alias but not keyUri
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest009, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    std::vector<uint8_t> aliasBuf(MAX_LEN_CERT_ALIAS, 0);
    reply.WriteBuffer(aliasBuf.data(), MAX_LEN_CERT_ALIAS);
    /* No keyUri data */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest010
* @tc.desc: test Unmarshalling - ReadUint32 fails for credDataSize (L56 B0)
*           Write type, alias, keyUri but no credDataSize
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest010, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    std::vector<uint8_t> aliasBuf(MAX_LEN_CERT_ALIAS, 0);
    reply.WriteBuffer(aliasBuf.data(), MAX_LEN_CERT_ALIAS);
    std::vector<uint8_t> keyUriBuf(MAX_LEN_URI, 0);
    reply.WriteBuffer(keyUriBuf.data(), MAX_LEN_URI);
    /* No credDataSize */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest011
* @tc.desc: test Unmarshalling - ReadUint32 fails for certNum (L90)
*           Write through credData but not certNum
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest011, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    std::vector<uint8_t> aliasBuf(MAX_LEN_CERT_ALIAS, 0);
    reply.WriteBuffer(aliasBuf.data(), MAX_LEN_CERT_ALIAS);
    std::vector<uint8_t> keyUriBuf(MAX_LEN_URI, 0);
    reply.WriteBuffer(keyUriBuf.data(), MAX_LEN_URI);
    reply.WriteUint32(1); /* credDataSize = 1 */
    std::vector<uint8_t> credData(1, 0);
    reply.WriteBuffer(credData.data(), 1);
    /* No certNum */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest012
* @tc.desc: test Unmarshalling - ReadUint32 fails for keyNum (L94)
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest012, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    std::vector<uint8_t> aliasBuf(MAX_LEN_CERT_ALIAS, 0);
    reply.WriteBuffer(aliasBuf.data(), MAX_LEN_CERT_ALIAS);
    std::vector<uint8_t> keyUriBuf(MAX_LEN_URI, 0);
    reply.WriteBuffer(keyUriBuf.data(), MAX_LEN_URI);
    reply.WriteUint32(1); /* credDataSize = 1 */
    std::vector<uint8_t> credData(1, 0);
    reply.WriteBuffer(credData.data(), 1);
    reply.WriteUint32(1); /* certNum = 1 */
    /* No keyNum */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListUnMarshallingTest013
* @tc.desc: test Unmarshalling - ReadUint32 fails for certPurpose (L139)
*           Full credential but no certPurpose
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListUnMarshallingTest013, TestSize.Level0)
{
    MessageParcel reply;
    reply.WriteUint32(1); /* credentialCount = 1 */
    reply.WriteUint32(1); /* isExist = 1 */
    std::vector<uint8_t> typeBuf(MAX_LEN_SUBJECT_NAME, 0);
    reply.WriteBuffer(typeBuf.data(), MAX_LEN_SUBJECT_NAME);
    std::vector<uint8_t> aliasBuf(MAX_LEN_CERT_ALIAS, 0);
    reply.WriteBuffer(aliasBuf.data(), MAX_LEN_CERT_ALIAS);
    std::vector<uint8_t> keyUriBuf(MAX_LEN_URI, 0);
    reply.WriteBuffer(keyUriBuf.data(), MAX_LEN_URI);
    reply.WriteUint32(1); /* credDataSize = 1 */
    std::vector<uint8_t> credData(1, 0);
    reply.WriteBuffer(credData.data(), 1);
    reply.WriteUint32(1); /* certNum = 1 */
    reply.WriteUint32(1); /* keyNum = 1 */
    /* No certPurpose */
    struct CredentialDetailListParcelInfo *info = CredentialDetailListParcelInfo::Unmarshalling(reply);
    EXPECT_EQ(info, nullptr);
}

/**
* @tc.name: CredentialDetailListMarshallingTest003
* @tc.desc: test Marshalling with null credential in list (WriteCredentialToParcel handles null)
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListMarshallingTest003, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credList.credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    (void)memset_s(credList.credential, sizeof(struct Credential), 0, sizeof(struct Credential));
    /* credData.data is nullptr, size = 0 - WriteBuffer with nullptr data returns false */
    credList.credential->credData.size = 0;
    credList.credential->credData.data = nullptr;
    MessageParcel reply;
    bool ret = credentialDetailListParcelInfo.Marshalling(reply);
    EXPECT_EQ(ret, false);
    CM_FREE_PTR(credList.credential);
}

/**
* @tc.name: CredentialDetailListTransportTest005
* @tc.desc: test TransPortUkeyCertList with valid data and verify dest fields
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest005, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credList.credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    (void)memset_s(credList.credential, sizeof(struct Credential), 0, sizeof(struct Credential));
    credList.credential->isExist = 1;
    credList.credential->certNum = 2;
    credList.credential->keyNum = 3;
    credList.credential->credData.size = 4;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(4));
    credList.credential->certPurpose = static_cast<enum CmCertificatePurpose>(1);
    struct CredentialDetailList destParcelInfo = {0, nullptr};
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(destParcelInfo.credentialCount, 1);
    EXPECT_EQ(destParcelInfo.credential[0].isExist, 1);
    EXPECT_EQ(destParcelInfo.credential[0].certNum, 2);
    EXPECT_EQ(destParcelInfo.credential[0].keyNum, 3);
    EXPECT_EQ(destParcelInfo.credential[0].credData.size, 4);
    EXPECT_EQ(destParcelInfo.credential[0].certPurpose, static_cast<enum CmCertificatePurpose>(1));
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(&destParcelInfo);
}

/**
* @tc.name: CredentialDetailListTransportTest006
* @tc.desc: test TransPortUkeyCertList with credData.size = 0 (CmMalloc(0) path)
* @tc.type: FUNC
*/
HWTEST_F(CmIpcResponseTypeTest, CredentialDetailListTransportTest006, TestSize.Level0)
{
    struct CredentialDetailList credList = {0, nullptr};
    struct CredentialDetailListParcelInfo credentialDetailListParcelInfo;
    credentialDetailListParcelInfo.credentialDetailList = &credList;
    credList.credentialCount = 1;
    credList.credential = static_cast<struct Credential*>(CmMalloc(sizeof(struct Credential)));
    (void)memset_s(credList.credential, sizeof(struct Credential), 0, sizeof(struct Credential));
    credList.credential->isExist = 1;
    credList.credential->credData.size = 4;
    credList.credential->credData.data = static_cast<uint8_t*>(CmMalloc(4));
    struct CredentialDetailList destParcelInfo = {0, nullptr};
    int32_t ret = credentialDetailListParcelInfo.TransPortUkeyCertList(&destParcelInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    CmFreeUkeyCertList(&credList);
    CmFreeUkeyCertList(&destParcelInfo);
}
} // end of namespace
