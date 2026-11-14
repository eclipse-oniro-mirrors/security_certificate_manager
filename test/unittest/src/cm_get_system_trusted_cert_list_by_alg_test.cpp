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
#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cert_manager_api.h"
#include "cert_manager_query.h"
#include "cm_mem.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static uint32_t PATH_COUNT = 1;
static uint32_t g_selfTokenId = 0;

static uint32_t CountKeptCerts(const struct CertBlob *certBlob, uint32_t total)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < total; i++) {
        if (certBlob->uri[i].size != 0) {
            n++;
        }
    }
    return n;
}
}

class CmGetSystemTrustedCertListByAlgTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    struct CmContext context{};
    struct CmMutableBlob pathList{0, nullptr};
    struct CmMutableBlob certFileList{0, nullptr};
    struct CertBlob certBlob{};
    uint32_t status[MAX_COUNT_CERTIFICATE_ALL]{};
    struct CmCertStoreInfo storeInfo{};
};

void CmGetSystemTrustedCertListByAlgTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmGetSystemTrustedCertListByAlgTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmGetSystemTrustedCertListByAlgTest::SetUp(void)
{
    (void)memset_s(&certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    (void)memset_s(status, sizeof(status), 0, sizeof(status));
    (void)memset_s(&storeInfo, sizeof(struct CmCertStoreInfo), 0, sizeof(struct CmCertStoreInfo));
}

void CmGetSystemTrustedCertListByAlgTest::TearDown(void)
{
    CmFreeCertBlob(&certBlob);
    if (certFileList.data != nullptr) {
        CmFreeCertFiles(reinterpret_cast<struct CertFileInfo *>(certFileList.data), certFileList.size);
        certFileList.data = nullptr;
        certFileList.size = 0;
    }
    if (pathList.data != nullptr) {
        CmFreePathList(&pathList, pathList.size);
        pathList.data = nullptr;
        pathList.size = 0;
    }
}

static int32_t PrepareSystemCertFileList(struct CmContext *ctx, struct CmMutableBlob *pathList,
    struct CmMutableBlob *certFileList)
{
    int32_t ret = CmGetSysCertPathList(ctx, pathList);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return CreateCertFileList(pathList, certFileList);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_001
 * @tc.desc: certAlg=ALL, returns all system certs and reads store version.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_001, TestSize.Level1)
{
    ASSERT_EQ(PrepareSystemCertFileList(&context, &pathList, &certFileList), CM_SUCCESS);
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_ALL, &certFileList,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_002
 * @tc.desc: certAlg=INTERNATIONAL, filters out SM certs.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_002, TestSize.Level1)
{
    ASSERT_EQ(PrepareSystemCertFileList(&context, &pathList, &certFileList), CM_SUCCESS);
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_INTERNATIONAL, &certFileList,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(CountKeptCerts(&certBlob, certFileList.size), 125); /* international preset count */
    EXPECT_GT(strlen(storeInfo.certStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_003
 * @tc.desc: certAlg=SM, returns only SM certs (may be empty on overseas devices).
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_003, TestSize.Level1)
{
    ASSERT_EQ(PrepareSystemCertFileList(&context, &pathList, &certFileList), CM_SUCCESS);
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_SM, &certFileList,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(CountKeptCerts(&certBlob, certFileList.size), 14); /* SM preset count */
    EXPECT_GT(strlen(storeInfo.smCertStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_004
 * @tc.desc: certAlg=SM, SM version non-empty and SM count > 0 on domestic device.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_004, TestSize.Level2)
{
    ASSERT_EQ(PrepareSystemCertFileList(&context, &pathList, &certFileList), CM_SUCCESS);
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_SM, &certFileList,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(CountKeptCerts(&certBlob, certFileList.size), 0);
    EXPECT_GT(strlen(storeInfo.smCertStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_005
 * @tc.desc: certAlg=ALL, intl version non-empty and total count == intl + sm.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_005, TestSize.Level2)
{
    ASSERT_EQ(PrepareSystemCertFileList(&context, &pathList, &certFileList), CM_SUCCESS);
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_ALL, &certFileList,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(CountKeptCerts(&certBlob, certFileList.size), 125 + 14);
    EXPECT_GT(strlen(storeInfo.certStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListInfo_006
 * @tc.desc: null inputs -> CMR_ERROR_INVALID_ARGUMENT.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListInfo_006, TestSize.Level2)
{
    int32_t ret = CmGetSystemTrustedCertListInfo(&context, CM_CERT_ALG_ALL, nullptr,
        &certBlob, status, &storeInfo);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}
