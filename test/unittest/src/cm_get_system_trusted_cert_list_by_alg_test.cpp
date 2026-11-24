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
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static uint32_t g_selfTokenId = 0;
}

class CmGetSystemTrustedCertListByAlgTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    struct CertList *lstCert = nullptr;
    struct CmCertStoreInfo storeInfo{};
};

void CmGetSystemTrustedCertListByAlgTest::SetUpTestCase(void)
{
    CmTestCommon::CleanupRdbResidue();
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmGetSystemTrustedCertListByAlgTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmGetSystemTrustedCertListByAlgTest::SetUp(void)
{
    ASSERT_EQ(InitCertList(&lstCert), CM_SUCCESS);
    (void)memset_s(&storeInfo, sizeof(struct CmCertStoreInfo), 0, sizeof(struct CmCertStoreInfo));
}

void CmGetSystemTrustedCertListByAlgTest::TearDown(void)
{
    FreeCertList(lstCert);
    lstCert = nullptr;
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_001
 * @tc.desc: parameter validation - null certificateList.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_001, TestSize.Level1)
{
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, nullptr, &storeInfo), CMR_ERROR_NULL_POINTER);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_002
 * @tc.desc: parameter validation - null certStoreInfo.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_002, TestSize.Level1)
{
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, lstCert, nullptr), CMR_ERROR_NULL_POINTER);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_003
 * @tc.desc: parameter validation - null certAbstract inside CertList.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_003, TestSize.Level1)
{
    struct CertList emptyList = {0, nullptr};
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, &emptyList, &storeInfo),
        CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_004
 * @tc.desc: parameter validation - invalid certAlg.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_004, TestSize.Level1)
{
    EXPECT_EQ(CmGetSystemTrustedCertList((enum CmCertAlgorithm)99, lstCert, &storeInfo),
        CMR_ERROR_INVALID_ARGUMENT);
}
