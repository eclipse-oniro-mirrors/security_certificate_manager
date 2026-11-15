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
 * @tc.desc: certAlg=ALL, returns system certs and store version.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_001, TestSize.Level1)
{
    int32_t ret = CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, lstCert, &storeInfo);
    ASSERT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(lstCert->certsCount, 0);
    EXPECT_GT(strlen(storeInfo.certStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_002
 * @tc.desc: certAlg=INTERNATIONAL, returns international certs and intl version.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_002, TestSize.Level1)
{
    int32_t ret = CmGetSystemTrustedCertList(CM_CERT_ALG_INTERNATIONAL, lstCert, &storeInfo);
    ASSERT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(lstCert->certsCount, 0);
    EXPECT_GT(strlen(storeInfo.certStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_003
 * @tc.desc: certAlg=SM, returns SM certs and sm version.
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_003, TestSize.Level1)
{
    int32_t ret = CmGetSystemTrustedCertList(CM_CERT_ALG_SM, lstCert, &storeInfo);
    ASSERT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(lstCert->certsCount, 0);
    EXPECT_GT(strlen(storeInfo.smCertStoreVersion), 0);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_004
 * @tc.desc: ALL count == INTERNATIONAL count + SM count (relationship, no hardcoded mirror values).
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_004, TestSize.Level2)
{
    struct CertList *allList = nullptr;
    struct CertList *intlList = nullptr;
    struct CertList *smList = nullptr;
    ASSERT_EQ(InitCertList(&allList), CM_SUCCESS);
    ASSERT_EQ(InitCertList(&intlList), CM_SUCCESS);
    ASSERT_EQ(InitCertList(&smList), CM_SUCCESS);

    ASSERT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, allList, &storeInfo), CM_SUCCESS);
    ASSERT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_INTERNATIONAL, intlList, &storeInfo), CM_SUCCESS);
    ASSERT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_SM, smList, &storeInfo), CM_SUCCESS);

    EXPECT_EQ(allList->certsCount, intlList->certsCount + smList->certsCount);

    FreeCertList(allList);
    FreeCertList(intlList);
    FreeCertList(smList);
}

/**
 * @tc.name: CmGetSystemTrustedCertListByAlg_005
 * @tc.desc: all parameter validation branches (client-side, no IPC needed).
 * @tc.type: FUNC
 */
HWTEST_F(CmGetSystemTrustedCertListByAlgTest, CmGetSystemTrustedCertListByAlg_005, TestSize.Level2)
{
    /* null certificateList */
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, nullptr, &storeInfo), CMR_ERROR_NULL_POINTER);
    /* null certStoreInfo */
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, lstCert, nullptr), CMR_ERROR_NULL_POINTER);
    /* null certAbstract inside CertList */
    struct CertList emptyList = {0, nullptr};
    EXPECT_EQ(CmGetSystemTrustedCertList(CM_CERT_ALG_ALL, &emptyList, &storeInfo),
        CMR_ERROR_INVALID_ARGUMENT);
    /* invalid certAlg */
    EXPECT_EQ(CmGetSystemTrustedCertList((enum CmCertAlgorithm)99, lstCert, &storeInfo),
        CMR_ERROR_INVALID_ARGUMENT);
}
