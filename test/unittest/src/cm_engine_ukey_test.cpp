/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "cert_manager.h"
#include "cert_manager_ukey_operation.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "cm_type_free.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
/* a provider name that no ukey hardware answers to on a test device */
uint8_t g_ukeyProvider[] = "TestUkeyProvider";

/* releases the list only when the environment unexpectedly succeeds */
void FreeListIfPresent(struct CredentialDetailList *list)
{
    if (list->credential != nullptr) {
        CmFreeUkeyCertList(list);
    }
    (void)memset_s(list, sizeof(*list), 0, sizeof(*list));
}
} // namespace

class CmEngineUkeyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}

    static void TearDownTestCase(void) {}

    void SetUp() {}

    void TearDown() {}
};

/**
 * @tc.name: CmEngineUkeyParamCheck_001
 * @tc.desc: the ukey entry points reject invalid arguments before touching huks.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUkeyTest, CmEngineUkeyParamCheck_001, TestSize.Level0)
{
    struct CmBlob provider = { sizeof(g_ukeyProvider), g_ukeyProvider };
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));

    /* provider list query */
    EXPECT_EQ(CmGetUkeyCertListByHksCertInfoSet(nullptr, CM_CERT_PURPOSE_ALL, &list),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetUkeyCertListByHksCertInfoSet(&provider, CM_CERT_PURPOSE_ALL, nullptr),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceGetUkeyCertList(nullptr, CM_CERT_PURPOSE_ALL, &list),
        CMR_ERROR_INVALID_ARGUMENT);

    /* single certificate query */
    EXPECT_EQ(CmGetUkeyCertByHksCertInfoSet(nullptr, CM_CERT_PURPOSE_ALL, &list),
        CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob emptyUri = { 0, nullptr };
    EXPECT_EQ(CmGetUkeyCertByHksCertInfoSet(&emptyUri, CM_CERT_PURPOSE_ALL, &list),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmGetUkeyCertByHksCertInfoSet(&provider, CM_CERT_PURPOSE_ALL, nullptr),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceGetUkeyCert(nullptr, CM_CERT_PURPOSE_ALL, &list),
        CMR_ERROR_INVALID_ARGUMENT);

    /* import */
    uint8_t certData[] = "certdata";
    struct CmBlob cert = { sizeof(certData) - 1, certData };
    EXPECT_EQ(CmServiceImportUkeyCert(nullptr, &cert, CM_CERT_PURPOSE_ALL), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceImportUkeyCert(&provider, nullptr, CM_CERT_PURPOSE_ALL), CMR_ERROR_INVALID_ARGUMENT);

    uint8_t bigUriBuf[MAX_LEN_URI + 1] = { 0 };
    (void)memset_s(bigUriBuf, sizeof(bigUriBuf), 'a', sizeof(bigUriBuf));
    struct CmBlob bigUri = { sizeof(bigUriBuf), bigUriBuf };
    EXPECT_EQ(CmServiceImportUkeyCert(&bigUri, &cert, CM_CERT_PURPOSE_ALL), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmEngineUkeyHksFailure_001
 * @tc.desc: without ukey hardware every query fails and nothing leaks.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineUkeyTest, CmEngineUkeyHksFailure_001, TestSize.Level0)
{
    struct CmBlob provider = { sizeof(g_ukeyProvider), g_ukeyProvider };
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));

    /* the provider query fails without a matching ukey device */
    int32_t ret = CmGetUkeyCertListByHksCertInfoSet(&provider, CM_CERT_PURPOSE_ALL, &list);
    FreeListIfPresent(&list);
    EXPECT_NE(ret, CM_SUCCESS);

    /* the service wrapper propagates the failure */
    ret = CmServiceGetUkeyCertList(&provider, CM_CERT_PURPOSE_ALL, &list);
    FreeListIfPresent(&list);
    EXPECT_NE(ret, CM_SUCCESS);

    /* the single certificate query fails the same way */
    ret = CmGetUkeyCertByHksCertInfoSet(&provider, CM_CERT_PURPOSE_SIGN, &list);
    FreeListIfPresent(&list);
    EXPECT_NE(ret, CM_SUCCESS);

    ret = CmServiceGetUkeyCert(&provider, CM_CERT_PURPOSE_SIGN, &list);
    FreeListIfPresent(&list);
    EXPECT_NE(ret, CM_SUCCESS);

    /* importing a certificate for an unknown ukey resource fails */
    uint8_t certData[] = "certdata";
    struct CmBlob cert = { sizeof(certData) - 1, certData };
    ret = CmServiceImportUkeyCert(&provider, &cert, CM_CERT_PURPOSE_ENCRYPT);
    EXPECT_NE(ret, CM_SUCCESS);
}
