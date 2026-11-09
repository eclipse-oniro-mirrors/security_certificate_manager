/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "cm_test_log.h"
#include "cm_test_common.h"
#include "cert_manager_api.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cm_root_ca_store_rdb.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken* g_MockHap = nullptr;
struct CertStatusExpectResult {
    char uri[MAX_LEN_URI];
    bool inparamStatus;
    bool expectStatus;
};

/* preset system CA pubkey hashes, precomputed with (NOT derived from the
 * code under test):
 *   openssl x509 -in config/systemCertificates/<uri> -pubkey -noout |
 *   openssl pkey -pubin -outform DER | sha256sum   (uppercase)
 * index i pairs with g_expectList[i].uri */
static const char *g_expectedSystemPkHashes[] = {
    "7E0EAD76BB6819DC2F54511A84354F6E8B307B9DD82058EA6C004F01D9DDA5DF", /* 1d3472b9.0 */
    "808D68B3FAB4884A5F971ACE7D10550D7A95A163774F3EC36AFFFB213FBE4C74", /* 4bfab552.0 */
    "40FCFC28875DCCBFEBCBDF6CD7433312DA63C4EFCF3BD7B1B505C22020AE0274", /* 4f316efb.0 */
};

/* read the whole force-check policy file; false when it cannot be opened */
static bool ReadPolicyFile(std::string &out)
{
    std::ifstream f(FORCE_CHECK_POLICY_FILE, std::ios::in | std::ios::binary);
    if (!f.is_open()) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

/* query the root_ca_cert_store disabled rows and assert that the row for
 * uri classifies as international (the preset CAs live in SYSTEM_CA_STORE) */
static void CheckDisabledRootCaAlgType(const char *uri)
{
    std::vector<struct RootCaStoreRecord> records(MAX_COUNT_CERTIFICATE_ALL);
    uint32_t disabledCount = 0;
    ASSERT_EQ(QueryDisabledRootCa(records.data(), MAX_COUNT_CERTIFICATE_ALL, &disabledCount), CM_SUCCESS)
        << "query disabled root ca failed";
    bool rowFound = false;
    for (uint32_t r = 0; r < disabledCount; ++r) {
        if (strcmp(records[r].uri, uri) == 0) {
            EXPECT_EQ(records[r].algType, CM_ROOT_CA_ALG_TYPE_INTERNATIONAL)
                << "alg type mismatch for uri: " << uri;
            rowFound = true;
            break;
        }
    }
    EXPECT_TRUE(rowFound) << "disabled row missing for uri: " << uri;
}

struct CertStatusExpectResult g_expectList[] = {
    {
        {"1d3472b9.0"}, false, false
    },
    {
        {"4bfab552.0"}, false, false
    },
    {
        {"4f316efb.0"}, true, true
    }
};

class CmSetCertStatusTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmSetCertStatusTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmSetCertStatusTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmSetCertStatusTest::SetUp()
{
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmSetCertStatusTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

/**
 * @tc.name: SimpleSetCertStatus001
 * @tc.desc: Test CertManager set cert status interface base function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SimpleSetCertStatus001, TestSize.Level0)
{
    struct CmBlob uriBlob = {strlen(g_expectList[0].uri) + 1, (uint8_t *)(g_expectList[0].uri)};

    int32_t ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, g_expectList[0].inparamStatus);
    EXPECT_EQ(ret, CM_SUCCESS) << "SimpleSetCertStatus failed,retcode:" << ret;

    ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, true);
    EXPECT_EQ(ret, CM_SUCCESS) << "SimpleSetCertStatus true failed,retcode:" << ret;
}

/**
 * @tc.name: SetCertStatusAndQueryStatus002
 * @tc.desc: Test CertManager set cert status and query status interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SetCertStatusAndQueryStatus002, TestSize.Level0)
{
    uint32_t size = sizeof(g_expectList) / sizeof(g_expectList[0]);
    for (uint32_t i = 0; i < size; ++i) {
        struct CmBlob uriBlob = {strlen(g_expectList[i].uri) + 1, (uint8_t *)(g_expectList[i].uri)};

        int32_t ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, g_expectList[i].inparamStatus);
        EXPECT_EQ(ret, CM_SUCCESS) << " SetCertStatusAndQueryStatus, CmSetCertStatus failed,retcode: " << ret;

        struct CertInfo certDetailInfo;
        (void)memset_s(&certDetailInfo, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));
        ret = InitCertInfo(&certDetailInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << "CmGetCertInfo malloc faild, retcode:" << ret;

        ret = CmGetCertInfo(&uriBlob, CM_SYSTEM_TRUSTED_STORE, &certDetailInfo);
        EXPECT_EQ(ret, CM_SUCCESS) << "SetCertStatusAndQueryStatus,CmGetCertInfo failed,retcode: " << ret;
        int32_t status = (g_expectList[i].expectStatus == certDetailInfo.status) ? 1 : 0;

        EXPECT_EQ(status, 1) << "SetCertStatusAndQueryStatus faild, cert info: " << DumpCertInfo(&certDetailInfo);
        FreeCMBlobData(&(certDetailInfo.certInfo));

        /* disabled in this iteration: the force-check policy file must list it */
        if (!g_expectList[i].inparamStatus) {
            std::string policy;
            ASSERT_TRUE(ReadPolicyFile(policy));
            EXPECT_NE(policy.find(std::string("1,") + g_expectedSystemPkHashes[i]), std::string::npos);

            /* the persisted row must classify the root CA by its store
             * directory: these preset CAs live in SYSTEM_CA_STORE */
            CheckDisabledRootCaAlgType(g_expectList[i].uri);
        }

        /* list-level: the abstract row for this uri must carry the same state
         * as the detail query (exercises the disabled-records query + uri match
         * in CmGetCertListInfo, and both directions of the status mapping) */
        struct CertList *certlist = nullptr;
        ASSERT_TRUE(InitCertList(&certlist) == CM_SUCCESS);
        ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, certlist);
        EXPECT_EQ(ret, CM_SUCCESS) << "SetCertStatusAndQueryStatus,CmGetCertList failed,retcode:" << ret;
        bool rowFound = false;
        for (uint32_t j = 0; j < certlist->certsCount; ++j) {
            if (strcmp(certlist->certAbstract[j].uri, g_expectList[i].uri) == 0) {
                EXPECT_EQ(certlist->certAbstract[j].status, g_expectList[i].expectStatus) <<
                    "list status mismatch for uri: " << g_expectList[i].uri;
                rowFound = true;
                break;
            }
        }
        EXPECT_TRUE(rowFound) << "uri not found in system cert list: " << g_expectList[i].uri;
        FreeCertList(certlist);

        ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS) << " SetCertStatusAndQueryStatus, CmSetCertStatus failed,retcode: " << ret;
    }
}

/**
 * @tc.name: SetAllCertStatus003
 * @tc.desc: Test CertManager set all cert status interface function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SetAllCertStatus003, TestSize.Level0)
{
    struct CertList *certlist = nullptr;

    ASSERT_TRUE(InitCertList(&certlist) == CM_SUCCESS);
    // CA trusted list
    int32_t ret = CmGetCertList(CM_SYSTEM_TRUSTED_STORE, certlist);

    EXPECT_EQ(ret, CM_SUCCESS) << "SetAllCertStatus,CmGetCertList failed,retcode:" << ret;

    for (uint32_t i = 0; i < certlist->certsCount; ++i) {
        struct CertAbstract *ptr = &(certlist->certAbstract[i]);
        ASSERT_TRUE(ptr != nullptr);
        struct CmBlob uriBlob = {strlen(ptr->uri) + 1, (uint8_t *)(ptr->uri)};
        ret = CmSetCertStatus(&uriBlob, CM_SYSTEM_TRUSTED_STORE, false);
        EXPECT_EQ(ret, CM_SUCCESS);
    }

    for (uint32_t i = 0; i < certlist->certsCount; ++i) {
        struct CertAbstract *ptr2 = &(certlist->certAbstract[i]);
        ASSERT_TRUE(ptr2 != nullptr);
        struct CmBlob uriBlob2 = {strlen(ptr2->uri) + 1, (uint8_t *)(ptr2->uri)};
        ret = CmSetCertStatus(&uriBlob2, CM_SYSTEM_TRUSTED_STORE, true);
        EXPECT_EQ(ret, CM_SUCCESS);
    }

    /* all re-enabled: the force-check policy file is empty again */
    std::string policy;
    ASSERT_TRUE(ReadPolicyFile(policy));
    ASSERT_EQ(policy.size(), 0u);
    FreeCertList(certlist);
}

/**
 * @tc.name: ExceptionSetStatus004
 * @tc.desc: Test CertManager set cert status interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, ExceptionSetStatus004, TestSize.Level0)
{
    struct CmBlob uriBlob = {strlen(g_expectList[1].uri) + 1, (uint8_t *)(g_expectList[1].uri)};
    EXPECT_EQ(CmSetCertStatus(nullptr, CM_SYSTEM_TRUSTED_STORE, true),
        CMR_ERROR_NULL_POINTER);

    EXPECT_EQ(CmSetCertStatus(&uriBlob, 10, true), CMR_ERROR_INVALID_ARGUMENT);

    const char *invalidUri = "INVALIDXXXX";
    struct CmBlob invalidUriBlob = {strlen(invalidUri) + 1, (uint8_t *)invalidUri};
    EXPECT_EQ(CmSetCertStatus(&invalidUriBlob, CM_SYSTEM_TRUSTED_STORE, true),
        CMR_ERROR_NOT_EXIST);
}

/**
 * @tc.name: SystemCaAlgTypeByDirectory005
 * @tc.desc: the persisted alg type follows the store directory the system CA
 *           file lives in, not the certificate encoding
 * @tc.type: FUNC
 * @tc.require: AR000H0MJA /SR000H096P
 */
HWTEST_F(CmSetCertStatusTest, SystemCaAlgTypeByDirectory005, TestSize.Level0)
{
    EXPECT_EQ(CmGetSystemCaAlgType(SYSTEM_CA_STORE_GM), CM_ROOT_CA_ALG_TYPE_GM);
    EXPECT_EQ(CmGetSystemCaAlgType(SYSTEM_CA_STORE), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL);
    EXPECT_EQ(CmGetSystemCaAlgType(nullptr), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL);
    EXPECT_EQ(CmGetSystemCaAlgType("/data/service/el1/public"), CM_ROOT_CA_ALG_TYPE_INTERNATIONAL);
}
}
