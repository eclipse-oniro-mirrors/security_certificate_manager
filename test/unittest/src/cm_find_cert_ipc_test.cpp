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
#include <cstring>
#include <string>

#include "securec.h"
#include "cert_manager_api.h"
#include "cm_cert_data_user.h"
#include "cm_test_common.h"
#include "cm_type.h"

using namespace testing::ext;
using namespace CertmanagerTest;
namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken *g_MockHap = nullptr;
constexpr uint32_t MAX_URI_LEN = 256;

/* install one user CA cert for the calling user and return its uri */
int32_t InstallFindCert(const std::string &alias, std::string &outUri)
{
    struct CmBlob userCert = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    if (strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), alias.c_str()) != EOK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob certAlias = { alias.size() + 1, aliasBuf };
    uint8_t uriBuf[MAX_URI_LEN] = { 0 };
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };

    int32_t ret = CmInstallUserTrustedCert(&userCert, &certAlias, &certUri);
    if (ret == CM_SUCCESS) {
        outUri = std::string(reinterpret_cast<char *>(uriBuf));
    }
    return ret;
}

/* the cert id of a user cert uri is the object part between 'o=' and ';' */
std::string CertIdFromUri(const std::string &uri)
{
    size_t begin = uri.find("o=");
    size_t end = uri.find(';', begin);
    if (begin == std::string::npos || end == std::string::npos) {
        return "";
    }
    return uri.substr(begin + 2, end - begin - 2);
}

/* best effort uninstall by the uri returned from the install */
void UninstallByUriQuietly(const std::string &uri)
{
    uint8_t uriBuf[MAX_URI_LEN] = { 0 };
    if (memcpy_s(uriBuf, sizeof(uriBuf), uri.c_str(), uri.size() + 1) != EOK) {
        return;
    }
    struct CmBlob certUri = { uri.size() + 1, uriBuf };
    (void)CmUninstallUserTrustedCert(&certUri);
}
} // namespace

class CmFindCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmFindCertTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmFindCertTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmFindCertTest::SetUp()
{
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmFindCertTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

/**
 * @tc.name: CmFindCertNullParam001
 * @tc.desc: Test CmFindCertificate with null request or null result
 * @tc.type: FUNC
 */
HWTEST_F(CmFindCertTest, CmFindCertNullParam001, TestSize.Level0)
{
    struct FindCertResult result = { 0, nullptr };
    EXPECT_EQ(CmFindCertificate(nullptr, &result), CMR_ERROR_INVALID_ARGUMENT);

    struct FindCertRequest request = {};
    EXPECT_EQ(CmFindCertificate(&request, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/**
 * @tc.name: CmFindCertCurrentUser002
 * @tc.desc: Test CmFindCertificate finds the user CA certs of the current user
 * @tc.type: FUNC
 */
HWTEST_F(CmFindCertTest, CmFindCertCurrentUser002, TestSize.Level0)
{
    std::string firstUri;
    std::string secondUri;
    ASSERT_EQ(InstallFindCert("r7find01", firstUri), CM_SUCCESS);
    ASSERT_EQ(InstallFindCert("r7find02", secondUri), CM_SUCCESS);

    /* no cert type variant: the request matches both installed certs */
    struct FindCertRequest request = {};
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_GE(result.count, 2u);
    bool firstFound = false;
    bool secondFound = false;
    for (uint32_t i = 0; i < result.count; i++) {
        firstFound = firstFound || (strstr(result.certInfos[i].alias, "r7find01") != nullptr);
        secondFound = secondFound || (strstr(result.certInfos[i].alias, "r7find02") != nullptr);
    }
    EXPECT_TRUE(firstFound);
    EXPECT_TRUE(secondFound);
    CmFreeFindCertResult(&result);

    /* the explicit user CA type variant returns the same matches */
    enum CmFindCertType certTypes[] = { CM_FIND_CERT_TYPE_USER_CA };
    request.certTypesCount = sizeof(certTypes) / sizeof(certTypes[0]);
    request.certTypes = certTypes;
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_GE(result.count, 2u);
    CmFreeFindCertResult(&result);

    UninstallByUriQuietly(firstUri);
    UninstallByUriQuietly(secondUri);
}

/**
 * @tc.name: CmFindCertFilters003
 * @tc.desc: Test CmFindCertificate with certId, name and countLimit filters
 * @tc.type: FUNC
 */
HWTEST_F(CmFindCertTest, CmFindCertFilters003, TestSize.Level0)
{
    std::string firstUri;
    std::string secondUri;
    ASSERT_EQ(InstallFindCert("r7find03", firstUri), CM_SUCCESS);
    ASSERT_EQ(InstallFindCert("r7find04", secondUri), CM_SUCCESS);
    const std::string certId = CertIdFromUri(firstUri);
    ASSERT_EQ(certId, "r7find03");

    /* the certId filter matches exactly one certificate */
    struct FindCertRequest request = {};
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    (void)strcpy_s(request.certId, sizeof(request.certId), certId.c_str());
    struct FindCertResult result = { 0, nullptr };
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 1u);
    EXPECT_NE(strstr(result.certInfos[0].uri, "o=r7find03;"), nullptr);
    CmFreeFindCertResult(&result);

    /* a name shared by both aliases returns at least both certs */
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    (void)strcpy_s(request.name, sizeof(request.name), "r7find0");
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_GE(result.count, 2u);
    CmFreeFindCertResult(&result);

    /* the count limit truncates the result */
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    (void)strcpy_s(request.name, sizeof(request.name), "r7find0");
    request.countLimit = 1;
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 1u);
    CmFreeFindCertResult(&result);

    /* a name matching nothing returns an empty result */
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_GLOBAL;
    (void)strcpy_s(request.name, sizeof(request.name), "NoSuchR7Cert");
    ASSERT_EQ(CmFindCertificate(&request, &result), CM_SUCCESS);
    EXPECT_EQ(result.count, 0u);
    EXPECT_EQ(result.certInfos, nullptr);
    CmFreeFindCertResult(&result);

    UninstallByUriQuietly(firstUri);
    UninstallByUriQuietly(secondUri);
}
