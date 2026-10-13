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

#include <cstring>
#include <gtest/gtest.h>

#include "cm_test_common.h"
#include "cert_manager_api.h"
#include "cm_type.h"
#include "cm_mem.h"
#include "cm_ukey_ability_type.h"
#include "cm_util.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
static void TestResultCallback(int32_t resultCode, void *userData)
{
    (void)resultCode;
    (void)userData;
}

class CmApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/* ---------- CmGetCertList ---------- */

HWTEST_F(CmApiTest, CmGetCertListNullArgs, TestSize.Level0)
{
    /* Null list pointer */
    EXPECT_EQ(CmGetCertList(CM_SYSTEM_TRUSTED_STORE, nullptr), CMR_ERROR_NULL_POINTER);

    /* certAbstract is NULL -> invalid argument */
    struct CertList certList;
    (void)memset_s(&certList, sizeof(certList), 0, sizeof(certList));
    EXPECT_EQ(CmGetCertList(CM_SYSTEM_TRUSTED_STORE, &certList), CMR_ERROR_INVALID_ARGUMENT);

    /* store != CM_SYSTEM_TRUSTED_STORE -> invalid argument */
    uint8_t buf[1024] = {0};
    certList.certAbstract = reinterpret_cast<struct CertAbstract *>(buf);
    EXPECT_EQ(CmGetCertList(CM_CREDENTIAL_STORE, &certList), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetCertInfo ---------- */

HWTEST_F(CmApiTest, CmGetCertInfoNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob certUri = { sizeof(uri), uri };
    uint8_t buf[1024] = {0};

    /* Null certUri */
    struct CertInfo certInfo;
    (void)memset_s(&certInfo, sizeof(certInfo), 0, sizeof(certInfo));
    certInfo.certInfo.data = buf;
    certInfo.certInfo.size = sizeof(buf);
    EXPECT_EQ(CmGetCertInfo(nullptr, CM_SYSTEM_TRUSTED_STORE, &certInfo), CMR_ERROR_NULL_POINTER);

    /* Null certInfo */
    EXPECT_EQ(CmGetCertInfo(&certUri, CM_SYSTEM_TRUSTED_STORE, nullptr), CMR_ERROR_NULL_POINTER);

    /* certInfo.data NULL -> invalid argument */
    struct CertInfo certInfo2;
    (void)memset_s(&certInfo2, sizeof(certInfo2), 0, sizeof(certInfo2));
    EXPECT_EQ(CmGetCertInfo(&certUri, CM_SYSTEM_TRUSTED_STORE, &certInfo2), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmGetCertInfoInvalidSizeAndStore, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob certUri = { sizeof(uri), uri };
    uint8_t buf[1024] = {0};

    /* size 0 -> invalid */
    struct CertInfo certInfo;
    (void)memset_s(&certInfo, sizeof(certInfo), 0, sizeof(certInfo));
    certInfo.certInfo.data = buf;
    certInfo.certInfo.size = 0;
    EXPECT_EQ(CmGetCertInfo(&certUri, CM_SYSTEM_TRUSTED_STORE, &certInfo), CMR_ERROR_INVALID_ARGUMENT);

    /* store != CM_SYSTEM_TRUSTED_STORE -> invalid */
    certInfo.certInfo.size = sizeof(buf);
    EXPECT_EQ(CmGetCertInfo(&certUri, CM_CREDENTIAL_STORE, &certInfo), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmSetCertStatus ---------- */

HWTEST_F(CmApiTest, CmSetCertStatusNullArgs, TestSize.Level0)
{
    /* Null uri */
    EXPECT_EQ(CmSetCertStatus(nullptr, CM_SYSTEM_TRUSTED_STORE, true), CMR_ERROR_NULL_POINTER);

    /* Wrong store */
    uint8_t uri[] = "uri";
    struct CmBlob certUri = { sizeof(uri), uri };
    EXPECT_EQ(CmSetCertStatus(&certUri, CM_CREDENTIAL_STORE, true), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmInstallAppCertEx ---------- */

HWTEST_F(CmApiTest, CmInstallAppCertExNullParam, TestSize.Level0)
{
    uint8_t buf[64] = {0};
    struct CmBlob keyUri = { sizeof(buf), buf };
    EXPECT_EQ(CmInstallAppCertEx(nullptr, &keyUri), CMR_ERROR_INVALID_ARGUMENT);

    /* Also verify that a non-null param but null keyUri is rejected separately */
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    EXPECT_EQ(CmInstallAppCertEx(&param, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExNullKeyUri, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = CM_AUTH_STORAGE_LEVEL_EL1;
    param.credFormat = FILE_P12;
    EXPECT_EQ(CmInstallAppCertEx(&param, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExNullKeyUriData, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob keyUri = { 0, nullptr };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = CM_AUTH_STORAGE_LEVEL_EL1;
    param.credFormat = FILE_P12;
    EXPECT_EQ(CmInstallAppCertEx(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExInvalidLevel, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = static_cast<enum CmAuthStorageLevel>(99); /* invalid level */
    param.credFormat = FILE_P12;
    EXPECT_EQ(CmInstallAppCertEx(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExInvalidFormat, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = CM_AUTH_STORAGE_LEVEL_EL1;
    param.credFormat = static_cast<enum CredFormat>(99); /* invalid format */
    EXPECT_EQ(CmInstallAppCertEx(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExP12MissingPwd, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = CM_AUTH_STORAGE_LEVEL_EL1;
    param.credFormat = FILE_P12;
    /* appCertPwd is NULL for FILE_P12 -> invalid */
    EXPECT_EQ(CmInstallAppCertEx(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertExChainKeyMissingPrivKey, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.certAlias = &certAlias;
    param.level = CM_AUTH_STORAGE_LEVEL_EL1;
    param.credFormat = CHAIN_KEY;
    /* appCertPrivKey is NULL for CHAIN_KEY -> invalid */
    EXPECT_EQ(CmInstallAppCertEx(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmInstallAppCert ---------- */

HWTEST_F(CmApiTest, CmInstallAppCertNullAppCert, TestSize.Level0)
{
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallAppCert(nullptr, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri),
              CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertNullPwd, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallAppCert(&appCert, nullptr, &certAlias, CM_CREDENTIAL_STORE, &keyUri),
              CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertNullAlias, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallAppCert(&appCert, &appCertPwd, nullptr, CM_CREDENTIAL_STORE, &keyUri),
              CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertNullKeyUri, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    EXPECT_EQ(CmInstallAppCert(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, nullptr),
              CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertNullKeyUriData, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob keyUri = { 0, nullptr };
    EXPECT_EQ(CmInstallAppCert(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, &keyUri),
              CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallAppCertWrongStore, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    /* store=5 is invalid (not in {0,3,4}) */
    EXPECT_EQ(CmInstallAppCert(&appCert, &appCertPwd, &certAlias, 5, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmUninstallAppCert ---------- */

HWTEST_F(CmApiTest, CmUninstallAppCertNullArgs, TestSize.Level0)
{
    /* Null uri */
    EXPECT_EQ(CmUninstallAppCert(nullptr, CM_CREDENTIAL_STORE), CMR_ERROR_INVALID_ARGUMENT);

    /* Wrong store */
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    EXPECT_EQ(CmUninstallAppCert(&keyUri, 5), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetAppCertList ---------- */

HWTEST_F(CmApiTest, CmGetAppCertListNullArgs, TestSize.Level0)
{
    /* Null list */
    EXPECT_EQ(CmGetAppCertList(CM_CREDENTIAL_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Wrong store */
    struct CredentialList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    EXPECT_EQ(CmGetAppCertList(5, &list), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetAppCertListByUid ---------- */

HWTEST_F(CmApiTest, CmGetAppCertListByUidNullArgs, TestSize.Level0)
{
    /* Null list */
    EXPECT_EQ(CmGetAppCertListByUid(CM_CREDENTIAL_STORE, 100, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Wrong store */
    struct CredentialList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    EXPECT_EQ(CmGetAppCertListByUid(5, 100, &list), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmCallingGetAppCertList ---------- */

HWTEST_F(CmApiTest, CmCallingGetAppCertListNullArgs, TestSize.Level0)
{
    /* Null list */
    EXPECT_EQ(CmCallingGetAppCertList(CM_CREDENTIAL_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Wrong store */
    struct CredentialList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    EXPECT_EQ(CmCallingGetAppCertList(5, &list), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetAppCert ---------- */

HWTEST_F(CmApiTest, CmGetAppCertNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };

    /* Null uri */
    struct Credential cred;
    (void)memset_s(&cred, sizeof(cred), 0, sizeof(cred));
    EXPECT_EQ(CmGetAppCert(nullptr, CM_CREDENTIAL_STORE, &cred), CMR_ERROR_INVALID_ARGUMENT);

    /* Null cred */
    EXPECT_EQ(CmGetAppCert(&keyUri, CM_CREDENTIAL_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Wrong store */
    (void)memset_s(&cred, sizeof(cred), 0, sizeof(cred));
    EXPECT_EQ(CmGetAppCert(&keyUri, 5, &cred), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGrantAppCertificate ---------- */

HWTEST_F(CmApiTest, CmGrantAppCertificateNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    uint8_t authBuf[64] = {0};
    struct CmBlob authUri = { sizeof(authBuf), authBuf };

    /* Null keyUri */
    EXPECT_EQ(CmGrantAppCertificate(nullptr, 100, &authUri), CMR_ERROR_INVALID_ARGUMENT);

    /* Null authUri */
    EXPECT_EQ(CmGrantAppCertificate(&keyUri, 100, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetAuthorizedAppList ---------- */

HWTEST_F(CmApiTest, CmGetAuthorizedAppListNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    struct CmAppUidList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));

    /* Null keyUri */
    EXPECT_EQ(CmGetAuthorizedAppList(nullptr, &list), CMR_ERROR_INVALID_ARGUMENT);

    /* Null list */
    EXPECT_EQ(CmGetAuthorizedAppList(&keyUri, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmIsAuthorizedApp / CmRemoveGrantedApp ---------- */

HWTEST_F(CmApiTest, CmIsAuthorizedAppAndRemoveGrantedNullArgs, TestSize.Level0)
{
    /* CmIsAuthorizedApp null uri */
    EXPECT_EQ(CmIsAuthorizedApp(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* CmRemoveGrantedApp null uri */
    EXPECT_EQ(CmRemoveGrantedApp(nullptr, 100), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmInit ---------- */

HWTEST_F(CmApiTest, CmInitNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob authUri = { sizeof(uri), uri };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PSS, CM_DIGEST_SHA256 };
    uint8_t handleBuf[64] = {0};
    struct CmBlob handle = { sizeof(handleBuf), handleBuf };

    /* Null uri */
    EXPECT_EQ(CmInit(nullptr, &spec, &handle), CMR_ERROR_INVALID_ARGUMENT);

    /* Null spec */
    EXPECT_EQ(CmInit(&authUri, nullptr, &handle), CMR_ERROR_INVALID_ARGUMENT);

    /* Null handle */
    EXPECT_EQ(CmInit(&authUri, &spec, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmUpdate ---------- */

HWTEST_F(CmApiTest, CmUpdateNullArgs, TestSize.Level0)
{
    uint8_t data[] = "data";
    struct CmBlob inData = { sizeof(data), data };
    uint8_t hBuf[] = "handle";
    struct CmBlob handle = { sizeof(hBuf), hBuf };

    /* Null handle */
    EXPECT_EQ(CmUpdate(nullptr, &inData), CMR_ERROR_INVALID_ARGUMENT);

    /* Null inData */
    EXPECT_EQ(CmUpdate(&handle, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmFinish ---------- */

HWTEST_F(CmApiTest, CmFinishNullHandle, TestSize.Level0)
{
    uint8_t data[] = "data";
    struct CmBlob inData = { sizeof(data), data };
    uint8_t outBuf[64] = {0};
    struct CmBlob outData = { sizeof(outBuf), outBuf };
    EXPECT_EQ(CmFinish(nullptr, &inData, &outData), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmFinishNullInData, TestSize.Level0)
{
    uint8_t hBuf[] = "handle";
    struct CmBlob handle = { sizeof(hBuf), hBuf };
    uint8_t outBuf[64] = {0};
    struct CmBlob outData = { sizeof(outBuf), outBuf };
    EXPECT_EQ(CmFinish(&handle, nullptr, &outData), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmFinishNullOutData, TestSize.Level0)
{
    uint8_t hBuf[] = "handle";
    struct CmBlob handle = { sizeof(hBuf), hBuf };
    uint8_t data[] = "data";
    struct CmBlob inData = { sizeof(data), data };
    EXPECT_EQ(CmFinish(&handle, &inData, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmAbort ---------- */

HWTEST_F(CmApiTest, CmAbortNullArgs, TestSize.Level0)
{
    EXPECT_EQ(CmAbort(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Also verify a non-null but invalid handle doesn't crash the API surface.
     * The handle is opaque to the caller; passing garbage should not cause
     * a crash, only an error code or no-op. */
    uint8_t hBuf[] = "invalid-handle";
    struct CmBlob handle = { sizeof(hBuf), hBuf };
    /* Result is not asserted because it depends on session state, but the call
     * itself must not crash. */
    (void)CmAbort(&handle);
}

/* ---------- CmGetUserCertList ---------- */

HWTEST_F(CmApiTest, CmGetUserCertListNullArgs, TestSize.Level0)
{
    EXPECT_EQ(CmGetUserCertList(CM_USER_TRUSTED_STORE, nullptr), CMR_ERROR_NULL_POINTER);

    /* Also verify a wrong store value returns error, not crash */
    struct CertList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    uint8_t buf[1024] = {0};
    list.certAbstract = reinterpret_cast<struct CertAbstract *>(buf);
    EXPECT_EQ(CmGetUserCertList(CM_CREDENTIAL_STORE, &list), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetUserCertInfo ---------- */

HWTEST_F(CmApiTest, CmGetUserCertInfoNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob certUri = { sizeof(uri), uri };

    /* Null certUri */
    struct CertInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    EXPECT_EQ(CmGetUserCertInfo(nullptr, CM_USER_TRUSTED_STORE, &info), CMR_ERROR_NULL_POINTER);

    /* Null certInfo */
    EXPECT_EQ(CmGetUserCertInfo(&certUri, CM_USER_TRUSTED_STORE, nullptr), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmInstallUserTrustedCert ---------- */

HWTEST_F(CmApiTest, CmInstallUserTrustedCertNullCert, TestSize.Level0)
{
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallUserTrustedCert(nullptr, &certAlias, &certUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallUserTrustedCertNullAlias, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob userCert = { sizeof(certBuf), certBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob certUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallUserTrustedCert(&userCert, nullptr, &certUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallUserTrustedCertNullUri, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob userCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    EXPECT_EQ(CmInstallUserTrustedCert(&userCert, &certAlias, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmUninstallUserTrustedCert ---------- */

HWTEST_F(CmApiTest, CmUninstallUserTrustedCertNullArgs, TestSize.Level0)
{
    EXPECT_EQ(CmUninstallUserTrustedCert(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Non-null but empty uri (size 0) should also be rejected */
    uint8_t uri[] = "uri";
    struct CmBlob certUri = { 0, uri };
    EXPECT_EQ(CmUninstallUserTrustedCert(&certUri), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmInstallSystemAppCert ---------- */

HWTEST_F(CmApiTest, CmInstallSystemAppCertNullParam, TestSize.Level0)
{
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    EXPECT_EQ(CmInstallSystemAppCert(nullptr, &keyUri), CMR_ERROR_INVALID_ARGUMENT);

    /* Also verify non-null param but null keyUri is rejected */
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    EXPECT_EQ(CmInstallSystemAppCert(&param, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallSystemAppCertNullKeyUri, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_SYS_CREDENTIAL_STORE;
    param.userId = 100;
    EXPECT_EQ(CmInstallSystemAppCert(&param, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallSystemAppCertNullKeyUriData, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob keyUri = { 0, nullptr };
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_SYS_CREDENTIAL_STORE;
    param.userId = 100;
    EXPECT_EQ(CmInstallSystemAppCert(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallSystemAppCertWrongStore, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_CREDENTIAL_STORE; /* wrong, must be CM_SYS_CREDENTIAL_STORE */
    param.userId = 100;
    EXPECT_EQ(CmInstallSystemAppCert(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallSystemAppCertUserIdZero, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_SYS_CREDENTIAL_STORE;
    param.userId = 0; /* invalid */
    EXPECT_EQ(CmInstallSystemAppCert(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmInstallSystemAppCertUserIdInvalid, TestSize.Level0)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    uint8_t certBuf[] = "cert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "pwd";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    uint8_t uriBuf[64] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    param.appCert = &appCert;
    param.appCertPwd = &appCertPwd;
    param.certAlias = &certAlias;
    param.store = CM_SYS_CREDENTIAL_STORE;
    param.userId = INIT_INVALID_VALUE; /* invalid */
    EXPECT_EQ(CmInstallSystemAppCert(&param, &keyUri), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetCertStorePath ---------- */

HWTEST_F(CmApiTest, CmGetCertStorePathNullAndSuccess, TestSize.Level0)
{
    /* Null path */
    EXPECT_EQ(CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, nullptr, 256), CMR_ERROR_NULL_POINTER);

    /* System success */
    char path[256] = {0};
    EXPECT_EQ(CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, path, sizeof(path)), CM_SUCCESS);
    EXPECT_GT(strlen(path), 0u);

    /* User success */
    char path2[256] = {0};
    EXPECT_EQ(CmGetCertStorePath(CM_CA_CERT_USER, 100, path2, sizeof(path2)), CM_SUCCESS);
    EXPECT_GT(strlen(path2), 0u);
}

HWTEST_F(CmApiTest, CmGetCertStorePathBufferTooSmall, TestSize.Level0)
{
    /* System too small */
    char path[2] = {0};
    EXPECT_EQ(CmGetCertStorePath(CM_CA_CERT_SYSTEM, 0, path, sizeof(path)), CMR_ERROR_BUFFER_TOO_SMALL);

    /* User too small */
    char path2[2] = {0};
    EXPECT_EQ(CmGetCertStorePath(CM_CA_CERT_USER, 100, path2, sizeof(path2)), CMR_ERROR_BUFFER_TOO_SMALL);

    /* Invalid type */
    char path3[256] = {0};
    EXPECT_EQ(CmGetCertStorePath(static_cast<enum CmCertType>(99), 100, path3, sizeof(path3)),
              CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetUserCACertList ---------- */

HWTEST_F(CmApiTest, CmGetUserCACertListNullArgs, TestSize.Level0)
{
    /* Null list */
    struct UserCAProperty property = { INIT_INVALID_VALUE, CM_ALL_USER };
    EXPECT_EQ(CmGetUserCACertList(&property, nullptr), CMR_ERROR_NULL_POINTER);

    /* Null property */
    struct CertList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    EXPECT_EQ(CmGetUserCACertList(nullptr, &list), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmInstallUserTrustedP7BCert ---------- */

HWTEST_F(CmApiTest, CmInstallUserTrustedP7BCertNullArgs, TestSize.Level0)
{
    uint8_t certBuf[] = "cert";
    struct CmBlob userCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };
    struct CmInstallCertInfo info = { &userCert, &certAlias, 100 };

    /* Null list */
    EXPECT_EQ(CmInstallUserTrustedP7BCert(&info, true, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Null info */
    struct CertUriList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    EXPECT_EQ(CmInstallUserTrustedP7BCert(nullptr, true, &list), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmGetUkeyCertList ---------- */

HWTEST_F(CmApiTest, CmGetUkeyCertListNullArgs, TestSize.Level0)
{
    uint8_t provider[] = "provider";
    struct CmBlob ukeyProvider = { sizeof(provider), provider };
    struct UkeyInfo info = { CM_CERT_PURPOSE_DEFAULT };
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));

    /* Null provider */
    EXPECT_EQ(CmGetUkeyCertList(nullptr, &info, &list), CMR_ERROR_NULL_POINTER);

    /* Null info */
    EXPECT_EQ(CmGetUkeyCertList(&ukeyProvider, nullptr, &list), CMR_ERROR_NULL_POINTER);

    /* Null list */
    EXPECT_EQ(CmGetUkeyCertList(&ukeyProvider, &info, nullptr), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmGetUkeyCert ---------- */

HWTEST_F(CmApiTest, CmGetUkeyCertNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    struct UkeyInfo info = { CM_CERT_PURPOSE_DEFAULT };
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));

    /* Null uri */
    EXPECT_EQ(CmGetUkeyCert(nullptr, &info, &list), CMR_ERROR_NULL_POINTER);

    /* Null info */
    EXPECT_EQ(CmGetUkeyCert(&keyUri, nullptr, &list), CMR_ERROR_NULL_POINTER);

    /* Null list */
    EXPECT_EQ(CmGetUkeyCert(&keyUri, &info, nullptr), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmImportUkeyCert ---------- */

HWTEST_F(CmApiTest, CmImportUkeyCertNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    uint8_t certBuf[] = "cert";
    struct CmBlob cert = { sizeof(certBuf), certBuf };
    struct UkeyInfo info = { CM_CERT_PURPOSE_DEFAULT };

    /* Null uri */
    EXPECT_EQ(CmImportUkeyCert(nullptr, &cert, &info), CMR_ERROR_NULL_POINTER);

    /* Null cert */
    EXPECT_EQ(CmImportUkeyCert(&keyUri, nullptr, &info), CMR_ERROR_NULL_POINTER);

    /* Null info */
    EXPECT_EQ(CmImportUkeyCert(&keyUri, &cert, nullptr), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmCheckAppPermission ---------- */

HWTEST_F(CmApiTest, CmCheckAppPermissionNullArgs, TestSize.Level0)
{
    uint8_t uri[] = "uri";
    struct CmBlob keyUri = { sizeof(uri), uri };
    enum CmPermissionState state = CM_PERMISSION_DENIED;

    /* Null uri */
    EXPECT_EQ(CmCheckAppPermission(nullptr, 100, &state, nullptr), CMR_ERROR_NULL_POINTER);

    /* Null state */
    EXPECT_EQ(CmCheckAppPermission(&keyUri, 100, nullptr, nullptr), CMR_ERROR_NULL_POINTER);
}

/* ---------- CmFreeUkeyCertificate ---------- */

HWTEST_F(CmApiTest, CmFreeUkeyCertificateNull, TestSize.Level0)
{
    /* no crash when passing nullptr */
    CmFreeUkeyCertificate(nullptr);

    /* Also verify freeing a zero-initialized list is safe */
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    CmFreeUkeyCertificate(&list);
    EXPECT_EQ(list.credential, nullptr);
    EXPECT_EQ(list.credentialCount, 0u);
}

HWTEST_F(CmApiTest, CmFreeUkeyCertificateWithAllocatedCred, TestSize.Level0)
{
    struct CredentialDetailList list;
    (void)memset_s(&list, sizeof(list), 0, sizeof(list));
    list.credentialCount = 2;
    list.credential = static_cast<struct Credential *>(CmMalloc(sizeof(struct Credential) * 2));
    ASSERT_NE(list.credential, nullptr);
    (void)memset_s(list.credential, sizeof(struct Credential) * 2, 0, sizeof(struct Credential) * 2);
    list.credential[0].credData.data = static_cast<uint8_t *>(CmMalloc(32));
    list.credential[0].credData.size = 32;
    list.credential[1].credData.data = static_cast<uint8_t *>(CmMalloc(16));
    list.credential[1].credData.size = 16;
    /* frees credData for each credential then frees credential array */
    CmFreeUkeyCertificate(&list);
    EXPECT_EQ(list.credential, nullptr);
    EXPECT_EQ(list.credentialCount, 0u);
}

/* ---------- CmFreeCredential ---------- */

HWTEST_F(CmApiTest, CmFreeCredentialNull, TestSize.Level0)
{
    /* no crash when passing nullptr */
    CmFreeCredential(nullptr);

    /* Also verify freeing a zero-initialized credential is safe */
    struct Credential cred;
    (void)memset_s(&cred, sizeof(cred), 0, sizeof(cred));
    CmFreeCredential(&cred);
    EXPECT_EQ(cred.credData.data, nullptr);
    EXPECT_EQ(cred.credData.size, 0u);
}

HWTEST_F(CmApiTest, CmFreeCredentialWithAllocatedData, TestSize.Level0)
{
    struct Credential cred;
    (void)memset_s(&cred, sizeof(cred), 0, sizeof(cred));
    cred.credData.data = static_cast<uint8_t *>(CmMalloc(32));
    cred.credData.size = 32;
    /* frees credData.data via CmFree */
    CmFreeCredential(&cred);
    EXPECT_EQ(cred.credData.data, nullptr);
}

/* ---------- CmOpenUkeyAuthDialog ---------- */

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogNullArgs, TestSize.Level0)
{
    /* Null request */
    EXPECT_EQ(CmOpenUkeyAuthDialog(nullptr, nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* Null callback */
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    EXPECT_EQ(CmOpenUkeyAuthDialog(&req, nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogInvalidKeyUri, TestSize.Level0)
{
    /* keyUri.data NULL -> invalid */
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialog(&req, cb, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* keyUri.size 0 -> invalid */
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = 0;
    EXPECT_EQ(CmOpenUkeyAuthDialog(&req, cb, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogCustomDataTooLarge, TestSize.Level0)
{
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    uint8_t bigData[CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE + 1] = {0};
    req.customData.data = bigData;
    req.customData.size = sizeof(bigData); /* too large */
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialog(&req, cb, nullptr), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
}

/* ---------- CmOpenUkeyAuthDialogForDriver ---------- */

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverNullDialogInfo, TestSize.Level0)
{
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(nullptr, &req, cb, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverNullRequest, TestSize.Level0)
{
    struct UkeyAuthDialogInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    uint8_t name[] = "ext";
    info.abilityName.data = name;
    info.abilityName.size = sizeof(name);
    info.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(&info, nullptr, cb, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverNullCallback, TestSize.Level0)
{
    struct UkeyAuthDialogInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    uint8_t name[] = "ext";
    info.abilityName.data = name;
    info.abilityName.size = sizeof(name);
    info.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(&info, &req, nullptr, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverNullAbilityName, TestSize.Level0)
{
    struct UkeyAuthDialogInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(&info, &req, cb, nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverWrongAbilityType, TestSize.Level0)
{
    struct UkeyAuthDialogInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    uint8_t name[] = "ext";
    info.abilityName.data = name;
    info.abilityName.size = sizeof(name);
    info.abilityType = static_cast<uint32_t>(99); /* wrong type */
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(&info, &req, cb, nullptr),
              CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
}

HWTEST_F(CmApiTest, CmOpenUkeyAuthDialogForDriverCustomDataTooLarge, TestSize.Level0)
{
    struct UkeyAuthDialogInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    uint8_t name[] = "ext";
    info.abilityName.data = name;
    info.abilityName.size = sizeof(name);
    info.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    struct UkeyAuthRequest req;
    (void)memset_s(&req, sizeof(req), 0, sizeof(req));
    uint8_t uri[] = "uri";
    req.keyUri.data = uri;
    req.keyUri.size = sizeof(uri);
    uint8_t bigData[CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE + 1] = {0};
    req.customData.data = bigData;
    req.customData.size = sizeof(bigData);
    auto cb = TestResultCallback;
    EXPECT_EQ(CmOpenUkeyAuthDialogForDriver(&info, &req, cb, nullptr),
              CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
}

/* ---------- CmReportUkeyAuthResult ---------- */

HWTEST_F(CmApiTest, CmReportUkeyAuthResultNullArgs, TestSize.Level0)
{
    /* Null requestId */
    EXPECT_EQ(CmReportUkeyAuthResult(nullptr, 0), CMR_ERROR_INVALID_ARGUMENT);

    /* Null requestId.data */
    struct CmBlob requestId = { 10, nullptr };
    EXPECT_EQ(CmReportUkeyAuthResult(&requestId, 0), CMR_ERROR_INVALID_ARGUMENT);

    /* Zero size */
    uint8_t id[] = "id";
    struct CmBlob requestId2 = { 0, id };
    EXPECT_EQ(CmReportUkeyAuthResult(&requestId2, 0), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- CmIsNumeric ---------- */

HWTEST_F(CmApiTest, CmIsNumericNullAndZeroLength, TestSize.Level0)
{
    uint32_t value = 0;

    /* Null str */
    EXPECT_EQ(CmIsNumeric(nullptr, 5, &value), CMR_ERROR_INVALID_ARGUMENT);

    /* Zero length */
    char str[] = "123";
    EXPECT_EQ(CmIsNumeric(str, 0, &value), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmIsNumericTooLongAndNullValue, TestSize.Level0)
{
    uint32_t value = 0;

    /* Length > STR_MAX_LEN (10) */
    char str[] = "12345678901";
    EXPECT_EQ(CmIsNumeric(str, strlen(str), &value), CMR_ERROR_INVALID_ARGUMENT);

    /* Null value pointer */
    char str2[] = "123";
    EXPECT_EQ(CmIsNumeric(str2, strlen(str2), nullptr), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmApiTest, CmIsNumericSuccessAndFailures, TestSize.Level0)
{
    uint32_t value = 0;

    /* No terminator: length 3 but string has no null terminator within first 3 chars */
    char strNoTerm[] = "123";
    EXPECT_EQ(CmIsNumeric(strNoTerm, strlen(strNoTerm), &value), CMR_ERROR_INVALID_ARGUMENT);

    /* Success: length includes the null terminator so the loop finds '\0' before last char */
    char strOk[] = "123";
    EXPECT_EQ(CmIsNumeric(strOk, sizeof(strOk), &value), CM_SUCCESS);
    EXPECT_EQ(value, 123u);

    /* Not numeric */
    char strBad[] = "abc";
    EXPECT_EQ(CmIsNumeric(strBad, sizeof(strBad), &value), CMR_ERROR_INVALID_ARGUMENT);
}
} // end of namespace
