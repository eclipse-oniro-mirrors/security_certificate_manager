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
#include <vector>

#include "accesstoken_kit.h"
#include "cert_manager_check.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_uri.h"
#include "cm_config_type.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_CHECK_USER = 8899;
constexpr uint32_t TEST_CHECK_UID = 889901;
constexpr uint32_t TEST_CHECK_OTHER_UID = 111;

/* permissions needed by the engine check entry points */
const std::vector<std::string> FULL_PERMS = {
    "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL",
    "ohos.permission.ACCESS_CERT_MANAGER",
    "ohos.permission.ACCESS_USER_TRUSTED_CERT",
    "ohos.permission.ACCESS_SYSTEM_APP_CERT",
};
const std::vector<std::string> COMMON_ONLY_PERMS = {
    "ohos.permission.ACCESS_CERT_MANAGER",
};

/* a hap token whose isSystemApp flag is false: covers the NOT_SYSTEMP_APP branches */
class NonSystemHapToken {
public:
    explicit NonSystemHapToken(const std::vector<std::string> &perms)
    {
        selfToken_ = GetSelfTokenID();
        HapInfoParams hapInfo;
        HapPolicyParams hapPolicy;
        CmTestCommon::SetHapInfoAndPolicy("test.nonsystem.app", perms, false, hapInfo, hapPolicy);
        tokenIdEx_ = CmTestCommon::AllocTestHapToken(hapInfo, hapPolicy);
        SetSelfTokenID(tokenIdEx_.tokenIDEx);
    }

    ~NonSystemHapToken()
    {
        SetSelfTokenID(selfToken_);
        CmTestCommon::DeleteTestHapToken(tokenIdEx_.tokenIdExStruct.tokenID);
    }

private:
    uint64_t selfToken_ = 0;
    AccessTokenIDEx tokenIdEx_ = { 0 };
};

struct CmAppCertParam BuildAppCertParam(struct CmBlob *appCert, struct CmBlob *appCertPwd,
    struct CmBlob *certAlias, uint32_t store, uint32_t userId, enum CredFormat credFormat,
    struct CmBlob *appCertPrivKey)
{
    struct CmAppCertParam param;
    (void)memset_s(&param, sizeof(param), 0, sizeof(param));
    param.appCert = appCert;
    param.appCertPwd = appCertPwd;
    param.certAlias = certAlias;
    param.store = store;
    param.userId = userId;
    param.level = CM_AUTH_STORAGE_LEVEL_EL2;
    param.credFormat = credFormat;
    param.appCertPrivKey = appCertPrivKey;
    param.aliasFormat = DEFAULT_FORMAT;
    return param;
}

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}
} // namespace

class CmEngineCheckTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        /* record the shell token so MockNativeToken can query atm with shell identity */
        CmTestCommon::SetTestEnvironment(GetSelfTokenID());
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
    }

    void SetUp() {}

    void TearDown() {}
};

/**
 * @tc.name: CheckUri_001
 * @tc.desc: validate the uri blob: null, oversized, unterminated, path escape and valid cases
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CheckUri_001, TestSize.Level0)
{
    /* null blob */
    EXPECT_EQ(CheckUri(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* null data */
    struct CmBlob nullData = { 16, nullptr };
    EXPECT_EQ(CheckUri(&nullData), CMR_ERROR_INVALID_ARGUMENT);

    /* zero size */
    uint8_t emptyBuf[] = "uri";
    struct CmBlob zeroSize = { 0, emptyBuf };
    EXPECT_EQ(CheckUri(&zeroSize), CMR_ERROR_INVALID_ARGUMENT);

    /* size beyond MAX_AUTH_LEN_URI */
    std::vector<uint8_t> bigBuf(MAX_AUTH_LEN_URI + 1, 'a');
    bigBuf[MAX_AUTH_LEN_URI] = '\0';
    struct CmBlob tooBig = { static_cast<uint32_t>(bigBuf.size()), bigBuf.data() };
    EXPECT_EQ(CheckUri(&tooBig), CMR_ERROR_INVALID_ARGUMENT);

    /* no terminator from index 1 */
    std::vector<uint8_t> noTerm(64, 'a');
    struct CmBlob unterminated = { static_cast<uint32_t>(noTerm.size()), noTerm.data() };
    EXPECT_EQ(CheckUri(&unterminated), CMR_ERROR_INVALID_ARGUMENT);

    /* contains ".." */
    uint8_t escapeUri[] = "oh:t=c;o=..;u=0;a=0";
    struct CmBlob escape = { sizeof(escapeUri), escapeUri };
    EXPECT_EQ(CheckUri(&escape), CMR_ERROR_INVALID_ARGUMENT);

    /* valid uri */
    uint8_t validUri[] = "oh:t=c;o=alias;u=8899;a=889901";
    struct CmBlob valid = { sizeof(validUri), validUri };
    EXPECT_EQ(CheckUri(&valid), CM_SUCCESS);
}

/**
 * @tc.name: CmServiceGetSystemCertListCheck_001
 * @tc.desc: store type validation and permission gating of the system cert list check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetSystemCertListCheck_001, TestSize.Level0)
{
    /* the store check happens before the permission check: no token needed */
    EXPECT_EQ(CmServiceGetSystemCertListCheck(CM_USER_TRUSTED_STORE), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(CmServiceGetSystemCertListCheck(CM_CREDENTIAL_STORE), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* a hap without any permission is rejected */
    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceGetSystemCertListCheck(CM_SYSTEM_TRUSTED_STORE), CMR_ERROR_PERMISSION_DENIED);
    }

    /* a non-system hap holding all permissions is not a system app */
    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceGetSystemCertListCheck(CM_SYSTEM_TRUSTED_STORE), CMR_ERROR_NOT_SYSTEMP_APP);
    }

    /* a system hap holding all permissions passes */
    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceGetSystemCertListCheck(CM_SYSTEM_TRUSTED_STORE), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceGetSystemCertCheck_001
 * @tc.desc: store, uri and permission validation of the single system cert check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetSystemCertCheck_001, TestSize.Level0)
{
    uint8_t validUri[] = "oh:t=c;o=alias;u=0;a=0";
    struct CmBlob uri = { sizeof(validUri), validUri };

    /* store and uri validation run before the permission check */
    EXPECT_EQ(CmServiceGetSystemCertCheck(CM_USER_TRUSTED_STORE, &uri), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(CmServiceGetSystemCertCheck(CM_SYSTEM_TRUSTED_STORE, nullptr), CMR_ERROR_INVALID_ARGUMENT_URI);

    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceGetSystemCertCheck(CM_SYSTEM_TRUSTED_STORE, &uri), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceGetSystemCertCheck(CM_SYSTEM_TRUSTED_STORE, &uri), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceSetCertStatusCheck_001
 * @tc.desc: store, uri, status, permission and system app validation of the status check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceSetCertStatusCheck_001, TestSize.Level0)
{
    uint8_t validUri[] = "oh:t=c;o=alias;u=0;a=0";
    struct CmBlob uri = { sizeof(validUri), validUri };

    /* argument validation happens before the permission check */
    EXPECT_EQ(CmServiceSetCertStatusCheck(CM_USER_TRUSTED_STORE, &uri, 0), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, nullptr, 0), CMR_ERROR_INVALID_ARGUMENT_URI);
    EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, &uri, 2), CMR_ERROR_INVALID_ARGUMENT_STATUS);

    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, &uri, 0), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, &uri, 0), CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, &uri, 0), CM_SUCCESS);
        EXPECT_EQ(CmServiceSetCertStatusCheck(CM_SYSTEM_TRUSTED_STORE, &uri, 1), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceInstallAppCertCheck_001
 * @tc.desc: null, store, level, format, cert, alias and password validation of the install check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceInstallAppCertCheck_001, TestSize.Level0)
{
    MockHapToken fullPerm; /* argument validation runs before the permission check */

    uint8_t certBuf[] = "fakeAppCert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "123456";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias8899";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };

    struct CmContext context = BuildContext(0, TEST_CHECK_UID);

    /* null arguments */
    struct CmAppCertParam param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias,
        CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(nullptr, &context), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* store, level, credFormat and aliasFormat macro checks */
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_USER_TRUSTED_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    param.level = static_cast<enum CmAuthStorageLevel>(99);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    param.credFormat = static_cast<enum CredFormat>(99);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    param.aliasFormat = static_cast<enum AliasTransFormat>(99);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT);

    /* appCert blob validation */
    struct CmBlob badCert = { 16, nullptr };
    param = BuildAppCertParam(&badCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
    std::vector<uint8_t> bigCert(MAX_LEN_APP_CERT + 1, 'a');
    struct CmBlob bigCertBlob = { static_cast<uint32_t>(bigCert.size()), bigCert.data() };
    param = BuildAppCertParam(&bigCertBlob, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_APP_CERT);

    /* alias blob validation */
    struct CmBlob badAlias = { 16, nullptr };
    param = BuildAppCertParam(&appCert, &appCertPwd, &badAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);
    std::vector<uint8_t> bigAlias(MAX_LEN_CERT_ALIAS + 1, 'a');
    bigAlias[MAX_LEN_CERT_ALIAS] = '\0';
    struct CmBlob bigAliasBlob = { static_cast<uint32_t>(bigAlias.size()), bigAlias.data() };
    param = BuildAppCertParam(&appCert, &appCertPwd, &bigAliasBlob, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);
    /* the private credential store keeps a tighter alias limit */
    param = BuildAppCertParam(&appCert, &appCertPwd, &bigAliasBlob, CM_PRI_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);
    /* the default alias format only accepts letters, digits and the underscore */
    uint8_t invalidCharAlias[] = "ali as";
    struct CmBlob invalidChar = { sizeof(invalidCharAlias), invalidCharAlias };
    param = BuildAppCertParam(&appCert, &appCertPwd, &invalidChar, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);
    /* the sha256 alias format accepts arbitrary bytes terminated by '\0' */
    std::vector<uint8_t> shaAlias(MAX_LEN_CERT_ALIAS - 1, 0xAB);
    shaAlias[MAX_LEN_CERT_ALIAS - 2] = '\0';
    struct CmBlob shaAliasBlob = { static_cast<uint32_t>(shaAlias.size()), shaAlias.data() };
    param = BuildAppCertParam(&appCert, &appCertPwd, &shaAliasBlob, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    param.aliasFormat = SHA256_FORMAT;
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);

    /* an empty alias is accepted for the public and system credential stores */
    uint8_t emptyAliasBuf[] = "";
    struct CmBlob emptyAlias = { sizeof(emptyAliasBuf), emptyAliasBuf };
    param = BuildAppCertParam(&appCert, &appCertPwd, &emptyAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);
    struct CmContext sysAliasCtx = BuildContext(0, TEST_CHECK_UID);
    param = BuildAppCertParam(&appCert, &appCertPwd, &emptyAlias, CM_SYS_CREDENTIAL_STORE,
        TEST_CHECK_USER, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &sysAliasCtx), CM_SUCCESS);
    /* ... but not for the private credential store */
    param = BuildAppCertParam(&appCert, &appCertPwd, &emptyAlias, CM_PRI_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);

    /* the private credential store keeps a tighter alias limit */
    std::vector<uint8_t> midAlias(MAX_LEN_PRI_CRED_ALIAS + 1, 'a');
    midAlias[MAX_LEN_PRI_CRED_ALIAS] = '\0';
    struct CmBlob midAliasBlob = { static_cast<uint32_t>(midAlias.size()), midAlias.data() };
    param = BuildAppCertParam(&appCert, &appCertPwd, &midAliasBlob, CM_PRI_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_ALIAS);

    /* p12 password validation */
    struct CmBlob badPwd = { 8, nullptr };
    param = BuildAppCertParam(&appCert, &badPwd, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_APP_PWD);
    std::vector<uint8_t> bigPwd(MAX_LEN_APP_CERT_PASSWD + 1, 'p');
    struct CmBlob bigPwdBlob = { static_cast<uint32_t>(bigPwd.size()), bigPwd.data() };
    param = BuildAppCertParam(&appCert, &bigPwdBlob, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_APP_PWD);
    std::vector<uint8_t> noTermPwd(MAX_LEN_APP_CERT_PASSWD - 1, 'p'); /* no terminator inside */
    struct CmBlob noTermPwdBlob = { static_cast<uint32_t>(noTermPwd.size()), noTermPwd.data() };
    param = BuildAppCertParam(&appCert, &noTermPwdBlob, &certAlias, CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT);

    /* chain key private key validation */
    struct CmBlob badKey = { 16, nullptr };
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, CHAIN_KEY, &badKey);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY);
    std::vector<uint8_t> bigKey(MAX_LEN_CRED_PRI_KEY + 1, 'k');
    bigKey[MAX_LEN_CRED_PRI_KEY] = '\0';
    struct CmBlob bigKeyBlob = { static_cast<uint32_t>(bigKey.size()), bigKey.data() };
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 0, CHAIN_KEY, &bigKeyBlob);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY);
}

/**
 * @tc.name: CmServiceInstallAppCertCheck_002
 * @tc.desc: userId update rules, permission and system app gating of the install check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceInstallAppCertCheck_002, TestSize.Level0)
{
    uint8_t certBuf[] = "fakeAppCert";
    struct CmBlob appCert = { sizeof(certBuf), certBuf };
    uint8_t pwdBuf[] = "123456";
    struct CmBlob appCertPwd = { sizeof(pwdBuf), pwdBuf };
    uint8_t aliasBuf[] = "alias8899";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };

    MockHapToken fullPerm;
    struct CmContext context = BuildContext(0, TEST_CHECK_UID);

    /* sa caller: an empty userId is only valid for the public credential store */
    struct CmAppCertParam param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias,
        CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);

    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_SYS_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_SYS_CREDENTIAL_STORE,
        INIT_INVALID_VALUE, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    /* sa caller: a designated userId is adopted into the context */
    context = BuildContext(0, TEST_CHECK_UID);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, TEST_CHECK_USER,
        FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);
    EXPECT_EQ(context.userId, TEST_CHECK_USER);

    context = BuildContext(0, TEST_CHECK_UID);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_SYS_CREDENTIAL_STORE, TEST_CHECK_USER,
        FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);
    EXPECT_EQ(context.userId, TEST_CHECK_USER);

    /* hap caller: a designated userId is not supported */
    context = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE, 100, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    /* hap caller: the unset userId is accepted and keeps the context */
    context = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    param = BuildAppCertParam(&appCert, &appCertPwd, &certAlias, CM_CREDENTIAL_STORE,
        INIT_INVALID_VALUE, FILE_P12, nullptr);
    EXPECT_EQ(CmServiceInstallAppCertCheck(&param, &context), CM_SUCCESS);
    EXPECT_EQ(context.userId, TEST_CHECK_USER);

    /* permission and system app gating */
    {
        MockHapToken noPerm;
        struct CmContext ctx = BuildContext(0, TEST_CHECK_UID);
        struct CmAppCertParam p = BuildAppCertParam(&appCert, &appCertPwd, &certAlias,
            CM_CREDENTIAL_STORE, 0, FILE_P12, nullptr);
        EXPECT_EQ(CmServiceInstallAppCertCheck(&p, &ctx), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        struct CmAppCertParam p = BuildAppCertParam(&appCert, &appCertPwd, &certAlias,
            CM_CREDENTIAL_STORE, INIT_INVALID_VALUE, FILE_P12, nullptr);
        EXPECT_EQ(CmServiceInstallAppCertCheck(&p, &ctx), CMR_ERROR_NOT_SYSTEMP_APP);
    }
}

/**
 * @tc.name: CmServiceUninstallAppCertCheck_001
 * @tc.desc: store, uri, permission, system app and caller/uri consistency validation
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceUninstallAppCertCheck_001, TestSize.Level0)
{
    uint8_t keyUriBuf[] = "oh:t=ak;o=alias;u=0;a=0";
    struct CmBlob keyUri = { sizeof(keyUriBuf), keyUriBuf };
    uint8_t sysUriBuf[] = "oh:t=sk;o=alias;u=0;a=0";
    struct CmBlob sysUri = { sizeof(sysUriBuf), sysUriBuf };

    /* store and uri validation run before the permission check */
    EXPECT_EQ(CmServiceUninstallAppCertCheck(nullptr, CM_USER_TRUSTED_STORE, &keyUri),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(CmServiceUninstallAppCertCheck(nullptr, CM_CREDENTIAL_STORE, nullptr),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    {
        MockHapToken noPerm;
        struct CmContext ctx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_CREDENTIAL_STORE, &keyUri),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_CREDENTIAL_STORE, &keyUri),
            CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        /* public credential store: no caller/uri consistency required */
        struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_CREDENTIAL_STORE, &keyUri), CM_SUCCESS);

        /* system credential store: the uri must decode to a sys key uri */
        uint8_t badTypeUriBuf[] = "oh:t=c;o=alias;u=0;a=0";
        struct CmBlob badTypeUri = { sizeof(badTypeUriBuf), badTypeUriBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_SYS_CREDENTIAL_STORE, &badTypeUri),
            CMR_ERROR_INVALID_ARGUMENT_URI);

        uint8_t badSchemeBuf[] = "xx:t=sk;o=alias;u=0;a=0";
        struct CmBlob badScheme = { sizeof(badSchemeBuf), badSchemeBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_SYS_CREDENTIAL_STORE, &badScheme),
            CMR_ERROR_INVALID_ARGUMENT_URI);

        uint8_t noAppUriBuf[] = "oh:t=sk;o=alias;u=0";
        struct CmBlob noAppUri = { sizeof(noAppUriBuf), noAppUriBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_SYS_CREDENTIAL_STORE, &noAppUri),
            CMR_ERROR_INVALID_ARGUMENT_URI);

        uint8_t nonNumericBuf[] = "oh:t=sk;o=alias;u=abc;a=0";
        struct CmBlob nonNumeric = { sizeof(nonNumericBuf), nonNumericBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&ctx, CM_SYS_CREDENTIAL_STORE, &nonNumeric),
            CMR_ERROR_INVALID_ARGUMENT_URI);

        /* sa caller with a mismatching uid is rejected */
        struct CmContext saCtx = BuildContext(0, TEST_CHECK_OTHER_UID);
        uint8_t sysUidUriBuf[] = "oh:t=sk;o=alias;u=8899;a=889901";
        struct CmBlob sysUidUri = { sizeof(sysUidUriBuf), sysUidUriBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&saCtx, CM_SYS_CREDENTIAL_STORE, &sysUidUri),
            CMR_ERROR_INVALID_ARGUMENT_UID);

        /* hap caller with a mismatching userId is rejected */
        struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        uint8_t otherUserUriBuf[] = "oh:t=sk;o=alias;u=100;a=889901";
        struct CmBlob otherUserUri = { sizeof(otherUserUriBuf), otherUserUriBuf };
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE, &otherUserUri),
            CMR_ERROR_INVALID_ARGUMENT_USER_ID);

        /* matching caller adopts the uri identity */
        struct CmContext okCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&okCtx, CM_SYS_CREDENTIAL_STORE, &sysUidUri), CM_SUCCESS);
        EXPECT_EQ(okCtx.userId, TEST_CHECK_USER);
        EXPECT_EQ(okCtx.uid, TEST_CHECK_UID);

        /* an sa caller accepts the global sys uri as well */
        struct CmContext saGlobalCtx = BuildContext(0, 0);
        EXPECT_EQ(CmServiceUninstallAppCertCheck(&saGlobalCtx, CM_SYS_CREDENTIAL_STORE, &sysUri), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceGetAppCertListCheck_001
 * @tc.desc: store, userId, permission and system app validation of the list check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetAppCertListCheck_001, TestSize.Level0)
{
    /* the store and userId checks run before the permission check */
    EXPECT_EQ(CmServiceGetAppCertListCheck(nullptr, CM_USER_TRUSTED_STORE),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    struct CmContext saCtx = BuildContext(0, TEST_CHECK_UID);
    EXPECT_EQ(CmServiceGetAppCertListCheck(&saCtx, CM_SYS_CREDENTIAL_STORE),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE), CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE), CMR_ERROR_NOT_SYSTEMP_APP);
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE), CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE), CM_SUCCESS);
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE), CM_SUCCESS);
        EXPECT_EQ(CmServiceGetAppCertListCheck(&hapCtx, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceGetCallingAppCertListCheck_001
 * @tc.desc: store, userId, common, privileged and system app validation of the calling list check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetCallingAppCertListCheck_001, TestSize.Level0)
{
    /* the store and userId checks run before the permission check */
    EXPECT_EQ(CmServiceGetCallingAppCertListCheck(nullptr, CM_USER_TRUSTED_STORE),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    struct CmContext saCtx = BuildContext(0, TEST_CHECK_UID);
    EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&saCtx, CM_SYS_CREDENTIAL_STORE),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE),
            CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_PRI_CREDENTIAL_STORE),
            CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        /* the common permission alone unlocks the private credential store */
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE),
            CMR_ERROR_NOT_SYSTEMP_APP);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE),
            CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_SYS_CREDENTIAL_STORE), CM_SUCCESS);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_CREDENTIAL_STORE), CM_SUCCESS);
        EXPECT_EQ(CmServiceGetCallingAppCertListCheck(&hapCtx, CM_PRI_CREDENTIAL_STORE), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceGetAppCertCheck_001
 * @tc.desc: store, uri, common, system app cert permission and system app validation
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetAppCertCheck_001, TestSize.Level0)
{
    uint8_t sysUriBuf[] = "oh:t=sk;o=alias;u=8899;a=889901";
    struct CmBlob sysUri = { sizeof(sysUriBuf), sysUriBuf };
    uint8_t credUriBuf[] = "oh:t=ak;o=alias;u=0;a=0";
    struct CmBlob credUri = { sizeof(credUriBuf), credUriBuf };

    /* the store and uri checks run before the permission check */
    EXPECT_EQ(CmServiceGetAppCertCheck(nullptr, CM_USER_TRUSTED_STORE, &sysUri),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(CmServiceGetAppCertCheck(nullptr, CM_CREDENTIAL_STORE, nullptr),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    {
        MockHapToken noPerm;
        struct CmContext noPermCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&noPermCtx, CM_CREDENTIAL_STORE, &credUri),
            CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmServiceGetAppCertCheck(&noPermCtx, CM_SYS_CREDENTIAL_STORE, &sysUri),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        /* the common permission without the system app cert permission is rejected */
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        struct CmContext credCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&credCtx, CM_CREDENTIAL_STORE, &credUri), CM_SUCCESS);
        struct CmContext sysNoPermCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&sysNoPermCtx, CM_SYS_CREDENTIAL_STORE, &sysUri),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        struct CmContext sysCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&sysCtx, CM_SYS_CREDENTIAL_STORE, &sysUri),
            CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        struct CmContext credCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&credCtx, CM_CREDENTIAL_STORE, &credUri), CM_SUCCESS);
        struct CmContext sysCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceGetAppCertCheck(&sysCtx, CM_SYS_CREDENTIAL_STORE, &sysUri), CM_SUCCESS);

        /* a bad uri is still rejected for the system store */
        struct CmContext badUriCtx = BuildContext(0, TEST_CHECK_UID);
        uint8_t badUriBuf[] = "oh:t=c;o=alias;u=0;a=0";
        struct CmBlob badUri = { sizeof(badUriBuf), badUriBuf };
        EXPECT_EQ(CmServiceGetAppCertCheck(&badUriCtx, CM_SYS_CREDENTIAL_STORE, &badUri),
            CMR_ERROR_INVALID_ARGUMENT_URI);
    }
}

/**
 * @tc.name: CmServiceGetUserCertInfoCheck_001
 * @tc.desc: context, uri decode, field, userId and uid validation with context update
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetUserCertInfoCheck_001, TestSize.Level0)
{
    uint8_t validUriBuf[] = "oh:t=c;o=alias;u=8899;a=889901";
    struct CmBlob validUri = { sizeof(validUriBuf), validUriBuf };

    /* null context */
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(nullptr, &validUri, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT);

    /* uri blob failing CheckUri */
    std::vector<uint8_t> noTerm(64, 'a');
    struct CmBlob unterminated = { static_cast<uint32_t>(noTerm.size()), noTerm.data() };
    struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &unterminated, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* uri decode failures */
    uint8_t badSchemeBuf[] = "xx:t=c;o=alias;u=0;a=0";
    struct CmBlob badScheme = { sizeof(badSchemeBuf), badSchemeBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &badScheme, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t noObjectBuf[] = "oh:t=c;u=0;a=0";
    struct CmBlob noObject = { sizeof(noObjectBuf), noObjectBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &noObject, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t wrongTypeBuf[] = "oh:t=ak;o=alias;u=0;a=0";
    struct CmBlob wrongType = { sizeof(wrongTypeBuf), wrongTypeBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &wrongType, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    uint8_t nonNumericBuf[] = "oh:t=c;o=alias;u=abc;a=0";
    struct CmBlob nonNumeric = { sizeof(nonNumericBuf), nonNumericBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &nonNumeric, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    /* an unsupported uri type maps to the store type error */
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &validUri, CM_URI_TYPE_APP_KEY, false),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);

    /* certificate uri: a hap caller only accepts its own user or the global user */
    uint8_t otherUserUriBuf[] = "oh:t=c;o=alias;u=100;a=889901";
    struct CmBlob otherUserUri = { sizeof(otherUserUriBuf), otherUserUriBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &otherUserUri, CM_URI_TYPE_CERTIFICATE, false),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    uint8_t globalUserUriBuf[] = "oh:t=c;o=alias;u=0;a=0";
    struct CmBlob globalUserUri = { sizeof(globalUserUriBuf), globalUserUriBuf };
    struct CmContext globalCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&globalCtx, &globalUserUri, CM_URI_TYPE_CERTIFICATE, false),
        CM_SUCCESS);
    EXPECT_EQ(globalCtx.userId, 0); /* adopted from the uri */

    /* sys key uri: the userId must match exactly for a hap caller */
    uint8_t sysUriBuf[] = "oh:t=sk;o=alias;u=100;a=889901";
    struct CmBlob sysUri = { sizeof(sysUriBuf), sysUriBuf };
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&ctx, &sysUri, CM_URI_TYPE_SYS_KEY, false),
        CMR_ERROR_INVALID_ARGUMENT_USER_ID);

    /* sa caller with the uid check: the uid must match the producer */
    struct CmContext saCtx = BuildContext(0, TEST_CHECK_OTHER_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&saCtx, &validUri, CM_URI_TYPE_CERTIFICATE, true),
        CMR_ERROR_INVALID_ARGUMENT_UID);

    /* without the uid check the sa caller passes regardless of the uri uid */
    struct CmContext saCtxNoCheck = BuildContext(0, TEST_CHECK_OTHER_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&saCtxNoCheck, &validUri, CM_URI_TYPE_CERTIFICATE, false),
        CM_SUCCESS);
    EXPECT_EQ(saCtxNoCheck.uid, TEST_CHECK_UID); /* adopted from the uri */

    /* a hap caller passes the uid check even with a foreign uri uid */
    struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_OTHER_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&hapCtx, &validUri, CM_URI_TYPE_CERTIFICATE, true),
        CM_SUCCESS);

    /* matching sa caller with the uid check */
    struct CmContext okCtx = BuildContext(0, TEST_CHECK_UID);
    EXPECT_EQ(CmServiceGetUserCertInfoCheck(&okCtx, &validUri, CM_URI_TYPE_CERTIFICATE, true),
        CM_SUCCESS);
    EXPECT_EQ(okCtx.userId, TEST_CHECK_USER);
    EXPECT_EQ(okCtx.uid, TEST_CHECK_UID);
}

/**
 * @tc.name: CmServiceInstallUserCertCheck_001
 * @tc.desc: context, cert, alias, permission and userId validation of the user cert install check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceInstallUserCertCheck_001, TestSize.Level0)
{
    uint8_t certBuf[] = "fakeUserCert";
    struct CmBlob userCert = { sizeof(certBuf), certBuf };
    uint8_t aliasBuf[] = "alias8899";
    struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };

    /* null context */
    EXPECT_EQ(CmServiceInstallUserCertCheck(nullptr, &userCert, &certAlias, TEST_CHECK_USER, PEM_DER),
        CMR_ERROR_INVALID_ARGUMENT);

    struct CmContext ctx = BuildContext(0, TEST_CHECK_UID);
    {
        MockHapToken fullPerm; /* argument validation runs before the permission check */

        /* userCert blob validation */
        struct CmBlob badCert = { 16, nullptr };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &badCert, &certAlias, 0, PEM_DER),
            CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
        std::vector<uint8_t> bigCert(MAX_LEN_CERTIFICATE + 1, 'c');
        bigCert[MAX_LEN_CERTIFICATE] = '\0';
        struct CmBlob bigCertBlob = { static_cast<uint32_t>(bigCert.size()), bigCert.data() };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &bigCertBlob, &certAlias, 0, PEM_DER),
            CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
        /* the p7b format allows a much bigger payload */
        std::vector<uint8_t> okP7b(MAX_LEN_CERTIFICATE + 1, 'c');
        okP7b[MAX_LEN_CERTIFICATE] = '\0';
        struct CmBlob okP7bBlob = { static_cast<uint32_t>(okP7b.size()), okP7b.data() };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &okP7bBlob, &certAlias, 0, P7B), CM_SUCCESS);
        std::vector<uint8_t> bigP7b(MAX_LEN_CERTIFICATE_P7B + 1, 'c');
        bigP7b[MAX_LEN_CERTIFICATE_P7B] = '\0';
        struct CmBlob bigP7bBlob = { static_cast<uint32_t>(bigP7b.size()), bigP7b.data() };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &bigP7bBlob, &certAlias, 0, P7B),
            CMR_ERROR_INVALID_ARGUMENT_APP_CERT);

        /* alias validation */
        struct CmBlob badAlias = { 16, nullptr };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &userCert, &badAlias, 0, PEM_DER),
            CMR_ERROR_INVALID_ARGUMENT_ALIAS);
        std::vector<uint8_t> bigAlias(MAX_LEN_CERT_ALIAS + 1, 'a');
        bigAlias[MAX_LEN_CERT_ALIAS] = '\0';
        struct CmBlob bigAliasBlob = { static_cast<uint32_t>(bigAlias.size()), bigAlias.data() };
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &userCert, &bigAliasBlob, 0, PEM_DER),
            CMR_ERROR_INVALID_ARGUMENT_ALIAS);

        /* userId rules: the sa caller may leave it unset or designate it */
        struct CmContext saCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceInstallUserCertCheck(&saCtx, &userCert, &certAlias, INIT_INVALID_VALUE, PEM_DER),
            CM_SUCCESS);
        EXPECT_EQ(saCtx.userId, 0);

        saCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceInstallUserCertCheck(&saCtx, &userCert, &certAlias, TEST_CHECK_USER, PEM_DER),
            CM_SUCCESS);
        EXPECT_EQ(saCtx.userId, TEST_CHECK_USER);

        /* the hap caller may not designate another user */
        struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceInstallUserCertCheck(&hapCtx, &userCert, &certAlias, 100, PEM_DER),
            CMR_ERROR_INVALID_ARGUMENT_USER_ID);

        /* the hap caller may request the public location */
        hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceInstallUserCertCheck(&hapCtx, &userCert, &certAlias, 0, PEM_DER), CM_SUCCESS);
        EXPECT_EQ(hapCtx.userId, 0);

        /* the hap caller may leave it unset */
        hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceInstallUserCertCheck(&hapCtx, &userCert, &certAlias, INIT_INVALID_VALUE, PEM_DER),
            CM_SUCCESS);
        EXPECT_EQ(hapCtx.userId, TEST_CHECK_USER);
    }

    {
        /* without any trusted permission the install is denied */
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &userCert, &certAlias, 0, PEM_DER),
            CMR_ERROR_PERMISSION_DENIED);
    }

    {
        /* the enterprise trusted permission alone is enough */
        MockHapToken enterpriseOnly({ "ohos.permission.ACCESS_ENTERPRISE_USER_TRUSTED_CERT" });
        EXPECT_EQ(CmServiceInstallUserCertCheck(&ctx, &userCert, &certAlias, 0, PEM_DER), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceUninstallUserCertCheck_001
 * @tc.desc: context, uri, permission and caller/uri consistency validation
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceUninstallUserCertCheck_001, TestSize.Level0)
{
    uint8_t validUriBuf[] = "oh:t=c;o=alias;u=8899;a=889901";
    struct CmBlob validUri = { sizeof(validUriBuf), validUriBuf };

    /* null context */
    EXPECT_EQ(CmServiceUninstallUserCertCheck(nullptr, &validUri), CMR_ERROR_INVALID_ARGUMENT);

    struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    {
        MockHapToken fullPerm; /* argument validation runs before the permission check */

        /* uri blob validation */
        std::vector<uint8_t> noTerm(64, 'a');
        struct CmBlob unterminated = { static_cast<uint32_t>(noTerm.size()), noTerm.data() };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &unterminated), CMR_ERROR_INVALID_ARGUMENT_URI);

        /* uri decode and field validation */
        uint8_t badSchemeBuf[] = "xx:t=c;o=alias;u=0;a=0";
        struct CmBlob badScheme = { sizeof(badSchemeBuf), badSchemeBuf };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &badScheme), CMR_ERROR_INVALID_ARGUMENT_URI);

        uint8_t wrongTypeBuf[] = "oh:t=ak;o=alias;u=0;a=0";
        struct CmBlob wrongType = { sizeof(wrongTypeBuf), wrongTypeBuf };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &wrongType), CMR_ERROR_INVALID_ARGUMENT_URI);

        uint8_t noAppUriBuf[] = "oh:t=c;o=alias;u=0";
        struct CmBlob noAppUri = { sizeof(noAppUriBuf), noAppUriBuf };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &noAppUri), CMR_ERROR_INVALID_ARGUMENT_URI);

        /* a hap caller only uninstalls its own user or the global user */
        uint8_t otherUserUriBuf[] = "oh:t=c;o=alias;u=100;a=889901";
        struct CmBlob otherUserUri = { sizeof(otherUserUriBuf), otherUserUriBuf };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &otherUserUri),
            CMR_ERROR_INVALID_ARGUMENT_USER_ID);

        uint8_t globalUserUriBuf[] = "oh:t=c;o=alias;u=0;a=0";
        struct CmBlob globalUserUri = { sizeof(globalUserUriBuf), globalUserUriBuf };
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &globalUserUri), CM_SUCCESS);

        /* the sa caller with a mismatching uid is rejected */
        struct CmContext saCtx = BuildContext(0, TEST_CHECK_OTHER_UID);
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&saCtx, &validUri), CMR_ERROR_INVALID_ARGUMENT_UID);

        /* matching caller adopts the uri identity */
        struct CmContext okCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&okCtx, &validUri), CM_SUCCESS);
        EXPECT_EQ(okCtx.userId, TEST_CHECK_USER);
        EXPECT_EQ(okCtx.uid, TEST_CHECK_UID);
    }

    {
        /* without any trusted permission the uninstall is denied */
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceUninstallUserCertCheck(&ctx, &validUri), CMR_ERROR_PERMISSION_DENIED);
    }
}

/**
 * @tc.name: CmServiceSetUserCertStatusCheck_001
 * @tc.desc: context, permission, system app and caller/uri consistency validation
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceSetUserCertStatusCheck_001, TestSize.Level0)
{
    uint8_t validUriBuf[] = "oh:t=c;o=alias;u=8899;a=889901";
    struct CmBlob validUri = { sizeof(validUriBuf), validUriBuf };

    /* null context */
    EXPECT_EQ(CmServiceSetUserCertStatusCheck(nullptr, &validUri), CMR_ERROR_INVALID_ARGUMENT);

    struct CmContext ctx = BuildContext(0, TEST_CHECK_UID);
    {
        /* without any permission the status change is denied */
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&ctx, &validUri), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        /* a non system app holding all permissions is rejected */
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&ctx, &validUri), CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        /* uri blob validation */
        std::vector<uint8_t> noTerm(64, 'a');
        struct CmBlob unterminated = { static_cast<uint32_t>(noTerm.size()), noTerm.data() };
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&ctx, &unterminated), CMR_ERROR_INVALID_ARGUMENT_URI);

        /* the sa caller with a mismatching uid is rejected */
        struct CmContext saCtx = BuildContext(0, TEST_CHECK_OTHER_UID);
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&saCtx, &validUri), CMR_ERROR_INVALID_ARGUMENT_UID);

        /* a hap caller with a foreign user is rejected */
        struct CmContext hapCtx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
        uint8_t otherUserUriBuf[] = "oh:t=c;o=alias;u=100;a=889901";
        struct CmBlob otherUserUri = { sizeof(otherUserUriBuf), otherUserUriBuf };
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&hapCtx, &otherUserUri),
            CMR_ERROR_INVALID_ARGUMENT_USER_ID);

        /* matching caller succeeds */
        struct CmContext okCtx = BuildContext(0, TEST_CHECK_UID);
        EXPECT_EQ(CmServiceSetUserCertStatusCheck(&okCtx, &validUri), CM_SUCCESS);
        EXPECT_EQ(okCtx.userId, TEST_CHECK_USER);
        EXPECT_EQ(okCtx.uid, TEST_CHECK_UID);
    }
}

/**
 * @tc.name: CheckInstallMultiCertCount_001
 * @tc.desc: multi cert count check against an empty user store for an isolated user
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CheckInstallMultiCertCount_001, TestSize.Level0)
{
    /* user 8899 owns no user CA directory, the store counts zero entries */
    struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);
    EXPECT_EQ(CheckInstallMultiCertCount(&ctx, 1), CM_SUCCESS);
    EXPECT_EQ(CheckInstallMultiCertCount(&ctx, MAX_COUNT_CERTIFICATE), CM_SUCCESS);
    EXPECT_EQ(CheckInstallMultiCertCount(&ctx, MAX_COUNT_CERTIFICATE + 1), CMR_ERROR_MAX_CERT_COUNT_REACHED);
}

/**
 * @tc.name: CmServiceSetCertManagerConfigCheck_001
 * @tc.desc: permission, count, key and value validation of the config set check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceSetCertManagerConfigCheck_001, TestSize.Level0)
{
    {
        /* the privileged permission is checked first */
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceSetCertManagerConfigCheck(nullptr), CMR_ERROR_PERMISSION_DENIED);
    }

    MockHapToken fullPerm;

    /* null config */
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* count validation */
    struct CmConfigItem items[MAX_COUNT_CONFIG_ITEM];
    (void)memset_s(items, sizeof(items), 0, sizeof(items));
    struct CertManagerConfig zeroCount = { 0, items };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&zeroCount), CMR_ERROR_INVALID_ARGUMENT);
    struct CertManagerConfig bigCount = { MAX_COUNT_CONFIG_ITEM + 1, items };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&bigCount), CMR_ERROR_INVALID_ARGUMENT);
    struct CertManagerConfig nullItems = { 1, nullptr };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&nullItems), CMR_ERROR_INVALID_ARGUMENT);

    /* empty key */
    struct CmConfigItem emptyItem = { "", "enable" };
    struct CertManagerConfig emptyKey = { 1, &emptyItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&emptyKey), CMR_ERROR_INVALID_ARGUMENT);

    /* unsupported key */
    struct CmConfigItem unknownItem = { "unknown_key", "enable" };
    struct CertManagerConfig unknownKey = { 1, &unknownItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&unknownKey), CMR_ERROR_INVALID_ARGUMENT);

    /* protected engine managed key */
    struct CmConfigItem protectedItem = { "last_cleanup_utc", "12345" };
    struct CertManagerConfig protectedKey = { 1, &protectedItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&protectedKey), CMR_ERROR_INVALID_ARGUMENT);

    /* default config value validation */
    struct CmConfigItem badDefaultItem = { "installGlobalUserCA_defaultConfig", "yes" };
    struct CertManagerConfig badDefault = { 1, &badDefaultItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&badDefault), CMR_ERROR_INVALID_ARGUMENT);

    /* user list value validation */
    struct CmConfigItem badListValueItem = { "enableInstallGlobalUserCA_userList", "abc|def" };
    struct CertManagerConfig badListValue = { 1, &badListValueItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&badListValue), CMR_ERROR_INVALID_ARGUMENT);

    /* valid single items */
    struct CmConfigItem defaultEnableItem = { "installGlobalUserCA_defaultConfig", "enable" };
    struct CertManagerConfig defaultEnable = { 1, &defaultEnableItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&defaultEnable), CM_SUCCESS);

    struct CmConfigItem defaultDisableItem = { "installGlobalUserCA_defaultConfig", "disable" };
    struct CertManagerConfig defaultDisable = { 1, &defaultDisableItem };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&defaultDisable), CM_SUCCESS);

    struct CmConfigItem userList = { "disableInstallGlobalUserCA_userList", "100|101" };
    struct CertManagerConfig listConfig = { 1, &userList };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&listConfig), CM_SUCCESS);

    /* an empty user list value means clearing the config */
    struct CmConfigItem emptyList = { "disableInstallGlobalUserCA_userList", "" };
    struct CertManagerConfig emptyListConfig = { 1, &emptyList };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&emptyListConfig), CM_SUCCESS);

    /* a full config of four valid items */
    struct CmConfigItem fullItems[MAX_COUNT_CONFIG_ITEM] = {
        { "installGlobalUserCA_defaultConfig", "enable" },
        { "enableInstallGlobalUserCA_userList", "100" },
        { "disableInstallGlobalUserCA_userList", "100|101|102" },
        { "installGlobalUserCA_defaultConfig", "disable" },
    };
    struct CertManagerConfig fullConfig = { MAX_COUNT_CONFIG_ITEM, fullItems };
    EXPECT_EQ(CmServiceSetCertManagerConfigCheck(&fullConfig), CM_SUCCESS);
}

/**
 * @tc.name: CmServiceGetCertManagerConfigCheck_001
 * @tc.desc: permission and system app validation of the config get check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetCertManagerConfigCheck_001, TestSize.Level0)
{
    uint8_t keysBuf[] = "installGlobalUserCA_defaultConfig";
    struct CmBlob keys = { sizeof(keysBuf), keysBuf };

    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceGetCertManagerConfigCheck(&keys), CMR_ERROR_PERMISSION_DENIED);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmServiceGetCertManagerConfigCheck(&keys), CMR_ERROR_NOT_SYSTEMP_APP);
    }

    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmServiceGetCertManagerConfigCheck(&keys), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmServiceGetCertManagerConfigCheckKeys_001
 * @tc.desc: key blob termination, per key validation and tolerated boundaries
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceGetCertManagerConfigCheckKeys_001, TestSize.Level0)
{
    /* null or empty blobs are accepted */
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(nullptr), CM_SUCCESS);
    uint8_t anyBuf[] = "any";
    struct CmBlob nullData = { 0, anyBuf };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&nullData), CM_SUCCESS);
    struct CmBlob nullBuf = { 16, nullptr };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&nullBuf), CM_SUCCESS);

    /* the last byte must terminate the key list */
    uint8_t notTerminated[] = "installGlobalUserCA_defaultConfig";
    struct CmBlob noTerm = { sizeof(notTerminated) - 1, notTerminated };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&noTerm), CMR_ERROR_INVALID_ARGUMENT);

    /* an unsupported key is rejected */
    uint8_t unknownKeyBuf[] = "unknown_key";
    struct CmBlob unknownKey = { sizeof(unknownKeyBuf), unknownKeyBuf };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&unknownKey), CMR_ERROR_INVALID_ARGUMENT);

    /* two valid keys terminated by '\0' are accepted */
    uint8_t validKeysBuf[] = "installGlobalUserCA_defaultConfig\0enableInstallGlobalUserCA_userList";
    struct CmBlob validKeys = { sizeof(validKeysBuf), validKeysBuf };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&validKeys), CM_SUCCESS);

    /* the protected engine key stays readable */
    uint8_t protectedKeyBuf[] = "last_cleanup_utc";
    struct CmBlob protectedKey = { sizeof(protectedKeyBuf), protectedKeyBuf };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&protectedKey), CM_SUCCESS);

    /* an empty key stops the walk without an error */
    uint8_t emptyKeyBuf[] = "";
    struct CmBlob emptyKey = { sizeof(emptyKeyBuf), emptyKeyBuf };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&emptyKey), CM_SUCCESS);

    /* a key at the length boundary stops the walk without an error */
    std::string boundaryKey(MAX_LEN_CONFIG_KEY, 'k');
    std::vector<uint8_t> boundaryBuf(boundaryKey.begin(), boundaryKey.end());
    boundaryBuf.push_back('\0');
    struct CmBlob boundary = { static_cast<uint32_t>(boundaryBuf.size()), boundaryBuf.data() };
    EXPECT_EQ(CmServiceGetCertManagerConfigCheckKeys(&boundary), CM_SUCCESS);
}

/**
 * @tc.name: CmServiceFindCertCheck_001
 * @tc.desc: request, permission, scope and cert type validation of the find cert check
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmServiceFindCertCheck_001, TestSize.Level0)
{
    struct CmContext ctx = BuildContext(TEST_CHECK_USER, TEST_CHECK_UID);

    /* null request */
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    struct FindCertRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    request.certTypesCount = 1;
    enum CmFindCertType certTypes[MAX_COUNT_FIND_CERT_TYPE] = { CM_FIND_CERT_TYPE_USER_CA };
    request.certTypes = certTypes;

    {
        MockHapToken noPerm;
        EXPECT_EQ(CmServiceFindCertCheck(&ctx, &request), CMR_ERROR_PERMISSION_DENIED);
    }

    MockHapToken fullPerm;

    /* scope validation */
    struct FindCertRequest badScope = request;
    badScope.scope = static_cast<enum CmFindCertScope>(99);
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &badScope), CMR_ERROR_INVALID_ARGUMENT);

    /* certTypesCount without a certTypes array */
    struct FindCertRequest nullTypes = request;
    nullTypes.certTypes = nullptr;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &nullTypes), CMR_ERROR_INVALID_ARGUMENT);

    /* an unsupported cert type */
    enum CmFindCertType badTypes[MAX_COUNT_FIND_CERT_TYPE] = { static_cast<enum CmFindCertType>(99) };
    struct FindCertRequest badTypesReq = request;
    badTypesReq.certTypes = badTypes;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &badTypesReq), CMR_ERROR_INVALID_ARGUMENT);

    /* zero cert types skip the loop */
    struct FindCertRequest noTypes = request;
    noTypes.certTypesCount = 0;
    noTypes.certTypes = nullptr;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &noTypes), CM_SUCCESS);

    /* all scopes are valid */
    request.scope = CM_FIND_CERT_SCOPE_GLOBAL;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &request), CM_SUCCESS);
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_AND_GLOBAL;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &request), CM_SUCCESS);
    request.scope = CM_FIND_CERT_SCOPE_CURRENT_USER;
    EXPECT_EQ(CmServiceFindCertCheck(&ctx, &request), CM_SUCCESS);
}

/**
 * @tc.name: CmPermissionCheck_001
 * @tc.desc: store keyed permission aggregation for the three credential stores
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmPermissionCheck_001, TestSize.Level0)
{
    {
        MockHapToken fullPerm;
        EXPECT_TRUE(CmPermissionCheck(CM_CREDENTIAL_STORE));
        EXPECT_TRUE(CmPermissionCheck(CM_PRI_CREDENTIAL_STORE));
        EXPECT_TRUE(CmPermissionCheck(CM_SYS_CREDENTIAL_STORE));
        EXPECT_FALSE(CmPermissionCheck(CM_USER_TRUSTED_STORE));
    }

    {
        MockHapToken noPerm;
        EXPECT_FALSE(CmPermissionCheck(CM_CREDENTIAL_STORE));
        EXPECT_FALSE(CmPermissionCheck(CM_PRI_CREDENTIAL_STORE));
        EXPECT_FALSE(CmPermissionCheck(CM_SYS_CREDENTIAL_STORE));
        EXPECT_FALSE(CmPermissionCheck(CM_SYSTEM_TRUSTED_STORE));
    }

    {
        /* the common permission alone only unlocks the private credential store */
        MockHapToken commonOnly(COMMON_ONLY_PERMS);
        EXPECT_FALSE(CmPermissionCheck(CM_CREDENTIAL_STORE));
        EXPECT_TRUE(CmPermissionCheck(CM_PRI_CREDENTIAL_STORE));
        EXPECT_FALSE(CmPermissionCheck(CM_SYS_CREDENTIAL_STORE));
    }
}

/**
 * @tc.name: CmHasGetCAPermission_001
 * @tc.desc: store keyed CA permission aggregation for system and user stores
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmHasGetCAPermission_001, TestSize.Level0)
{
    {
        MockHapToken fullPerm;
        EXPECT_EQ(CmHasGetCAPermission(CM_SYSTEM_TRUSTED_STORE), CM_SUCCESS);
        EXPECT_EQ(CmHasGetCAPermission(CM_USER_TRUSTED_STORE), CM_SUCCESS);
        EXPECT_EQ(CmHasGetCAPermission(CM_CREDENTIAL_STORE), CMR_ERROR_INVALID_ARGUMENT);
    }

    {
        MockHapToken noPerm;
        EXPECT_EQ(CmHasGetCAPermission(CM_SYSTEM_TRUSTED_STORE), CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmHasGetCAPermission(CM_USER_TRUSTED_STORE), CMR_ERROR_PERMISSION_DENIED);
        EXPECT_EQ(CmHasGetCAPermission(CM_CREDENTIAL_STORE), CMR_ERROR_INVALID_ARGUMENT);
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_EQ(CmHasGetCAPermission(CM_SYSTEM_TRUSTED_STORE), CMR_ERROR_NOT_SYSTEMP_APP);
        EXPECT_EQ(CmHasGetCAPermission(CM_USER_TRUSTED_STORE), CM_SUCCESS);
    }
}

/**
 * @tc.name: CmIsSystemApp_001
 * @tc.desc: system app detection per token type and per store
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmIsSystemApp_001, TestSize.Level0)
{
    {
        MockHapToken fullPerm;
        EXPECT_TRUE(CmIsSystemApp());
    }

    {
        NonSystemHapToken nonSystem(FULL_PERMS);
        EXPECT_FALSE(CmIsSystemApp());
        /* the store keyed variant only consults the flag for the credential stores */
        EXPECT_FALSE(CmIsSystemAppByStoreType(CM_CREDENTIAL_STORE));
        EXPECT_FALSE(CmIsSystemAppByStoreType(CM_SYS_CREDENTIAL_STORE));
        EXPECT_TRUE(CmIsSystemAppByStoreType(CM_PRI_CREDENTIAL_STORE));
        EXPECT_TRUE(CmIsSystemAppByStoreType(CM_USER_TRUSTED_STORE));
    }

    {
        /* non hap tokens are always treated as system callers */
        MockNativeToken native("foundation");
        EXPECT_TRUE(CmIsSystemApp());
        EXPECT_TRUE(CmIsSystemAppByStoreType(CM_CREDENTIAL_STORE));
        EXPECT_TRUE(CmIsSystemAppByStoreType(CM_SYS_CREDENTIAL_STORE));
    }
}

/**
 * @tc.name: CmHasPermission_001
 * @tc.desc: individual permission predicates under the mocked tokens
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmHasPermission_001, TestSize.Level0)
{
    {
        MockHapToken fullPerm;
        EXPECT_TRUE(CmHasPrivilegedPermission());
        EXPECT_TRUE(CmHasCommonPermission());
        EXPECT_TRUE(CmHasUserTrustedPermission());
        EXPECT_TRUE(CmHasSystemAppPermission());
        EXPECT_FALSE(CmHasEnterpriseUserTrustedPermission()); /* not in the default list */
    }

    {
        MockHapToken noPerm;
        EXPECT_FALSE(CmHasPrivilegedPermission());
        EXPECT_FALSE(CmHasCommonPermission());
        EXPECT_FALSE(CmHasUserTrustedPermission());
        EXPECT_FALSE(CmHasSystemAppPermission());
        EXPECT_FALSE(CmHasEnterpriseUserTrustedPermission());
    }

    {
        MockHapToken enterprise({ "ohos.permission.ACCESS_ENTERPRISE_USER_TRUSTED_CERT" });
        EXPECT_TRUE(CmHasEnterpriseUserTrustedPermission());
        EXPECT_FALSE(CmHasUserTrustedPermission());
    }
}

/**
 * @tc.name: CmGetCertManagerAppUid_001
 * @tc.desc: bundle manager lookup of the cert manager uid keeps the output untouched on failure
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineCheckTest, CmGetCertManagerAppUid_001, TestSize.Level0)
{
    /* the result depends on the bundle manager availability on the device:
     * only the failure contract is asserted deterministically */
    int32_t uid = -1;
    bool ok = CmGetCertManagerAppUid(&uid, TEST_CHECK_USER);
    if (!ok) {
        EXPECT_EQ(uid, -1); /* not overwritten on failure */
    }
}
