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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "securec.h"

#include "cm_cert_data_part1_rsa.h"
#include "cm_module_cert_data.h"
#include "cm_pfx.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_ed25519.h"
#include "cm_util.h"

using namespace testing::ext;
namespace {
static constexpr uint32_t STR_MAX_LEN = 10;

static constexpr uint32_t DEFAULT_SIZE = 1024;

class CmCertParseTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmCertParseTest::SetUpTestCase(void)
{
}

void CmCertParseTest::TearDownTestCase(void)
{
}

void CmCertParseTest::SetUp()
{
}

void CmCertParseTest::TearDown()
{
}

/**
* @tc.name: CmCertParseTest001
* @tc.desc: test InitCertContext certBuf nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest001, TestSize.Level0)
{
    X509 *x509 = InitCertContext(nullptr, 0);
    EXPECT_EQ(x509, nullptr);
    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest002
* @tc.desc: test InitCertContext size invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest002, TestSize.Level0)
{
    uint8_t certBuf[] = "this is test for certBuf";
    X509 *x509 = InitCertContext(certBuf, MAX_LEN_CERTIFICATE + 1);
    EXPECT_EQ(x509, nullptr);
    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest003
* @tc.desc: test InitCertContext cert buffer pem format invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest003, TestSize.Level0)
{
    uint8_t certBuf[] = "this is test for certBuf";
    certBuf[0] = '-';
    X509 *x509 = InitCertContext(certBuf, sizeof(certBuf));
    EXPECT_EQ(x509, nullptr);
    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest004
* @tc.desc: test InitCertContext cert buffer der format invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest004, TestSize.Level0)
{
    uint8_t certBuf[] = "this is test for certBuf";
    certBuf[0] = ASN1_TAG_TYPE_SEQ;
    X509 *x509 = InitCertContext(certBuf, sizeof(certBuf));
    EXPECT_EQ(x509, nullptr);
    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest005
* @tc.desc: test InitCertContext cert buffer not pem or der format
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest005, TestSize.Level0)
{
    uint8_t certBuf[] = "this is test for certBuf";
    X509 *x509 = InitCertContext(certBuf, sizeof(certBuf));
    EXPECT_EQ(x509, nullptr);
    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest006
* @tc.desc: test GetX509SerialNumber x509 is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest006, TestSize.Level0)
{
    char tmpSerialNumber[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SerialNumber(nullptr, tmpSerialNumber, sizeof(tmpSerialNumber));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCertParseTest007
* @tc.desc: test GetX509SerialNumber outBuf is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest007, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpSerialNumber[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SerialNumber(x509, nullptr, sizeof(tmpSerialNumber));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest008
* @tc.desc: test GetX509SerialNumber outBufMaxSize is 0
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest008, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpSerialNumber[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SerialNumber(x509, tmpSerialNumber, 0);
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest009
* @tc.desc: test GetX509SubjectNameLongFormat outBufMaxSize is 0
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest009, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpSubjectName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(x509, tmpSubjectName, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest010
* @tc.desc: test GetX509SubjectNameLongFormat outBuf is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest010, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpSubjectName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(x509, nullptr, sizeof(tmpSubjectName));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest011
* @tc.desc: test GetX509SubjectNameLongFormat x509 is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest011, TestSize.Level0)
{
    char tmpSubjectName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(nullptr, tmpSubjectName, sizeof(tmpSubjectName));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCertParseTest012
* @tc.desc: test GetX509IssueNameLongFormat outBufMaxSize is 0
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest012, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpIssueName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509IssueNameLongFormat(x509, tmpIssueName, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest013
* @tc.desc: test GetX509IssueNameLongFormat outBuf is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest013, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpIssueName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509IssueNameLongFormat(x509, nullptr, sizeof(tmpIssueName));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest014
* @tc.desc: test GetX509IssueNameLongFormat x509 is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest014, TestSize.Level0)
{
    char tmpIssueName[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509IssueNameLongFormat(nullptr, tmpIssueName, sizeof(tmpIssueName));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCertParseTest015
* @tc.desc: test GetX509NotBefore x509 is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest015, TestSize.Level0)
{
    char tmpTimeOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509NotBefore(nullptr, tmpTimeOut, sizeof(tmpTimeOut));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCertParseTest016
* @tc.desc: test GetX509NotBefore size is 0
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest016, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpTimeOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509NotBefore(x509, tmpTimeOut, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest017
* @tc.desc: test GetX509NotBefore outBuf is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest017, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpTimeOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509NotBefore(x509, nullptr, sizeof(tmpTimeOut));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest018
* @tc.desc: test GetX509NotBefore size too small
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest018, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpTimeOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509NotBefore(x509, tmpTimeOut, 1); /* buffer not enough */
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest019
* @tc.desc: test GetX509NotBefore x509 is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest019, TestSize.Level0)
{
    X509 *tempX509 = X509_new();
    ASSERT_TRUE(tempX509 != nullptr);

    char tmpTimeOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509NotBefore(tempX509, tmpTimeOut, sizeof(tmpTimeOut));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT);

    X509_free(tempX509);
}

/**
* @tc.name: CmCertParseTest020
* @tc.desc: test GetX509Fingerprint x509 is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest020, TestSize.Level0)
{
    char tmpFinggerOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509Fingerprint(nullptr, tmpFinggerOut, sizeof(tmpFinggerOut));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmCertParseTest021
* @tc.desc: test GetX509Fingerprint size too small
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest021, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpFinggerOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509Fingerprint(x509, tmpFinggerOut, 1); /* buffer not enough */
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest022
* @tc.desc: test GetX509Fingerprint outBuf is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest022, TestSize.Level0)
{
    X509 *x509 = InitCertContext(g_certData, sizeof(g_certData));
    EXPECT_NE(x509, nullptr);

    char tmpFinggerOut[DEFAULT_SIZE] = {0};
    int32_t ret = GetX509Fingerprint(x509, nullptr, sizeof(tmpFinggerOut));
    EXPECT_EQ(ret, CMR_ERROR_MEM_OPERATION_PRINT);

    FreeCertContext(x509);
}

/**
* @tc.name: CmCertParseTest023
* @tc.desc: test CmParsePkcs12Cert normal testcase
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest023, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;
    struct CmBlob certInfo = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&certInfo, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
        &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CM_SUCCESS);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest024
* @tc.desc: test CmParsePkcs12Cert p12Cert is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest024, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(nullptr, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
        &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest025
* @tc.desc: test CmParsePkcs12Cert p12Cert data is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest025, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;
    struct CmBlob certInfo = { sizeof(g_rsa2048P12CertInfo), nullptr };

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&certInfo, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
        &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest026
* @tc.desc: test CmParsePkcs12Cert p12Cert size too big
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest026, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;
    struct CmBlob certInfo = { MAX_LEN_CERTIFICATE_CHAIN + 1, const_cast<uint8_t *>(g_rsa2048P12CertInfo) };

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&certInfo, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
        &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest027
* @tc.desc: test CmParsePkcs12Cert p12Cert invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest027, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;
    uint8_t tempBuf[] = "this is for test error";
    struct CmBlob certInfo = { sizeof(tempBuf), tempBuf };

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&certInfo, reinterpret_cast<char *>(const_cast<uint8_t *>(g_certPwd)),
        &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest028
* @tc.desc: test CmParsePkcs12Cert pwd invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest028, TestSize.Level0)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *pkey = nullptr;
    struct CmBlob certInfo = { sizeof(g_rsa2048P12CertInfo), const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    char tempPwd[] = "this is for test error123";

    X509 *cert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&certInfo, tempPwd, &pkey, &appCert, &cert);
    if (cert != nullptr) {
        FreeCertContext(cert);
    }
    EXPECT_EQ(ret, CMR_ERROR_PASSWORD_IS_ERR);

    EVP_PKEY_free(pkey);
}

/**
* @tc.name: CmCertParseTest029
* @tc.desc: test init P7B format cert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest029, TestSize.Level0)
{
    STACK_OF(X509) *certStack = InitCertStackContext(g_p7bUserCert.data, g_p7bUserCert.size);
    EXPECT_NE(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
}

/**
* @tc.name: CmCertParseTest030
* @tc.desc: test init P7B format cert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest030, TestSize.Level0)
{
    STACK_OF(X509) *certStack = InitCertStackContext(g_p7bUserCertTooLongSubj.data, g_p7bUserCertTooLongSubj.size);
    EXPECT_NE(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
}

/**
* @tc.name: CmCertParseTest031
* @tc.desc: test init P7B format cert
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest031, TestSize.Level0)
{
    STACK_OF(X509) *certStack = InitCertStackContext(nullptr, 0);
    EXPECT_EQ(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
    certStack = InitCertStackContext(g_p7bUserCertTooLongSubj.data, 0);
    EXPECT_EQ(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
    certStack = InitCertStackContext(g_p7bUserCertTooLongSubj.data, MAX_LEN_CERTIFICATE_P7B + 1);
    EXPECT_EQ(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
    certStack = InitCertStackContext(g_ed25519P12CertInfo, sizeof(g_ed25519P12CertInfo));
    EXPECT_EQ(certStack, nullptr);
    sk_X509_pop_free(certStack, X509_free);
}

/**
* @tc.name: CmCertParseTest032
* @tc.desc: test CmIsNumeric
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmCertParseTest, CmCertParseTest032, TestSize.Level0)
{
    char str[] = "123";
    int32_t ret = CmIsNumeric(nullptr, 0, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    ret = CmIsNumeric(str, 0, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    ret = CmIsNumeric(str, STR_MAX_LEN + 1, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    ret = CmIsNumeric(str, sizeof(str), nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    uint32_t value = 0;
    ret = CmIsNumeric(str, sizeof(str), &value);
    EXPECT_EQ(ret, CM_SUCCESS);
    ret = CmIsNumeric(str, sizeof(str) - 1, &value);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    char errorStr[] = "123ab123";
    ret = CmIsNumeric(errorStr, sizeof(errorStr), &value);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}
} // end of namespace
