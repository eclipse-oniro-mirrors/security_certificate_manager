/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <openssl/x509.h>

#include "cm_test_common.h"
#include "cm_pfx.h"
#include "cm_cert_data_chain_key.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_advsecmode_check.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken* g_MockHap = nullptr;

static const struct CmBlob g_appDerCertChain = { sizeof(g_rsa2048DERCertChain),
    const_cast<uint8_t *>(g_rsa2048DERCertChain) };
static const struct CmBlob g_appDerCertPrivKey = { sizeof(g_rsa2048DERPrivKey),
    const_cast<uint8_t *>(g_rsa2048DERPrivKey) };

class CmPfxTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmPfxTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmPfxTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmPfxTest::SetUp()
{
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmPfxTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

/**
* @tc.name: CmPfxTest001
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest001, TestSize.Level0)
{
    uint8_t p12CertBuf[] = "p12CertBuf";
    struct CmBlob p12Cert = { sizeof(p12CertBuf), p12CertBuf };
    char passWd[] = "passWd";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert *appCert = nullptr;
    int32_t ret = CmParsePkcs12Cert(&p12Cert, passWd, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT);
}

/**
* @tc.name: CmPfxTest002
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest002, TestSize.Level0)
{
    struct CmBlob *certChain = nullptr;
    struct CmBlob *privKey = nullptr;;
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert *appCert = nullptr;
    int32_t ret = CmParseCertChainAndPrivKey(certChain, privKey, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
}

/**
* @tc.name: CmPfxTest003
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest003, TestSize.Level0)
{
    uint8_t certChainBuf[] = "certChainBuf";
    struct CmBlob certChain = { sizeof(certChainBuf), certChainBuf };
    struct CmBlob *privKey = nullptr;;
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert *appCert = nullptr;
    int32_t ret = CmParseCertChainAndPrivKey(&certChain, privKey, &pkey, appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
}

/**
* @tc.name: CmPfxTest004
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest004, TestSize.Level0)
{
    bool *isAdvSecMode = nullptr;
    int32_t ret = CheckAdvSecMode(isAdvSecMode);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}

/**
* @tc.name: CmPfxTest005
* @tc.desc: Test CmIsAuthorizedApp handle is null
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest005, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParseCertChainAndPrivKey(&g_appDerCertChain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest006
* @tc.desc: Test CmParsePkcs12Cert with invalid p12 cert (not PKCS12 format)
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest006, TestSize.Level0)
{
    uint8_t notP12Buf[] = "this is not a p12";
    struct CmBlob notP12 = { sizeof(notP12Buf), notP12Buf };
    char passWd[] = "123456";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(&notP12, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_CERT_FORMAT);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest007
* @tc.desc: Test CmParsePkcs12Cert with invalid argument (size > MAX_LEN_CERTIFICATE_CHAIN)
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest007, TestSize.Level0)
{
    uint8_t buf[16] = {0};
    struct CmBlob tooLargeBlob = { MAX_LEN_CERTIFICATE_CHAIN + 1, buf };
    char passWd[] = "123456";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(&tooLargeBlob, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
}

/**
* @tc.name: CmPfxTest008
* @tc.desc: Test CmParsePkcs12Cert with wrong password
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest008, TestSize.Level0)
{
    struct CmBlob p12Cert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    char passWd[] = "wrongpassword";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(&p12Cert, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_PASSWORD_IS_ERR);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest009
* @tc.desc: Test CmParsePkcs12Cert success path with valid P12 cert and password
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest009, TestSize.Level0)
{
    struct CmBlob p12Cert = { sizeof(g_rsa2048P12CertInfo),
        const_cast<uint8_t *>(g_rsa2048P12CertInfo) };
    char passWd[] = "123456";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(&p12Cert, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_NE(pkey, nullptr);
    EXPECT_NE(x509Cert, nullptr);
    EXPECT_GT(appCert.certCount, 0u);
    EXPECT_GT(appCert.certSize, 0u);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest010
* @tc.desc: Test CmParseCertChainAndPrivKey with PEM cert chain and PEM priv key
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest010, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CmBlob pemChain = { strlen(g_rsa2048PEMCertChain) + 1,
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_rsa2048PEMCertChain)) };
    struct CmBlob pemKey = { strlen(g_rsa2048PEMPrivKey) + 1,
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_rsa2048PEMPrivKey)) };
    int32_t ret = CmParseCertChainAndPrivKey(&pemChain, &pemKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CM_SUCCESS);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest012
* @tc.desc: Test CmParseCertChainAndPrivKey with invalid PEM cert chain
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest012, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    uint8_t invalidChain[] = "invalid cert chain data";
    struct CmBlob chain = { sizeof(invalidChain), invalidChain };
    int32_t ret = CmParseCertChainAndPrivKey(&chain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest014
* @tc.desc: Test CmParsePkcs12Cert with NULL data pointer
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest014, TestSize.Level0)
{
    struct CmBlob nullData = { 100, nullptr };
    char passWd[] = "123456";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(&nullData, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
}

/**
* @tc.name: CmPfxTest015
* @tc.desc: Test CmParseCertChainAndPrivKey with mismatched priv key
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest015, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    /* PEM cert chain + a mismatched PEM key from a different keypair would fail the
       pubkey comparison; here we use a syntactically invalid PEM key buffer */
    uint8_t fakeKey[] = "-----BEGIN PRIVATE KEY-----\r\ninvalid\r\n-----END PRIVATE KEY-----\r\n";
    struct CmBlob fakeKeyBlob = { sizeof(fakeKey), fakeKey };
    int32_t ret = CmParseCertChainAndPrivKey(&g_appDerCertChain, &fakeKeyBlob, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest016
* @tc.desc: Test CmParseCertChainAndPrivKey with PEM cert chain and DER priv key (mismatched keypair)
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest016, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;D8
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CmBlob pemChain = { strlen(g_rsa2048PEMCertChain) + 1,
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_rsa2048PEMCertChain)) };
    int32_t ret = CmParseCertChainAndPrivKey(&pemChain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_NE(ret, CM_SUCCESS);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest017
* @tc.desc: Test CmParseCertChainAndPrivKey with DER cert chain and PEM priv key (mismatched keypair)
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest017, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CmBlob pemKey = { strlen(g_rsa2048PEMPrivKey) + 1,
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_rsa2048PEMPrivKey)) };
    int32_t ret = CmParseCertChainAndPrivKey(&g_appDerCertChain, &pemKey, &pkey, &appCert, &x509Cert);
    EXPECT_NE(ret, CM_SUCCESS);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest018
* @tc.desc: Test CmParseCertChainAndPrivKey with invalid PEM priv key (not matching)
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest018, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CmBlob pemChain = { strlen(g_rsa2048PEMCertChain) + 1,
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_rsa2048PEMCertChain)) };
    uint8_t fakeKey[] = "-----BEGIN PRIVATE KEY-----\r\ninvalid\r\n-----END PRIVATE KEY-----\r\n";
    struct CmBlob fakeKeyBlob = { sizeof(fakeKey), fakeKey };
    int32_t ret = CmParseCertChainAndPrivKey(&pemChain, &fakeKeyBlob, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest019
* @tc.desc: Test CmParseCertChainAndPrivKey with certChain->data NULL
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest019, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CmBlob nullDataChain = { 100, nullptr };
    int32_t ret = CmParseCertChainAndPrivKey(&nullDataChain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest020
* @tc.desc: Test CmParseCertChainAndPrivKey with certChain size > MAX_LEN_CERTIFICATE_CHAIN
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest020, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    uint8_t buf[16] = {0};
    struct CmBlob tooLargeChain = { MAX_LEN_CERTIFICATE_CHAIN + 1, buf };
    int32_t ret = CmParseCertChainAndPrivKey(&tooLargeChain, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest021
* @tc.desc: Test CmParsePkcs12Cert with p12Cert NULL
* @tc.type: CmParsePkcs12Cert
*/
HWTEST_F(CmPfxTest, CmPfxTest021, TestSize.Level0)
{
    char passWd[] = "123456";
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    int32_t ret = CmParsePkcs12Cert(nullptr, passWd, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT_APP_CERT);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest022
* @tc.desc: Test CmParseCertChainAndPrivKey with invalid DER priv key (parse fail)
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest022, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    /* DER-format key buffer that is invalid */
    uint8_t invalidDerKey[] = { 0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    struct CmBlob invalidDerKeyBlob = { sizeof(invalidDerKey), invalidDerKey };
    int32_t ret = CmParseCertChainAndPrivKey(&g_appDerCertChain, &invalidDerKeyBlob, &pkey, &appCert, &x509Cert);
    EXPECT_EQ(ret, CMR_ERROR_OPENSSL_FAIL);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}

/**
* @tc.name: CmPfxTest023
* @tc.desc: Test CmParseCertChainAndPrivKey with PEM chain that has no certs
* @tc.type: CmParseCertChainAndPrivKey
*/
HWTEST_F(CmPfxTest, CmPfxTest023, TestSize.Level0)
{
    EVP_PKEY *pkey = nullptr;
    X509 *x509Cert = nullptr;
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    /* PEM data with no certificates */
    uint8_t emptyPem[] = "-----BEGIN CERTIFICATE-----\r\n-----END CERTIFICATE-----\r\n";
    struct CmBlob emptyPemBlob = { sizeof(emptyPem), emptyPem };
    int32_t ret = CmParseCertChainAndPrivKey(&emptyPemBlob, &g_appDerCertPrivKey, &pkey, &appCert, &x509Cert);
    EXPECT_TRUE(ret == CMR_ERROR_OPENSSL_FAIL || ret == CMR_ERROR_INVALID_CERT_FORMAT);
    if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }
    if (x509Cert != nullptr) {
        X509_free(x509Cert);
    }
}
} // end of namespace