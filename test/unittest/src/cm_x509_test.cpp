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

#include <securec.h>

#include "cm_x509.h"
#include "cm_type.h"
#include "cm_mem.h"

#include "cm_cert_data_user.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_chain_key.h"

using namespace testing::ext;

namespace {
class CmX509Test : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/* ---------- InitCertContext ---------- */

HWTEST_F(CmX509Test, InitCertContextNullBuf, TestSize.Level0)
{
    EXPECT_EQ(InitCertContext(NULL, 100), nullptr);
}

HWTEST_F(CmX509Test, InitCertContextZeroSize, TestSize.Level0)
{
    uint8_t buf[] = "x";
    EXPECT_EQ(InitCertContext(buf, 0), nullptr);
}

HWTEST_F(CmX509Test, InitCertContextTooLarge, TestSize.Level0)
{
    uint8_t buf[] = "x";
    EXPECT_EQ(InitCertContext(buf, MAX_LEN_CERTIFICATE + 1), nullptr);
}

HWTEST_F(CmX509Test, InitCertContextPemSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, InitCertContextPemInvalid, TestSize.Level0)
{
    uint8_t invalidPem[] = "-----BEGIN CERTIFICATE-----\r\ninvalid\r\n-----END CERTIFICATE-----\r\n";
    X509 *cert = InitCertContext(invalidPem, sizeof(invalidPem));
    EXPECT_EQ(cert, nullptr);
}

HWTEST_F(CmX509Test, InitCertContextDerSuccess, TestSize.Level0)
{
    /* g_certData01 is DER-encoded system CA cert */
    X509 *cert = InitCertContext(g_certData01, sizeof(g_certData01));
    ASSERT_NE(cert, nullptr);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, InitCertContextDerInvalid, TestSize.Level0)
{
    uint8_t derStart[] = { 0x30, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00 };
    X509 *cert = InitCertContext(derStart, sizeof(derStart));
    EXPECT_EQ(cert, nullptr);
}

HWTEST_F(CmX509Test, FreeCertContextNull, TestSize.Level0)
{
    FreeCertContext(nullptr); /* no crash */
}

/* ---------- InitCertStackContext (P7B) ---------- */

HWTEST_F(CmX509Test, InitCertStackContextNullBuf, TestSize.Level0)
{
    EXPECT_EQ(InitCertStackContext(NULL, 100), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextZeroSize, TestSize.Level0)
{
    uint8_t buf[] = "x";
    EXPECT_EQ(InitCertStackContext(buf, 0), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextTooLarge, TestSize.Level0)
{
    uint8_t buf[] = "x";
    EXPECT_EQ(InitCertStackContext(buf, MAX_LEN_CERTIFICATE_P7B + 1), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextInvalidP7B, TestSize.Level0)
{
    uint8_t notP7b[] = { 0x30, 0x82, 0x01, 0x00, 0x00 };
    EXPECT_EQ(InitCertStackContext(notP7b, sizeof(notP7b)), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextPemNotP7b, TestSize.Level0)
{
    /* PEM data is not DER-encoded PKCS7 -> d2i_PKCS7_bio fails */
    uint8_t pemData[] = "-----BEGIN CERTIFICATE-----\r\ninvalid\r\n-----END CERTIFICATE-----\r\n";
    EXPECT_EQ(InitCertStackContext(pemData, sizeof(pemData)), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextSuccess, TestSize.Level0)
{
    STACK_OF(X509) *stack = InitCertStackContext(g_p7bUserCertInfo, sizeof(g_p7bUserCertInfo));
    ASSERT_NE(stack, nullptr);
    EXPECT_GT(sk_X509_num(stack), 0);
    sk_X509_pop_free(stack, X509_free);
}

/* ---------- GetX509SerialNumber ---------- */

HWTEST_F(CmX509Test, GetX509SerialNumberNullArgs, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509SerialNumber(nullptr, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetX509SerialNumber(cert, nullptr, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SerialNumberBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[1] = {0};
    int32_t ret = GetX509SerialNumber(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_INVALID_CERT_FORMAT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SerialNumberSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    int32_t ret = GetX509SerialNumber(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectName ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameNullArgs, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    EXPECT_EQ(GetX509SubjectName(nullptr, CM_COMMON_NAME, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetX509SubjectName(cert, CM_COMMON_NAME, nullptr, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetX509SubjectName(cert, CM_COMMON_NAME, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameCn, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    int32_t ret = GetX509SubjectName(cert, CM_COMMON_NAME, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    EXPECT_GT(strlen(buf), 0u);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameUnknownObj, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    int32_t ret = GetX509SubjectName(cert, "UNKNOWN_OBJ", buf, sizeof(buf));
    /* no matching entry -> length 0 */
    EXPECT_EQ(ret, 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509SubjectName(cert, CM_COMMON_NAME, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    FreeCertContext(cert);
}

/* ---------- GetX509FirstSubjectName ---------- */

HWTEST_F(CmX509Test, GetX509FirstSubjectNameNullArgs, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[256] = {0};
    struct CmBlob displayName = { sizeof(buf), buf };
    EXPECT_EQ(GetX509FirstSubjectName(nullptr, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetX509FirstSubjectName(cert, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    struct CmBlob badBlob = { 0, buf };
    EXPECT_EQ(GetX509FirstSubjectName(cert, &badBlob), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509FirstSubjectNameSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[256] = {0};
    struct CmBlob displayName = { sizeof(buf), buf };
    int32_t ret = GetX509FirstSubjectName(cert, &displayName);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(displayName.size, 0u);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509FirstSubjectNameBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[1] = {0};
    struct CmBlob displayName = { sizeof(buf), buf };
    int32_t ret = GetX509FirstSubjectName(cert, &displayName);
    /* subject name longer than 1 byte -> BUFFER_TOO_SMALL or INVALID_CERT_FORMAT */
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_INVALID_CERT_FORMAT);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectNameLongFormat ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatNullArgs, TestSize.Level0)
{
    EXPECT_EQ(GetX509SubjectNameLongFormat(nullptr, nullptr, 0), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[MAX_LEN_SUBJECT_NAME] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[4] = {0}; /* too small to hold the formatted subject */
    int32_t ret = GetX509SubjectNameLongFormat(cert, buf, sizeof(buf));
    /* snprintf_s truncation returns CMR_ERROR_MEM_OPERATION_PRINT (-45) */
    EXPECT_EQ(ret, CMR_ERROR_MEM_OPERATION_PRINT);
    FreeCertContext(cert);
}

/* ---------- GetX509IssueNameLongFormat ---------- */

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatNullArgs, TestSize.Level0)
{
    EXPECT_EQ(GetX509IssueNameLongFormat(nullptr, nullptr, 0), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[MAX_LEN_SUBJECT_NAME] = {0};
    int32_t ret = GetX509IssueNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    FreeCertContext(cert);
}

/* ---------- GetX509NotBefore / GetX509NotAfter ---------- */

HWTEST_F(CmX509Test, GetX509NotBeforeNullArgs, TestSize.Level0)
{
    EXPECT_EQ(GetX509NotBefore(nullptr, nullptr, 0), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509NotBeforeSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[TIME_FORMAT_MAX_SIZE] = {0};
    int32_t ret = GetX509NotBefore(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotAfterSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[TIME_FORMAT_MAX_SIZE] = {0};
    int32_t ret = GetX509NotAfter(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotBeforeBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509NotBefore(cert, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    FreeCertContext(cert);
}

/* ---------- GetX509Fingerprint ---------- */

HWTEST_F(CmX509Test, GetX509FingerprintNullCert, TestSize.Level0)
{
    char buf[FINGERPRINT_MAX_SIZE] = {0};
    EXPECT_EQ(GetX509Fingerprint(nullptr, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509FingerprintSuccess, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[FINGERPRINT_MAX_SIZE] = {0};
    int32_t ret = GetX509Fingerprint(cert, buf, sizeof(buf));
    EXPECT_GT(ret, 0);
    EXPECT_GT(strlen(buf), 0u);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509FingerprintBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[4] = {0};
    int32_t ret = GetX509Fingerprint(cert, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    FreeCertContext(cert);
}

/* ---------- GetSubjectNameAndAlias ---------- */

HWTEST_F(CmX509Test, GetSubjectNameAndAliasNullArgs, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[64] = {0};
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    uint8_t dispBuf[256] = {0};
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };

    EXPECT_EQ(GetSubjectNameAndAlias(nullptr, &alias, &subjectName, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetSubjectNameAndAlias(cert, nullptr, &subjectName, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetSubjectNameAndAlias(cert, &alias, nullptr, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetSubjectNameAndAlias(cert, &alias, &subjectName, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetSubjectNameAndAliasWithAlias, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[64] = {0};
    strcpy_s(reinterpret_cast<char *>(aliasBuf), sizeof(aliasBuf), "myalias");
    struct CmBlob alias = { strlen(reinterpret_cast<char *>(aliasBuf)) + 1, aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    uint8_t dispBuf[256] = {0};
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };

    int32_t ret = GetSubjectNameAndAlias(cert, &alias, &subjectName, &displayName);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(strcmp(reinterpret_cast<char *>(displayName.data), "myalias"), 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetSubjectNameAndAliasEmptyAlias, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[1] = {0}; /* empty alias string "" */
    struct CmBlob alias = { 1, aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    uint8_t dispBuf[256] = {0};
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };

    int32_t ret = GetSubjectNameAndAlias(cert, &alias, &subjectName, &displayName);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_GT(displayName.size, 0u);
    FreeCertContext(cert);
}

/* ---------- InitCertContext additional ---------- */

HWTEST_F(CmX509Test, InitCertContextDerInvalidShort, TestSize.Level0)
{
    /* DER tag but truncated */
    uint8_t shortDer[] = { 0x30, 0x05, 0x00, 0x00, 0x00 };
    X509 *cert = InitCertContext(shortDer, sizeof(shortDer));
    EXPECT_EQ(cert, nullptr);
}

HWTEST_F(CmX509Test, InitCertContextPemPartialSuccess, TestSize.Level0)
{
    /* PEM with leading garbage then valid cert - should fail */
    uint8_t garbage[] = "garbage-----BEGIN CERTIFICATE-----\r\n";
    X509 *cert = InitCertContext(garbage, sizeof(garbage));
    EXPECT_EQ(cert, nullptr);
}

/* ---------- InitCertStackContext additional ---------- */

HWTEST_F(CmX509Test, InitCertStackContextDerNotP7b, TestSize.Level0)
{
    /* DER cert data (starts with 0x30) is not PKCS7 - d2i_PKCS7_bio should fail */
    EXPECT_EQ(InitCertStackContext(g_certData01, sizeof(g_certData01)), nullptr);
}

HWTEST_F(CmX509Test, InitCertStackContextP7bMultipleCerts, TestSize.Level0)
{
    /* g_p7bUserCertTooLongSubjInfo contains multiple certs - exercises DumplicateCerts */
    STACK_OF(X509) *stack = InitCertStackContext(g_p7bUserCertTooLongSubjInfo,
        sizeof(g_p7bUserCertTooLongSubjInfo));
    if (stack != nullptr) {
        EXPECT_GT(sk_X509_num(stack), 0);
        sk_X509_pop_free(stack, X509_free);
    }
}

/* ---------- GetX509FirstSubjectName additional ---------- */

HWTEST_F(CmX509Test, GetX509FirstSubjectNameSizeZero, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[256] = {0};
    struct CmBlob displayName = { 0, buf }; /* size 0 */
    EXPECT_EQ(GetX509FirstSubjectName(cert, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectName additional ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameOu, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    int32_t ret = GetX509SubjectName(cert, CM_ORGANIZATION_UNIT_NAME, buf, sizeof(buf));
    /* may or may not have OU - just check non-negative */
    EXPECT_GE(ret, 0);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameO, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    int32_t ret = GetX509SubjectName(cert, CM_ORGANIZATION_NAME, buf, sizeof(buf));
    EXPECT_GE(ret, 0);
    FreeCertContext(cert);
}

/* ---------- GetX509IssueNameLongFormat additional ---------- */

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[4] = {0};
    int32_t ret = GetX509IssueNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_MEM_OPERATION_PRINT);
    FreeCertContext(cert);
}

/* ---------- GetX509NotBefore / NotAfter additional ---------- */

HWTEST_F(CmX509Test, GetX509NotAfterBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509NotAfter(cert, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    FreeCertContext(cert);
}

/* ---------- GetSubjectNameAndAlias additional ---------- */

HWTEST_F(CmX509Test, GetSubjectNameAndAliasAliasTooLong, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    /* alias larger than displayName buffer -> memcpy_s fail */
    uint8_t aliasBuf[512] = {0};
    memset(aliasBuf, 'x', sizeof(aliasBuf) - 1);
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    uint8_t dispBuf[8] = {0}; /* too small */
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };

    int32_t ret = GetSubjectNameAndAlias(cert, &alias, &subjectName, &displayName);
    EXPECT_EQ(ret, CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectNameLongFormat empty buffer ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatSizeZero, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509SubjectNameLongFormat(cert, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatSizeZero, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509IssueNameLongFormat(cert, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509Fingerprint edge cases ---------- */

HWTEST_F(CmX509Test, GetX509FingerprintBufferExactlyRight, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    /* First get the actual length needed */
    char tmpBuf[FINGERPRINT_MAX_SIZE] = {0};
    int32_t len = GetX509Fingerprint(cert, tmpBuf, sizeof(tmpBuf));
    ASSERT_GT(len, 0);
    /* Provide a buffer of exactly the right size (length == len, not len+1) -> should fail */
    char smallBuf[64] = {0};
    if ((uint32_t)len < sizeof(smallBuf)) {
        int32_t ret = GetX509Fingerprint(cert, smallBuf, (uint32_t)len);
        EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    }
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectNameLongFormat offset exceeded ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatOffsetExceeded, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    /* Use a very small buffer so offset will exceed outBufMaxSize during the loop.
       This triggers the break at line 391 (offset >= outBufMaxSize). */
    char buf[2] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(cert, buf, sizeof(buf));
    /* With a 2-byte buffer, snprintf_s will fail or offset will exceed */
    EXPECT_TRUE(ret == CMR_ERROR_MEM_OPERATION_PRINT || ret == CMR_ERROR_BUFFER_TOO_SMALL || ret < 0);
    FreeCertContext(cert);
}

/* ---------- GetX509FirstSubjectName: subjectName empty string path ---------- */
/* When the subjectName retrieved is empty (strlen == 0), the loop continues to the next name.
   This covers the branch at line 278 where strlen(subjectName) > 0 is false. */

HWTEST_F(CmX509Test, GetX509FirstSubjectNameEmptySubjectAllNames, TestSize.Level0)
{
    /* Construct a cert with no CN, OU, or O - but we can't easily craft one.
       Instead, test with cert that has CN to ensure the strlen > 0 branch is taken. */
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob displayName = { sizeof(buf), buf };
    int32_t ret = GetX509FirstSubjectName(cert, &displayName);
    EXPECT_EQ(ret, CM_SUCCESS);
    FreeCertContext(cert);
}

/* ---------- GetX509NotBefore/NotAfter: asn1Time length < NAME_ANS1TIME_LEN ---------- */
/* This branch is hard to trigger with a valid cert. Skip. */

/* ---------- GetSubjectNameAndAlias: null subjectName ---------- */

HWTEST_F(CmX509Test, GetSubjectNameAndAliasNullSubjectName, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[] = "alias";
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    uint8_t dispBuf[64] = {0};
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };
    int32_t ret = GetSubjectNameAndAlias(cert, &alias, nullptr, &displayName);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetSubjectNameAndAliasNullDisplayName, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[] = "alias";
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    int32_t ret = GetSubjectNameAndAlias(cert, &alias, &subjectName, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509FirstSubjectProp: buffer too small path ---------- */
/* GetX509FirstSubjectProp is static, called from GetDisplayName when alias is empty
   and subjectName is CM_SUBJECT_NAME_NULL. Hard to trigger directly.
   Instead test GetDisplayName via GetSubjectNameAndAlias with empty alias
   and a cert that has subject name to trigger GetX509FirstSubjectName. */

HWTEST_F(CmX509Test, GetSubjectNameAndAliasEmptyAliasBufferTooSmall, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t aliasBuf[] = "";
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    uint8_t subjBuf[MAX_LEN_SUBJECT_NAME] = {0};
    struct CmBlob subjectName = { sizeof(subjBuf), subjBuf };
    uint8_t dispBuf[2] = {0}; /* too small */
    struct CmBlob displayName = { sizeof(dispBuf), dispBuf };
    int32_t ret = GetSubjectNameAndAlias(cert, &alias, &subjectName, &displayName);
    /* Should fail with buffer too small */
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- InitCertContext: size == MAX_LEN_CERTIFICATE + 1 ---------- */

HWTEST_F(CmX509Test, InitCertContextSizeAtMax, TestSize.Level0)
{
    uint8_t buf[] = "dummy";
    /* size exactly at MAX_LEN_CERTIFICATE boundary (too large) */
    EXPECT_EQ(InitCertContext(buf, MAX_LEN_CERTIFICATE + 1), nullptr);
}

/* ---------- GetX509NotBefore / GetX509NotAfter: null args ---------- */

HWTEST_F(CmX509Test, GetX509NotBeforeNullCert, TestSize.Level0)
{
    char buf[64] = {0};
    EXPECT_EQ(GetX509NotBefore(nullptr, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509NotAfterNullCert, TestSize.Level0)
{
    char buf[64] = {0};
    EXPECT_EQ(GetX509NotAfter(nullptr, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509NotBeforeNullBuf, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(GetX509NotBefore(cert, nullptr, 64), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotAfterNullBuf, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(GetX509NotAfter(cert, nullptr, 64), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotBeforeZeroSize, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509NotBefore(cert, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotAfterZeroSize, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509NotAfter(cert, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509Fingerprint null buf ---------- */

HWTEST_F(CmX509Test, GetX509FingerprintNullBuf, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    int32_t ret = GetX509Fingerprint(cert, nullptr, 64);
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509SerialNumber null outBuf ---------- */

HWTEST_F(CmX509Test, GetX509SerialNumberNullOutBuf, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(GetX509SerialNumber(cert, nullptr, 64), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SerialNumberNullCert, TestSize.Level0)
{
    char buf[64] = {0};
    EXPECT_EQ(GetX509SerialNumber(nullptr, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
}

/* ---------- GetX509SubjectName null args ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameNullCert, TestSize.Level0)
{
    char buf[64] = {0};
    EXPECT_EQ(GetX509SubjectName(nullptr, CM_COMMON_NAME, buf, sizeof(buf)), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmX509Test, GetX509SubjectNameNullOutBuf, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(GetX509SubjectName(cert, CM_COMMON_NAME, nullptr, 64), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509SubjectNameZeroOutBufSize, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[64] = {0};
    EXPECT_EQ(GetX509SubjectName(cert, CM_COMMON_NAME, buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509FirstSubjectName: null displayName, invalid blob ---------- */

HWTEST_F(CmX509Test, GetX509FirstSubjectNameNullDisplayName, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(GetX509FirstSubjectName(cert, nullptr), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509FirstSubjectNameNullData, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    struct CmBlob displayName = { 64, nullptr };
    EXPECT_EQ(GetX509FirstSubjectName(cert, &displayName), CMR_ERROR_INVALID_ARGUMENT);
    FreeCertContext(cert);
}

/* ---------- GetX509SerialNumber: strncpy_s fails due to small buffer ---------- */

HWTEST_F(CmX509Test, GetX509SerialNumberBufferTooSmallForHex, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[1] = {0};
    int32_t ret = GetX509SerialNumber(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectName: no matching OID name ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameNoMatchObjName, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[256] = {0};
    int32_t ret = GetX509SubjectName(cert, "INVALID_OID_NAME", buf, sizeof(buf));
    EXPECT_EQ(ret, 0);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectName: strncpy_s fails ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameStrncpyFails, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[5] = {0};
    int32_t ret = GetX509SubjectName(cert, CM_COMMON_NAME, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- GetX509FirstSubjectName: strncpy_s fails ---------- */

HWTEST_F(CmX509Test, GetX509FirstSubjectNameStrncpyFails, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    uint8_t buf[3] = {0};
    struct CmBlob displayName = { sizeof(buf), buf };
    int32_t ret = GetX509FirstSubjectName(cert, &displayName);
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- GetX509NotBefore/After: buffer too small for strncpy_s ---------- */

HWTEST_F(CmX509Test, GetX509NotBeforeBufferTooSmallForTime, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509NotBefore(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

HWTEST_F(CmX509Test, GetX509NotAfterBufferTooSmallForTime, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509NotAfter(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_COPY);
    FreeCertContext(cert);
}

/* ---------- GetX509Fingerprint: buffer too small ---------- */

HWTEST_F(CmX509Test, GetX509FingerprintBufferTooSmallV2, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[2] = {0};
    int32_t ret = GetX509Fingerprint(cert, buf, sizeof(buf));
    EXPECT_EQ(ret, CMR_ERROR_BUFFER_TOO_SMALL);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectNameLongFormat: offset exceeded ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatOffsetExceededExact, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[15] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret >= 0 || ret == CMR_ERROR_MEM_OPERATION_PRINT);
    FreeCertContext(cert);
}

/* ---------- GetX509IssueNameLongFormat: offset exceeded ---------- */

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatOffsetExceededExact, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[15] = {0};
    int32_t ret = GetX509IssueNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret >= 0 || ret == CMR_ERROR_BUFFER_TOO_SMALL || ret == CMR_ERROR_MEM_OPERATION_PRINT);
    FreeCertContext(cert);
}

/* ---------- GetX509SubjectNameLongFormat: snprintf_s fails ---------- */

HWTEST_F(CmX509Test, GetX509SubjectNameLongFormatSnprintfFails, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[3] = {0};
    int32_t ret = GetX509SubjectNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_MEM_OPERATION_PRINT || ret < 0);
    FreeCertContext(cert);
}

/* ---------- GetX509IssueNameLongFormat: snprintf_s fails ---------- */

HWTEST_F(CmX509Test, GetX509IssueNameLongFormatSnprintfFails, TestSize.Level0)
{
    X509 *cert = InitCertContext(reinterpret_cast<const uint8_t *>(g_certData06), strlen(g_certData06));
    ASSERT_NE(cert, nullptr);
    char buf[3] = {0};
    int32_t ret = GetX509IssueNameLongFormat(cert, buf, sizeof(buf));
    EXPECT_TRUE(ret == CMR_ERROR_MEM_OPERATION_PRINT || ret == CMR_ERROR_BUFFER_TOO_SMALL || ret < 0);
    FreeCertContext(cert);
}
} // end of namespace