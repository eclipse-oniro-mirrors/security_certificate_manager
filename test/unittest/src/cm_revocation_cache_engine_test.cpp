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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <limits.h>
#include <unistd.h>

#include "cert_manager_api.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_revocation_cache.h"
#include "cert_manager_storage.h"
#include "cm_mem.h"
#include "cm_revocation_cache.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr int64_t ALREADY_EXPIRED_SEC = 10; /* expire offset already in the past */
MockNativeToken *g_mockNative = nullptr;

/* remove all revocation cache records, files and meta left by this or previous test runs */
void CleanupRevocationCacheState()
{
    char **paths = nullptr;
    uint32_t count = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &count) == CM_SUCCESS) {
        for (uint32_t i = 0; i < count; i++) {
            char full[PATH_MAX] = { 0 };
            if (snprintf_s(full, sizeof(full), sizeof(full) - 1, "%s%s", REVOCATION_CACHE_DIR,
                paths[i]) >= 0) {
                (void)unlink(full);
            }
            (void)DeleteRevocationCacheRecord(paths[i]);
        }
        FreeRevocationCacheFilePaths(paths, count);
    }
    (void)DeleteRevocationCacheMeta();
}

/* write raw bytes to a file so tests can craft cache files with edge-case contents */
static int WriteTestFile(const char *fullPath, const uint8_t *buf, uint32_t len)
{
    FILE *fp = fopen(fullPath, "wb");
    if (fp == nullptr) {
        return -1;
    }
    size_t written = fwrite(buf, 1, len, fp);
    (void)fclose(fp);
    return (written == len) ? 0 : -1;
}

/* build the absolute cache file path of key so tests can craft raw cache files */
static int BuildCacheFullPath(const struct CmBlob *key, uint32_t type, char *fullPath, uint32_t len)
{
    char relPath[512] = { 0 };
    if (CmRevocationCacheBuildRelPath(type, key, relPath, sizeof(relPath)) != CM_SUCCESS) {
        return -1;
    }
    return (snprintf_s(fullPath, len, len - 1, "%s%s", REVOCATION_CACHE_DIR, relPath) >= 0) ? 0 : -1;
}

class CmRevocationCacheEngineTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CmRevocationCacheEngineTest::SetUpTestCase()
{
    /* record the shell token so MockNativeToken can query atm with shell identity */
    CmTestCommon::SetTestEnvironment(GetSelfTokenID());
    ASSERT_EQ(CreateRevocationCacheRdb(), CM_SUCCESS);
}

void CmRevocationCacheEngineTest::TearDownTestCase()
{
    CmTestCommon::ResetTestEnvironment();
}

/* CmGetRevocationCache only serves HAP/native callers; mock self as a native process */
void CmRevocationCacheEngineTest::SetUp()
{
    CleanupRevocationCacheState(); /* clear leftovers from previous runs/cases */
    g_mockNative = new (std::nothrow) MockNativeToken("foundation");
}

void CmRevocationCacheEngineTest::TearDown()
{
    CleanupRevocationCacheState(); /* remove records/files/meta created by this case */
    if (g_mockNative != nullptr) {
        delete g_mockNative;
        g_mockNative = nullptr;
    }
}
} // namespace

TEST_F(CmRevocationCacheEngineTest, SaveThenGetRoundTrip)
{
    uint8_t keyBuf[] = "key1";
    uint8_t dataBuf[] = "DER";
    struct CmBlob key = { 4, keyBuf };
    struct CmBlob data = { 3, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectDer[] = "DER";
    ASSERT_EQ(out.size, sizeof(expectDer) - 1);
    EXPECT_EQ(memcmp(out.data, expectDer, sizeof(expectDer) - 1), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, GetMissingKeyReturnsNotExist)
{
    uint8_t keyBuf[] = "nokey00";
    struct CmBlob key = { 7, keyBuf };
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_CRL, &out), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(out.data, nullptr); /* out params must stay clean on failure */
    EXPECT_EQ(out.size, 0u);
    /* the ocsp store behaves the same for an absent key */
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(out.data, nullptr);
    EXPECT_EQ(out.size, 0u);
}

TEST_F(CmRevocationCacheEngineTest, RejectExpiredExpireTime)
{
    uint8_t keyBuf[] = "k";
    uint8_t dataBuf[] = "d";
    struct CmBlob key = { 1, keyBuf };
    struct CmBlob data = { 1, dataBuf };
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_CRL, &data,
        static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheEngineTest, ClampBeyondMaxValid)
{
    uint8_t keyBuf[] = "k2";
    uint8_t dataBuf[] = "d2";
    struct CmBlob key = { 2, keyBuf };
    struct CmBlob data = { 2, dataBuf };
    int64_t far = static_cast<int64_t>(time(nullptr)) + 100LL * 24 * 3600; /* > 30d → clamp, not error */
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, far), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, ResaveSameKeyLastWriteWins)
{
    uint8_t keyBuf[] = "k3";
    uint8_t d1Buf[] = "AAA";
    uint8_t d2Buf[] = "BBB";
    struct CmBlob key = { 2, keyBuf };
    struct CmBlob d1 = { 3, d1Buf };
    struct CmBlob d2 = { 3, d2Buf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d1, expire), CM_SUCCESS);
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &d2, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectData[] = "BBB";
    ASSERT_EQ(out.size, sizeof(expectData) - 1);
    EXPECT_EQ(memcmp(out.data, expectData, sizeof(expectData) - 1), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, SaveRejectsNullArgs)
{
    uint8_t keyBuf[] = "k";
    uint8_t dataBuf[] = "d";
    struct CmBlob key = { 1, keyBuf };
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmServiceSaveRevocationCache(nullptr, CM_REVOCATION_TYPE_OCSP, &data, expire),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, nullptr, expire),
        CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmRevocationCacheEngineTest, SaveRejectsOversizedKey)
{
    uint8_t keyBuf[CM_REVOCATION_CACHE_KEY_MAX_LEN + 1] = { 0 };
    (void)memset_s(keyBuf, sizeof(keyBuf), 'k', sizeof(keyBuf));
    struct CmBlob key = { sizeof(keyBuf), keyBuf };
    uint8_t dataBuf[] = "d";
    struct CmBlob data = { 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire),
        CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY);
}

TEST_F(CmRevocationCacheEngineTest, KeyMaxLenRoundTrip)
{
    uint8_t keyBuf[CM_REVOCATION_CACHE_KEY_MAX_LEN] = { 0 };
    (void)memset_s(keyBuf, sizeof(keyBuf), 'm', sizeof(keyBuf));
    struct CmBlob key = { sizeof(keyBuf), keyBuf };
    uint8_t dataBuf[] = "DER-MAXKEY";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectDer[] = "DER-MAXKEY";
    ASSERT_EQ(out.size, sizeof(expectDer) - 1);
    EXPECT_EQ(memcmp(out.data, expectDer, sizeof(expectDer) - 1), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, RejectExpireAtNow)
{
    uint8_t keyBuf[] = "kn";
    struct CmBlob key = { 2, keyBuf };
    uint8_t dataBuf[] = "d";
    struct CmBlob data = { 1, dataBuf };
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr))), CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheEngineTest, GetExpiredEntryReturnsNotExist)
{
    uint8_t keyBuf[] = "expkey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { 3, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    /* overwrite the header with an already expired timestamp */
    char full[PATH_MAX] = { 0 };
    ASSERT_EQ(BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP, full, sizeof(full)), 0);
    uint8_t payload[sizeof(int64_t) + 3] = { 0 };
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC, payload);
    const uint8_t der[] = "DER";
    (void)memcpy_s(payload + sizeof(int64_t), sizeof(payload) - sizeof(int64_t), der, sizeof(der) - 1);
    ASSERT_EQ(WriteTestFile(full, payload, sizeof(payload)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, GetHeaderOnlyFileReturnsError)
{
    uint8_t keyBuf[] = "hdrkey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { 3, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    char full[PATH_MAX] = { 0 };
    ASSERT_EQ(BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP, full, sizeof(full)), 0);
    /* only the 8-byte header: der length would be 0 and must be rejected */
    uint8_t headerOnly[sizeof(int64_t)] = { 0 };
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) + 3600, headerOnly);
    ASSERT_EQ(WriteTestFile(full, headerOnly, sizeof(headerOnly)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheEngineTest, GetTinyFileReturnsNotExist)
{
    uint8_t keyBuf[] = "tinyky1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { 3, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    char full[PATH_MAX] = { 0 };
    ASSERT_EQ(BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP, full, sizeof(full)), 0);
    uint8_t tiny[4] = { 1, 2, 3, 4 }; /* smaller than the 8-byte expire header */
    ASSERT_EQ(WriteTestFile(full, tiny, sizeof(tiny)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, GetOversizedFileReturnsError)
{
    uint8_t keyBuf[] = "bigkey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { 3, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    char full[PATH_MAX] = { 0 };
    ASSERT_EQ(BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP, full, sizeof(full)), 0);
    /* header plus data larger than MAX_OUT_BLOB_SIZE must be rejected, not allocated */
    std::vector<uint8_t> big(sizeof(int64_t) + MAX_OUT_BLOB_SIZE + 1, 'x');
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) + 3600, big.data());
    ASSERT_EQ(WriteTestFile(full, big.data(), static_cast<uint32_t>(big.size())), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicRejectsBadRelPath)
{
    uint8_t buf[] = "x";
    EXPECT_EQ(CmRevocationCacheWriteAtomic(nullptr, buf, sizeof(buf) - 1), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/aa/ok.cache", nullptr, 1), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/aa/ok.cache", buf, 0), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("/data/tmp/abs.cache", buf, sizeof(buf) - 1),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/aa/../../escape.cache", buf, sizeof(buf) - 1),
        CMR_ERROR_INVALID_ARGUMENT);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicMissingDirFails)
{
    uint8_t buf[] = "x";
    /* the prefix directory does not exist, opening the tmp file must fail */
    const char *missingOcsp = "ocsp/zz/never-created.cache";
    EXPECT_EQ(CmRevocationCacheWriteAtomic(missingOcsp, buf, sizeof(buf) - 1), CMR_ERROR_OPEN_FILE_FAIL);
    /* the failed write must not leave a partial tmp or cache file behind */
    char leftover[PATH_MAX] = { 0 };
    ASSERT_GE(snprintf_s(leftover, sizeof(leftover), sizeof(leftover) - 1, "%s%s.tmp", REVOCATION_CACHE_DIR,
        missingOcsp), 0);
    EXPECT_EQ(access(leftover, F_OK), -1);
    ASSERT_GE(snprintf_s(leftover, sizeof(leftover), sizeof(leftover) - 1, "%s%s", REVOCATION_CACHE_DIR,
        missingOcsp), 0);
    EXPECT_EQ(access(leftover, F_OK), -1);
    /* the crl store fails the same way when its directory is missing */
    EXPECT_EQ(CmRevocationCacheWriteAtomic("crl/zz/never-created.cache", buf, sizeof(buf) - 1),
        CMR_ERROR_OPEN_FILE_FAIL);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicPersistsContent)
{
    uint8_t keyBuf[] = "wackey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    /* reuse the existing directory layout and write through the raw atomic API */
    char full[PATH_MAX] = { 0 };
    ASSERT_EQ(BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP, full, sizeof(full)), 0);
    std::string rel(full + strlen(REVOCATION_CACHE_DIR));
    const uint8_t body[] = "RAWBODY";
    ASSERT_EQ(CmRevocationCacheWriteAtomic(rel.c_str(), body, sizeof(body) - 1), CM_SUCCESS);
    FILE *fp = fopen(full, "rb");
    ASSERT_NE(fp, nullptr);
    uint8_t readBack[32] = { 0 };
    size_t n = fread(readBack, 1, sizeof(readBack), fp);
    (void)fclose(fp);
    EXPECT_EQ(n, sizeof(body) - 1);
    EXPECT_EQ(memcmp(readBack, body, sizeof(body) - 1), 0);
}

TEST_F(CmRevocationCacheEngineTest, CleanupRemovesExpiredRecord)
{
    /* an RDB record whose expire is in the past, with no file on disk */
    struct RevocationCacheRecord expired = { 0 };
    expired.expireTimeUtc = static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC;
    const char *expiredRel = "ocsp/ee/expiredfake.cache";
    (void)strncpy_s(expired.filePath, sizeof(expired.filePath), expiredRel, strlen(expiredRel));
    expired.dataSize = 100;
    ASSERT_EQ(InsertRevocationCacheRecord(&expired), CM_SUCCESS);
    /* last-clean=0 forces the next save to run the cleanup pass */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t keyBuf[] = "clnkey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);
    /* the expired record must be gone from the RDB */
    char **paths = nullptr;
    uint32_t count = 0;
    ASSERT_EQ(QueryAllRevocationCacheFilePaths(&paths, &count), CM_SUCCESS);
    bool found = false;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(paths[i], expiredRel) == 0) {
            found = true;
        }
    }
    FreeRevocationCacheFilePaths(paths, count);
    EXPECT_FALSE(found);
}

TEST_F(CmRevocationCacheEngineTest, CleanupRemovesOrphanAndTmpFiles)
{
    /* save a valid entry first so the type/prefix directories exist */
    uint8_t keyBuf[] = "orphkey";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);

    char relA[512] = { 0 };
    ASSERT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, relA, sizeof(relA)), CM_SUCCESS);
    std::string rel(relA);
    std::string dir = rel.substr(0, rel.rfind('/') + 1);   /* ocsp/<xx>/ */
    std::string hash = rel.substr(dir.size());             /* <64hex>.cache */
    /* the orphan .cache keeps the two-char prefix so cleanup derives its real path */
    std::string orphanFull = std::string(REVOCATION_CACHE_DIR) + dir + hash.substr(0, 2) +
        std::string(62, 'f') + ".cache";
    std::string tmpFull = std::string(REVOCATION_CACHE_DIR) + dir + "leftover.tmp";
    std::string txtFull = std::string(REVOCATION_CACHE_DIR) + dir + "note.txt";
    const uint8_t one[] = "x";
    ASSERT_EQ(WriteTestFile(orphanFull.c_str(), one, 1), 0);
    ASSERT_EQ(WriteTestFile(tmpFull.c_str(), one, 1), 0);
    ASSERT_EQ(WriteTestFile(txtFull.c_str(), one, 1), 0);

    /* last-clean=0 forces the next save to run the cleanup pass */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t key2Buf[] = "orphk2y";
    struct CmBlob key2 = { 7, key2Buf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key2, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);

    /* orphan .cache and leftover .tmp are removed; unrelated files are kept */
    EXPECT_EQ(access(orphanFull.c_str(), F_OK), -1);
    EXPECT_EQ(access(tmpFull.c_str(), F_OK), -1);
    EXPECT_EQ(access(txtFull.c_str(), F_OK), 0);
    (void)unlink(txtFull.c_str()); /* do not leave unrelated files to other cases */
    /* the valid entry must survive the cleanup */
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, EvictOldestWhenOverCapacity)
{
    /* a fake oldest record claiming 50MB pushes the total over the capacity limit */
    struct RevocationCacheRecord big = { 0 };
    big.expireTimeUtc = static_cast<int64_t>(time(nullptr)) + 60; /* older than the new entry */
    const char *bigRel = "ocsp/ee/bigfake00.cache";
    (void)strncpy_s(big.filePath, sizeof(big.filePath), bigRel, strlen(bigRel));
    big.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&big), CM_SUCCESS);

    uint8_t keyBuf[] = "evctkey";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);

    /* the oldest oversized record must have been evicted */
    char **paths = nullptr;
    uint32_t count = 0;
    ASSERT_EQ(QueryAllRevocationCacheFilePaths(&paths, &count), CM_SUCCESS);
    bool found = false;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(paths[i], bigRel) == 0) {
            found = true;
        }
    }
    FreeRevocationCacheFilePaths(paths, count);
    EXPECT_FALSE(found);
}

TEST_F(CmRevocationCacheEngineTest, GetHapCallerUsesSandboxBase)
{
    /* write an entry as native so the service-store file really exists */
    uint8_t keyBuf[] = "hapkey1";
    struct CmBlob key = { 7, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + 3600), CM_SUCCESS);

    /* HAP callers read from their sandbox base and must not see the native entry */
    MockHapToken mockHap;
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
    EXPECT_EQ(out.data, nullptr); /* out params must stay clean on failure */
    EXPECT_EQ(out.size, 0u);
}

TEST_F(CmRevocationCacheEngineTest, AsyncSaveEventuallyPersists)
{
    uint8_t dataBuf[] = "AD";
    struct CmBlob data = { 2, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + 3600;
    EXPECT_EQ(CmRunSaveRevocationCacheAsync(nullptr, CM_REVOCATION_TYPE_OCSP, &data, expire),
        CMR_ERROR_INVALID_ARGUMENT);

    /* submit more keys than the worker limit; extra saves degrade to synchronous mode */
    constexpr int ASYNC_KEY_COUNT = 8;
    uint8_t keyBufs[ASYNC_KEY_COUNT][8] = { { 0 } };
    struct CmBlob keys[ASYNC_KEY_COUNT] = { { 0, nullptr } };
    for (int i = 0; i < ASYNC_KEY_COUNT; i++) {
        (void)snprintf_s(reinterpret_cast<char *>(keyBufs[i]), sizeof(keyBufs[i]), sizeof(keyBufs[i]) - 1,
            "ak%d", i);
        keys[i].size = strlen(reinterpret_cast<char *>(keyBufs[i]));
        keys[i].data = keyBufs[i];
        ASSERT_EQ(CmRunSaveRevocationCacheAsync(&keys[i], CM_REVOCATION_TYPE_OCSP, &data, expire),
            CM_SUCCESS);
    }

    /* every submission must land within the bounded wait (~10s) */
    bool allDone = false;
    for (int round = 0; round < 100 && !allDone; round++) {
        allDone = true;
        for (int i = 0; i < ASYNC_KEY_COUNT; i++) {
            struct CmBlob out = { 0, nullptr };
            if (CmGetRevocationCache(keys[i], CM_REVOCATION_TYPE_OCSP, &out) != CM_SUCCESS) {
                allDone = false;
            }
            CmFreeRevocationCache(&out);
        }
        if (!allDone) {
            usleep(100 * 1000);
        }
    }
    ASSERT_TRUE(allDone);
    for (int i = 0; i < ASYNC_KEY_COUNT; i++) {
        struct CmBlob out = { 0, nullptr };
        ASSERT_EQ(CmGetRevocationCache(keys[i], CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
        const uint8_t expectData[] = "AD";
        EXPECT_EQ(out.size, sizeof(expectData) - 1);
        CmFreeRevocationCache(&out);
    }
}
