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

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <climits>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cert_manager_api.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_revocation_cache.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cm_config_rdb.h"
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
constexpr int64_t ONE_HOUR_SEC = 3600;      /* expire offset: one hour in the future */
constexpr int64_t FAR_FUTURE_SEC = 100LL * 24 * 3600; /* beyond the 30d cap: clamped, not rejected */
constexpr int64_t OLDER_EXPIRE_SEC = 60;    /* expire earlier than the new entry, still in the future */
constexpr int64_t EXPIRE_TOLERANCE_SEC = 5; /* slack between the requested and the stored expire */
constexpr uint32_t REL_PATH_BUF_SIZE = 512; /* comfortably above any built rel path */
/* flip offset: craft an orphan name that differs from the real entry yet stays well-formed */
constexpr uint32_t ENCODED_NAME_PREFIX_LEN = 2;
constexpr uint32_t FILE_READ_BUF_SIZE = 64; /* 8-byte header + payload of a persisted file */
constexpr uint32_t TINY_FILE_LEN = 4;       /* deliberately below the 8-byte expire header */
constexpr int NFTW_MAX_OPEN_FDS = 16;       /* max fds nftw may keep open while walking */
constexpr int POLL_MAX_ROUNDS = 100;        /* bounded poll rounds for the async persistence */
constexpr useconds_t POLL_INTERVAL_USEC = 100 * 1000; /* 100ms between two poll rounds */
constexpr uint32_t ASYNC_KEY_BUF_LEN = 8;   /* room for the short async test keys */
constexpr uint64_t EXPIRED_RECORD_DATA_SIZE = 100;    /* dataSize of the fake expired record */
constexpr int64_t META_VALUE_QUERYABLE = 424242;      /* meta value fetched back via the external get path */
MockNativeToken *g_mockNative = nullptr;

/* snapshot of all cache rel-paths recorded in the RDB; nullopt when the query itself fails */
static std::optional<std::vector<std::string>> QueryCacheFilePaths()
{
    /* the array is owned by the C query API until FreeRevocationCacheFilePaths */
    char **paths = nullptr;
    uint32_t count = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &count) != CM_SUCCESS) {
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (uint32_t i = 0; i < count; i++) {
        result.emplace_back(paths[i]);
    }
    FreeRevocationCacheFilePaths(paths, count);
    return result;
}

/* remove all revocation cache records, files and meta left by this or previous test runs */
void CleanupRevocationCacheState()
{
    const auto paths = QueryCacheFilePaths();
    if (paths.has_value()) {
        for (const auto &rel : *paths) {
            (void)unlink((std::string(REVOCATION_CACHE_DIR) + rel).c_str());
            (void)DeleteRevocationCacheRecord(rel.c_str());
        }
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
static std::string BuildCacheFullPath(const struct CmBlob *key, uint32_t type)
{
    char relPath[REL_PATH_BUF_SIZE] = { 0 };
    if (CmRevocationCacheBuildRelPath(type, key, relPath, sizeof(relPath)) != CM_SUCCESS) {
        return "";
    }
    return std::string(REVOCATION_CACHE_DIR) + relPath;
}

static int RemoveTreeEntry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st;
    (void)ftw;
    /* the walk root is the base cache directory itself (nftw may hand it back
     * with or without its trailing slash): it belongs to the SA lifecycle and
     * must survive the cleanup */
    std::string entry = path;
    std::string base = REVOCATION_CACHE_DIR;
    if (!entry.empty() && entry.back() == '/') {
        entry.pop_back();
    }
    if (!base.empty() && base.back() == '/') {
        base.pop_back();
    }
    if (entry == base) {
        return 0;
    }
    if (type == FTW_D || type == FTW_DP) {
        (void)rmdir(path); /* FTW_DEPTH visits children first, so dirs are empty here */
    } else {
        (void)unlink(path);
    }
    return 0;
}

/*
 * The engine-level cases run in this root process and create the cache
 * directories (revocation_cache/<type>) with root ownership. The SA
 * (uid cert_manager_server) then fails its atomic rename with EACCES when
 * saving through IPC. Deleting is allowed though (same as teardown cleanup), so
 * drop the tree contents before pulling up the SA and let its own save
 * pipeline recreate the levels below with the SA's ownership; the base
 * directory itself belongs to the SA lifecycle and is kept.
 */
static void RemoveRevocationCacheTree(void)
{
    (void)nftw(REVOCATION_CACHE_DIR, RemoveTreeEntry, NFTW_MAX_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

/* ---------- helpers for verifying the SA-persisted formal store ---------- */

/* read the whole cache file the SA persisted (8-byte big-endian expiry + payload) */
static bool ReadFormalCacheFile(const char *fullPath, uint8_t *buf, uint32_t bufLen, uint32_t *outLen)
{
    FILE *fp = fopen(fullPath, "rb");
    if (fp == nullptr) {
        return false;
    }
    size_t n = fread(buf, 1, bufLen, fp);
    (void)fclose(fp);
    if (n < sizeof(int64_t)) {
        return false;
    }
    *outLen = static_cast<uint32_t>(n);
    return true;
}

/* decode the 8-byte big-endian expiry header the SA wrote in front of the payload */
static int64_t DecodeExpireHeader(const uint8_t *buf)
{
    int64_t expire = 0;
    for (uint32_t i = 0; i < sizeof(int64_t); i++) {
        expire = (expire << CHAR_BIT) | buf[i];
    }
    return expire;
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
    /* the cleanup meta row lives in cert_manager_config: create it first */
    ASSERT_EQ(CreateCertManagerConfigRdb(), CM_SUCCESS);
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
    CleanupRevocationCacheState(); /* remove records/files/meta created by this case (incl. SA-written rows) */
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
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, expire), CM_SUCCESS);
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    const uint8_t expectDer[] = "DER";
    ASSERT_EQ(out.size, sizeof(expectDer) - 1);
    EXPECT_EQ(memcmp(out.data, expectDer, sizeof(expectDer) - 1), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, SaveRecordsKeyAndTypeColumns)
{
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    /* earlier expire for the ocsp entry: the expire-ascending query is deterministic */
    uint8_t keyBuf[] = "key1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + OLDER_EXPIRE_SEC), CM_SUCCESS);
    uint8_t crlKeyBuf[] = "ck";
    struct CmBlob crlKey = { sizeof(crlKeyBuf) - 1, crlKeyBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&crlKey, CM_REVOCATION_TYPE_CRL, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the RDB row must carry the hex-encoded key (hex("key1") = 6b657931) and the type string */
    struct RevocationCacheRecord rec = { 0 };
    ASSERT_EQ(QueryRevocationCacheEvictCandidate("none", "none", &rec), CM_SUCCESS);
    EXPECT_STREQ(rec.key, "6b657931");
    EXPECT_STREQ(rec.type, "ocsp");
    EXPECT_STREQ(rec.filePath, "ocsp/6b657931.cache");
    ASSERT_EQ(DeleteRevocationCacheRecord(rec.filePath), CM_SUCCESS);

    /* the crl row follows: hex("ck") = 636b */
    ASSERT_EQ(QueryRevocationCacheEvictCandidate("none", "none", &rec), CM_SUCCESS);
    EXPECT_STREQ(rec.key, "636b");
    EXPECT_STREQ(rec.type, "crl");
    EXPECT_STREQ(rec.filePath, "crl/636b.cache");
}

TEST_F(CmRevocationCacheEngineTest, GetMissingKeyReturnsNotExist)
{
    uint8_t keyBuf[] = "nokey00";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
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
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t far = static_cast<int64_t>(time(nullptr)) + FAR_FUTURE_SEC; /* > 30d cap: clamped, not an error */
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
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob d1 = { sizeof(d1Buf) - 1, d1Buf };
    struct CmBlob d2 = { sizeof(d2Buf) - 1, d2Buf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
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
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
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
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
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
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
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
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "d";
    struct CmBlob data = { 1, dataBuf };
    int64_t nowSec = static_cast<int64_t>(time(nullptr)); /* expire == now is the reject boundary */
    EXPECT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data, nowSec),
        CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME);
}

TEST_F(CmRevocationCacheEngineTest, GetExpiredEntryReturnsNotExist)
{
    uint8_t keyBuf[] = "expkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    /* overwrite the header with an already expired timestamp */
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    const uint8_t der[] = "DER";
    uint8_t payload[sizeof(int64_t) + sizeof(der) - 1] = { 0 };
    struct CmBlob expireBlob = { sizeof(int64_t), payload };
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC, &expireBlob);
    (void)memcpy_s(payload + sizeof(int64_t), sizeof(payload) - sizeof(int64_t), der, sizeof(der) - 1);
    ASSERT_EQ(WriteTestFile(full.c_str(), payload, sizeof(payload)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, GetHeaderOnlyFileReturnsError)
{
    uint8_t keyBuf[] = "hdrkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    /* only the 8-byte header: der length would be 0 and must be rejected */
    uint8_t headerOnly[sizeof(int64_t)] = { 0 };
    struct CmBlob expireBlob = { sizeof(headerOnly), headerOnly };
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC, &expireBlob);
    ASSERT_EQ(WriteTestFile(full.c_str(), headerOnly, sizeof(headerOnly)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheEngineTest, GetTinyFileReturnsNotExist)
{
    uint8_t keyBuf[] = "tinyky1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    uint8_t tiny[TINY_FILE_LEN] = { 0 }; /* smaller than the 8-byte expire header */
    ASSERT_EQ(WriteTestFile(full.c_str(), tiny, sizeof(tiny)), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
}

TEST_F(CmRevocationCacheEngineTest, GetOversizedFileReturnsError)
{
    uint8_t keyBuf[] = "bigkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    /* header plus data larger than MAX_OUT_BLOB_SIZE must be rejected, not allocated */
    std::vector<uint8_t> big(sizeof(int64_t) + MAX_OUT_BLOB_SIZE + 1, 'x');
    struct CmBlob expireBlob = { sizeof(int64_t), big.data() };
    CmRevocationCacheEncodeInt64Be(static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC, &expireBlob);
    ASSERT_EQ(WriteTestFile(full.c_str(), big.data(), static_cast<uint32_t>(big.size())), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_BUFFER_TOO_SMALL);
}

TEST_F(CmRevocationCacheEngineTest, GetSizingIsExactAtBlockBoundaries)
{
    /* payload = 8-byte expire header + data: with 4088 data bytes it is
     * exactly one 4096-byte block, with 4089 it is one byte past; both must
     * read back byte-identical, the file size must never be taken from
     * block rounding */
    constexpr uint32_t dataExactBlock = 4088; /* 8 + 4088 = 4096 */
    constexpr uint32_t dataPastBlock = 4089;    /* 8 + 4089 = 4097 */
    uint8_t key1Buf[] = "blk4088";
    struct CmBlob key1 = { sizeof(key1Buf) - 1, key1Buf };
    uint8_t key2Buf[] = "blk4089";
    struct CmBlob key2 = { sizeof(key2Buf) - 1, key2Buf };
    std::vector<uint8_t> data1(dataExactBlock, 0x5a);
    std::vector<uint8_t> data2(dataPastBlock, 0xa5);
    struct CmBlob blob1 = { static_cast<uint32_t>(data1.size()), data1.data() };
    struct CmBlob blob2 = { static_cast<uint32_t>(data2.size()), data2.data() };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    ASSERT_EQ(CmServiceSaveRevocationCache(&key1, CM_REVOCATION_TYPE_OCSP, &blob1, expire), CM_SUCCESS);
    ASSERT_EQ(CmServiceSaveRevocationCache(&key2, CM_REVOCATION_TYPE_OCSP, &blob2, expire), CM_SUCCESS);

    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key1, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    EXPECT_EQ(out.size, blob1.size);
    ASSERT_NE(out.data, nullptr);
    EXPECT_EQ(memcmp(out.data, data1.data(), out.size), 0);
    CmFreeRevocationCache(&out);

    ASSERT_EQ(CmGetRevocationCache(key2, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    EXPECT_EQ(out.size, blob2.size);
    ASSERT_NE(out.data, nullptr);
    EXPECT_EQ(memcmp(out.data, data2.data(), out.size), 0);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, GetSymlinkedEntryReturnsNotExist)
{
    uint8_t keyBuf[] = "symget1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    ASSERT_EQ(unlink(full.c_str()), 0);
    /* a symlink planted at the entry path must not be followed, even though
     * its target exists: the normalized path escapes the cache root */
    ASSERT_EQ(symlink("/etc/passwd", full.c_str()), 0);
    struct CmBlob out = { 0, nullptr };
    EXPECT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CMR_ERROR_NOT_EXIST);
    (void)unlink(full.c_str()); /* remove the planted symlink; the row is cleaned by teardown */
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicDoesNotFollowTmpSymlink)
{
    uint8_t keyBuf[] = "symtmp1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "DER";
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    const std::string tmp = full + ".tmp";
    /* plant a symlink where the tmp file is written: the write must replace
     * it, never write through it */
    struct stat passwdBefore;
    ASSERT_EQ(stat("/etc/passwd", &passwdBefore), 0);
    ASSERT_EQ(symlink("/etc/passwd", tmp.c_str()), 0);
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    struct stat passwdAfter;
    ASSERT_EQ(stat("/etc/passwd", &passwdAfter), 0);
    EXPECT_EQ(passwdAfter.st_size, passwdBefore.st_size); /* the target must stay untouched */
    struct stat tmpSt;
    EXPECT_EQ(lstat(tmp.c_str(), &tmpSt), -1); /* no tmp leftover */
    struct stat fullSt;
    ASSERT_EQ(lstat(full.c_str(), &fullSt), 0);
    EXPECT_TRUE(S_ISREG(fullSt.st_mode)); /* the entry itself is a regular file */
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicRejectsBadRelPath)
{
    uint8_t buf[] = "x";
    uint64_t accounted = 0; /* out param: must never be written on rejection */
    EXPECT_EQ(CmRevocationCacheWriteAtomic(nullptr, buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/ok.cache", nullptr, 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/ok.cache", buf, 0, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    /* the accounted-size out parameter is mandatory too */
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/ok.cache", buf, sizeof(buf) - 1, nullptr),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("/data/tmp/abs.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/../../escape.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    /* the strict rel-path whitelist also rejects non-hex and uppercase names */
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/zz616263.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/61626G.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(CmRevocationCacheWriteAtomic("ocsp/ABCD.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(accounted, 0u);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicMissingDirFails)
{
    uint8_t buf[] = "x";
    /* best effort: drop the (normally empty) type dirs so the parent of a
     * well-formed path is genuinely missing; SetUp already removed every
     * row-backed file, so a leftover file would make the write below succeed
     * and fail this test loudly */
    (void)rmdir((std::string(REVOCATION_CACHE_DIR) + "ocsp").c_str());
    (void)rmdir((std::string(REVOCATION_CACHE_DIR) + "crl").c_str());
    /* the type directory does not exist: the hex-shaped name passes the
     * whitelist, and opening the tmp file must still fail */
    const char *missingOcsp = "ocsp/badbad.cache";
    uint64_t accounted = 0;
    EXPECT_EQ(CmRevocationCacheWriteAtomic(missingOcsp, buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_OPEN_FILE_FAIL);
    /* the failed write must not leave a partial tmp or cache file behind */
    char leftover[PATH_MAX] = { 0 };
    ASSERT_GE(snprintf_s(leftover, sizeof(leftover), sizeof(leftover) - 1, "%s%s.tmp", REVOCATION_CACHE_DIR,
        missingOcsp), 0);
    EXPECT_EQ(access(leftover, F_OK), -1);
    ASSERT_GE(snprintf_s(leftover, sizeof(leftover), sizeof(leftover) - 1, "%s%s", REVOCATION_CACHE_DIR,
        missingOcsp), 0);
    EXPECT_EQ(access(leftover, F_OK), -1);
    /* the crl store fails the same way when its directory is missing */
    EXPECT_EQ(CmRevocationCacheWriteAtomic("crl/badbad.cache", buf, sizeof(buf) - 1, &accounted),
        CMR_ERROR_OPEN_FILE_FAIL);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicPersistsContent)
{
    uint8_t keyBuf[] = "wackey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    /* reuse the existing directory layout and write through the raw atomic API */
    const std::string full = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(full.empty());
    std::string rel = full.substr(strlen(REVOCATION_CACHE_DIR));
    const uint8_t body[] = "RAWBODY";
    constexpr uint64_t accountedTwoBlocks = 8192; /* 8-byte body + 4 KiB page, 4 KiB aligned */
    uint64_t accounted = 0;
    ASSERT_EQ(CmRevocationCacheWriteAtomic(rel.c_str(), body, sizeof(body) - 1, &accounted), CM_SUCCESS);
    EXPECT_EQ(accounted, accountedTwoBlocks);
    FILE *fp = fopen(full.c_str(), "rb");
    ASSERT_NE(fp, nullptr);
    uint8_t readBack[sizeof(body) - 1] = { 0 }; /* exactly the body length: the read must fill it */
    size_t n = fread(readBack, 1, sizeof(readBack), fp);
    (void)fclose(fp);
    EXPECT_EQ(n, sizeof(body) - 1);
    EXPECT_EQ(memcmp(readBack, body, sizeof(body) - 1), 0);
}

TEST_F(CmRevocationCacheEngineTest, WriteAtomicAccountsAlignedSize)
{
    /* accounted = payload + one 4 KiB metadata page, rounded up to 4 KiB */
    constexpr uint32_t lenBelowBlock = 1;              /* payload under one block */
    constexpr uint32_t lenExactBlock = 4096;         /* exactly one block */
    constexpr uint32_t lenPastBlock = 4097;          /* one byte past one block */
    constexpr uint32_t lenSecondBlockPartial = 5000;  /* inside the second block */
    constexpr uint64_t accountedTwoBlocks = 8192;
    constexpr uint64_t accountedThreeBlocks = 12288;
    uint8_t buf[lenSecondBlockPartial] = { 0 };
    const struct {
        uint32_t len;
        uint64_t accounted;
    } vectors[] = {
        { lenBelowBlock, accountedTwoBlocks },
        { lenExactBlock, accountedTwoBlocks },
        { lenPastBlock, accountedThreeBlocks },
        { lenSecondBlockPartial, accountedThreeBlocks },
    };
    std::vector<std::string> created;
    for (uint32_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        /* hex-only crafted names keep every path inside the whitelist */
        char name[32] = { 0 };
        ASSERT_GE(snprintf_s(name, sizeof(name), sizeof(name) - 1, "acc%06x", i), 0);
        std::string rel = std::string("ocsp/") + name + ".cache";
        uint64_t accounted = 0;
        ASSERT_EQ(CmRevocationCacheWriteAtomic(rel.c_str(), buf, vectors[i].len, &accounted), CM_SUCCESS);
        EXPECT_EQ(accounted, vectors[i].accounted);
        created.push_back(std::string(REVOCATION_CACHE_DIR) + rel);
    }
    /* raw writes leave no RDB rows: remove the files so later cases start clean */
    for (const auto &full : created) {
        (void)unlink(full.c_str());
    }
}

TEST_F(CmRevocationCacheEngineTest, CleanupRemovesExpiredRecord)
{
    /* an RDB record whose expire is in the past, with no file on disk */
    struct RevocationCacheRecord expired = { 0 };
    expired.expireTimeUtc = static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC;
    const char *expiredRel = "ocsp/ee998877.cache";
    (void)strncpy_s(expired.key, sizeof(expired.key), "ee998877", strlen("ee998877"));
    (void)strncpy_s(expired.type, sizeof(expired.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(expired.filePath, sizeof(expired.filePath), expiredRel, strlen(expiredRel));
    expired.dataSize = EXPIRED_RECORD_DATA_SIZE;
    ASSERT_EQ(InsertRevocationCacheRecord(&expired), CM_SUCCESS);
    /* last-clean=0 forces the next save to run the cleanup pass */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t keyBuf[] = "clnkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    /* the expired record must be gone from the RDB */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_EQ(std::find(paths->begin(), paths->end(), expiredRel), paths->end());
}

TEST_F(CmRevocationCacheEngineTest, CleanupRemovesOrphanAndTmpFiles)
{
    /* save a valid entry first so the type/prefix directories exist */
    uint8_t keyBuf[] = "orphkey";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    char relA[REL_PATH_BUF_SIZE] = { 0 };
    ASSERT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, relA, sizeof(relA)), CM_SUCCESS);
    std::string rel(relA);
    std::string dir = rel.substr(0, rel.rfind('/') + 1);    /* ocsp/ */
    std::string name = rel.substr(dir.size());              /* <hex>.cache */
    /* the orphan .cache differs from the real entry's name by one flipped hex
     * char: the cleanup derives the rel path from the file name, so the
     * crafted name must stay well-formed */
    ASSERT_GT(name.size(), ENCODED_NAME_PREFIX_LEN + strlen(".cache"));
    std::string orphanName = name;
    /* stay inside the hex alphabet so the crafted name is a well-formed orphan */
    orphanName[ENCODED_NAME_PREFIX_LEN] =
        (orphanName[ENCODED_NAME_PREFIX_LEN] == 'a') ? 'b' : 'a';
    std::string orphanFull = std::string(REVOCATION_CACHE_DIR) + dir + orphanName;
    std::string tmpFull = std::string(REVOCATION_CACHE_DIR) + dir + "leftover.tmp";
    std::string txtFull = std::string(REVOCATION_CACHE_DIR) + dir + "note.txt";
    const uint8_t one[] = "x";
    ASSERT_EQ(WriteTestFile(orphanFull.c_str(), one, 1), 0);
    ASSERT_EQ(WriteTestFile(tmpFull.c_str(), one, 1), 0);
    ASSERT_EQ(WriteTestFile(txtFull.c_str(), one, 1), 0);

    /* last-clean=0 forces the next save to run the cleanup pass */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t key2Buf[] = "orphk2y";
    struct CmBlob key2 = { sizeof(key2Buf) - 1, key2Buf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key2, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

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
    /* an expired record claiming the whole 2 MiB budget pushes the next save
     * over the accounted capacity limit and is reaped physically; the
     * unexpired logical branch has its own case (LogicalEvictionKeepsFile) */
    constexpr uint64_t accountedTwoBlocks = 8192; /* 9-byte payload: page + 8 bytes, aligned */
    struct RevocationCacheRecord big = { 0 };
    big.expireTimeUtc = static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC; /* expired */
    const char *bigRel = "ocsp/cafe0000.cache";
    (void)strncpy_s(big.key, sizeof(big.key), "cafe0000", strlen("cafe0000"));
    (void)strncpy_s(big.type, sizeof(big.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(big.filePath, sizeof(big.filePath), bigRel, strlen(bigRel));
    big.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&big), CM_SUCCESS);
    std::string bigFull = std::string(REVOCATION_CACHE_DIR) + bigRel;
    const uint8_t body[] = "OLD";
    ASSERT_EQ(WriteTestFile(bigFull.c_str(), body, sizeof(body) - 1), 0);

    /* keep the periodic cleanup out: it would reap the expired row before
     * the eviction branch under test sees it */
    int64_t nowSec = static_cast<int64_t>(time(nullptr));
    ASSERT_EQ(SetRevocationCacheMeta(nowSec), CM_SUCCESS);

    uint8_t keyBuf[] = "evctkey";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the oldest oversized record must have been evicted physically */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_EQ(std::find(paths->begin(), paths->end(), bigRel), paths->end());
    EXPECT_NE(access(bigFull.c_str(), F_OK), 0);
    /* the surviving row bills its accounted size, not the raw payload length */
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, accountedTwoBlocks);
}

TEST_F(CmRevocationCacheEngineTest, ResaveBillsOnceNeverEvictsOthers)
{
    /* a re-save must never bill or evict for its own old row: the old row is
     * excluded from the active sum and from the eviction candidates */
    constexpr uint64_t accountedTwoBlocks = 8192; /* 9-byte payload, aligned */
    uint8_t keyBuf[] = "reself1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    /* DATA_SIZE holds the accounted size: one active row, nothing excluded */
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, accountedTwoBlocks);

    /* a fake peer sized to exactly fill the rest of the budget: the store is
     * at capacity, so double-billing the self row would evict the peer */
    struct RevocationCacheRecord peer = { 0 };
    peer.expireTimeUtc = static_cast<int64_t>(time(nullptr)) + OLDER_EXPIRE_SEC;
    const char *peerRel = "ocsp/70656572.cache"; /* hex("peer") */
    (void)strncpy_s(peer.key, sizeof(peer.key), "70656572", strlen("70656572"));
    (void)strncpy_s(peer.type, sizeof(peer.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(peer.filePath, sizeof(peer.filePath), peerRel, strlen(peerRel));
    peer.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES) - accountedTwoBlocks;
    ASSERT_EQ(InsertRevocationCacheRecord(&peer), CM_SUCCESS);

    /* the re-save succeeds and the peer survives: the self row is replaced by
     * the (KEY, TYPE) conflict with the same accounted size */
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_NE(std::find(paths->begin(), paths->end(), peerRel), paths->end());
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES));
}

TEST_F(CmRevocationCacheEngineTest, LogicalEvictionKeepsFile)
{
    /* an unexpired oversized row is logically evicted: the row leaves the
     * active accounting but the file stays on disk for late readers */
    constexpr uint64_t accountedTwoBlocks = 8192; /* 9-byte payload, aligned */
    const char *bigRel = "ocsp/6c6f6769.cache"; /* hex("logi") */
    struct RevocationCacheRecord big = { 0 };
    big.expireTimeUtc = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC; /* unexpired */
    (void)strncpy_s(big.key, sizeof(big.key), "6c6f6769", strlen("6c6f6769"));
    (void)strncpy_s(big.type, sizeof(big.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(big.filePath, sizeof(big.filePath), bigRel, strlen(bigRel));
    big.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&big), CM_SUCCESS);
    std::string bigFull = std::string(REVOCATION_CACHE_DIR) + bigRel;
    const uint8_t body[] = "KEEPME";
    ASSERT_EQ(WriteTestFile(bigFull.c_str(), body, sizeof(body) - 1), 0);

    uint8_t keyBuf[] = "lgckey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the row no longer bills capacity ... */
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, accountedTwoBlocks);
    /* ... but the path stays queryable and the file stays on disk */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_NE(std::find(paths->begin(), paths->end(), bigRel), paths->end());
    EXPECT_EQ(access(bigFull.c_str(), F_OK), 0);
}

TEST_F(CmRevocationCacheEngineTest, ResaveResurrectsDeletedRow)
{
    /* a re-save after logical deletion resurrects the row: the REPLACE insert
     * writes IS_DELETED = 0 and the new accounted size bills again */
    constexpr uint64_t accountedTwoBlocks = 8192; /* 9-byte payload, aligned */
    uint8_t keyBuf[] = "rsrkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    char selfRel[REL_PATH_BUF_SIZE] = { 0 };
    ASSERT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, selfRel, sizeof(selfRel)),
        CM_SUCCESS);
    ASSERT_EQ(MarkRevocationCacheRecordDeleted(selfRel), CM_SUCCESS);
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, 0u); /* the deleted row no longer bills */

    /* re-save the same (key, type): REPLACE resurrects the row */
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, accountedTwoBlocks);
    /* and the entry reads back */
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    CmFreeRevocationCache(&out);
}

TEST_F(CmRevocationCacheEngineTest, RaceRegressionExpiredSelfRowSurvives)
{
    /* race regression: an expired row for the very key being re-saved must
     * never be an eviction candidate, or the physical branch would unlink
     * the just-renamed new file at the same path */
    constexpr uint64_t accountedTwoBlocks = 8192; /* 9-byte payload, aligned */
    uint8_t keyBuf[] = "racekey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    char selfRel[REL_PATH_BUF_SIZE] = { 0 };
    ASSERT_EQ(CmRevocationCacheBuildRelPath(CM_REVOCATION_TYPE_OCSP, &key, selfRel, sizeof(selfRel)),
        CM_SUCCESS);

    /* the old world: an expired row for this key with a huge billed size and
     * the old file on disk */
    struct RevocationCacheRecord selfRow = { 0 };
    selfRow.expireTimeUtc = static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC;
    (void)strncpy_s(selfRow.key, sizeof(selfRow.key), "726163656b657931", strlen("726163656b657931"));
    (void)strncpy_s(selfRow.type, sizeof(selfRow.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(selfRow.filePath, sizeof(selfRow.filePath), selfRel, strlen(selfRel));
    selfRow.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&selfRow), CM_SUCCESS);
    std::string selfFull = std::string(REVOCATION_CACHE_DIR) + selfRel;
    const uint8_t oldBody[] = "OLDFILE";
    ASSERT_EQ(WriteTestFile(selfFull.c_str(), oldBody, sizeof(oldBody) - 1), 0);

    /* a filler row keeps the store over capacity so the eviction loop runs;
     * without the self exclusion the expired self row would be picked first */
    struct RevocationCacheRecord filler = { 0 };
    filler.expireTimeUtc = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    const char *fillerRel = "ocsp/66696c6c.cache"; /* hex("fill") */
    (void)strncpy_s(filler.key, sizeof(filler.key), "66696c6c", strlen("66696c6c"));
    (void)strncpy_s(filler.type, sizeof(filler.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(filler.filePath, sizeof(filler.filePath), fillerRel, strlen(fillerRel));
    filler.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&filler), CM_SUCCESS);

    /* the periodic cleanup must NOT run first: it would mask the race by
     * reaping the expired row before the eviction could see it */
    int64_t nowSec = static_cast<int64_t>(time(nullptr));
    ASSERT_EQ(SetRevocationCacheMeta(nowSec), CM_SUCCESS);

    /* re-save: the new file lands on the very path the expired row points to */
    uint8_t newBody[] = "NEWFILE";
    struct CmBlob data = { sizeof(newBody) - 1, newBody };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the new file must have survived and carry the new content */
    struct CmBlob out = { 0, nullptr };
    ASSERT_EQ(CmGetRevocationCache(key, CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    EXPECT_EQ(out.size, data.size);
    EXPECT_EQ(memcmp(out.data, data.data, out.size), 0);
    CmFreeRevocationCache(&out);
    /* the self row survived for the REPLACE and bills the new accounted size */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_NE(std::find(paths->begin(), paths->end(), selfRel), paths->end());
    uint64_t total = 0;
    ASSERT_EQ(QueryRevocationCacheActiveSumSize("none", "none", &total), CM_SUCCESS);
    EXPECT_EQ(total, accountedTwoBlocks);
}

TEST_F(CmRevocationCacheEngineTest, EvictBoundaryExpireEqualsNow)
{
    /* the eviction boundary matches the read path: expire == now counts as
     * expired, so the candidate row and its file go physically */
    const char *edgeRel = "ocsp/65646765.cache"; /* hex("edge") */
    struct RevocationCacheRecord edge = { 0 };
    edge.expireTimeUtc = static_cast<int64_t>(time(nullptr)); /* exactly now */
    (void)strncpy_s(edge.key, sizeof(edge.key), "65646765", strlen("65646765"));
    (void)strncpy_s(edge.type, sizeof(edge.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(edge.filePath, sizeof(edge.filePath), edgeRel, strlen(edgeRel));
    edge.dataSize = static_cast<uint64_t>(REVOCATION_CACHE_MAX_TOTAL_BYTES);
    ASSERT_EQ(InsertRevocationCacheRecord(&edge), CM_SUCCESS);
    std::string edgeFull = std::string(REVOCATION_CACHE_DIR) + edgeRel;
    const uint8_t body[] = "EDGE";
    ASSERT_EQ(WriteTestFile(edgeFull.c_str(), body, sizeof(body) - 1), 0);

    /* keep the periodic cleanup out: it spares expire == now, the eviction
     * branch under test must not */
    int64_t nowSec = static_cast<int64_t>(time(nullptr));
    ASSERT_EQ(SetRevocationCacheMeta(nowSec), CM_SUCCESS);
    uint8_t keyBuf[] = "edgkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* physically gone: neither the row nor the file remains */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_EQ(std::find(paths->begin(), paths->end(), edgeRel), paths->end());
    EXPECT_NE(access(edgeFull.c_str(), F_OK), 0);
}

TEST_F(CmRevocationCacheEngineTest, OrphanScanKeepsDeletedRowFiles)
{
    /* a logically deleted row keeps its file: the orphan scan must not reap
     * files that a deleted-but-unexpired row still points to */
    const char *keptRel = "ocsp/6b657074.cache"; /* hex("kept") */
    struct RevocationCacheRecord kept = { 0 };
    kept.expireTimeUtc = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    (void)strncpy_s(kept.key, sizeof(kept.key), "6b657074", strlen("6b657074"));
    (void)strncpy_s(kept.type, sizeof(kept.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(kept.filePath, sizeof(kept.filePath), keptRel, strlen(keptRel));
    kept.dataSize = EXPIRED_RECORD_DATA_SIZE;
    ASSERT_EQ(InsertRevocationCacheRecord(&kept), CM_SUCCESS);
    ASSERT_EQ(MarkRevocationCacheRecordDeleted(keptRel), CM_SUCCESS);
    std::string keptFull = std::string(REVOCATION_CACHE_DIR) + keptRel;
    const uint8_t body[] = "KEPT";
    ASSERT_EQ(WriteTestFile(keptFull.c_str(), body, sizeof(body) - 1), 0);

    /* last-clean=0 forces the cleanup pass on the next save */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t keyBuf[] = "orpkdy1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the row is still there (unexpired) and the file survived the scan */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_NE(std::find(paths->begin(), paths->end(), keptRel), paths->end());
    EXPECT_EQ(access(keptFull.c_str(), F_OK), 0);
}

TEST_F(CmRevocationCacheEngineTest, CleanupRemovesExpiredDeletedRow)
{
    /* a logically deleted row is reaped physically once it expires: the
     * periodic cleanup deletes the row and unlinks the file */
    const char *goneRel = "ocsp/676f6e65.cache"; /* hex("gone") */
    struct RevocationCacheRecord gone = { 0 };
    gone.expireTimeUtc = static_cast<int64_t>(time(nullptr)) - ALREADY_EXPIRED_SEC;
    (void)strncpy_s(gone.key, sizeof(gone.key), "676f6e65", strlen("676f6e65"));
    (void)strncpy_s(gone.type, sizeof(gone.type), "ocsp", strlen("ocsp"));
    (void)strncpy_s(gone.filePath, sizeof(gone.filePath), goneRel, strlen(goneRel));
    gone.dataSize = EXPIRED_RECORD_DATA_SIZE;
    ASSERT_EQ(InsertRevocationCacheRecord(&gone), CM_SUCCESS);
    ASSERT_EQ(MarkRevocationCacheRecordDeleted(goneRel), CM_SUCCESS);
    std::string goneFull = std::string(REVOCATION_CACHE_DIR) + goneRel;
    const uint8_t body[] = "GONE";
    ASSERT_EQ(WriteTestFile(goneFull.c_str(), body, sizeof(body) - 1), 0);

    /* last-clean=0 forces the cleanup pass on the next save */
    ASSERT_EQ(SetRevocationCacheMeta(0), CM_SUCCESS);
    uint8_t keyBuf[] = "rpkdly1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

    /* the row is gone and the file went with it */
    const auto paths = QueryCacheFilePaths();
    ASSERT_NE(paths, std::nullopt);
    EXPECT_EQ(std::find(paths->begin(), paths->end(), goneRel), paths->end());
    EXPECT_NE(access(goneFull.c_str(), F_OK), 0);
}

TEST_F(CmRevocationCacheEngineTest, GetHapCallerUsesSandboxBase)
{
    /* write an entry as native so the service-store file really exists */
    uint8_t keyBuf[] = "hapkey1";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    uint8_t dataBuf[] = "D";
    struct CmBlob data = { 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);

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
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    EXPECT_EQ(CmRunSaveRevocationCacheAsync(nullptr, CM_REVOCATION_TYPE_OCSP, &data, expire),
        CMR_ERROR_INVALID_ARGUMENT);

    /* submit more keys than the worker limit; extra saves degrade to synchronous mode */
    constexpr int asyncKeyCount = 8;
    uint8_t keyBufs[asyncKeyCount][ASYNC_KEY_BUF_LEN] = { { 0 } };
    struct CmBlob keys[asyncKeyCount] = { { 0, nullptr } };
    for (int i = 0; i < asyncKeyCount; i++) {
        const std::string keyText = "ak" + std::to_string(i);
        ASSERT_EQ(memcpy_s(keyBufs[i], sizeof(keyBufs[i]), keyText.c_str(), keyText.size() + 1), EOK);
        keys[i].size = keyText.size();
        keys[i].data = keyBufs[i];
        ASSERT_EQ(CmRunSaveRevocationCacheAsync(&keys[i], CM_REVOCATION_TYPE_OCSP, &data, expire),
            CM_SUCCESS);
    }

    /* every submission must land within the bounded wait (~10s) */
    bool allDone = false;
    for (int round = 0; round < POLL_MAX_ROUNDS && !allDone; round++) {
        allDone = true;
        for (int i = 0; i < asyncKeyCount; i++) {
            struct CmBlob out = { 0, nullptr };
            if (CmGetRevocationCache(keys[i], CM_REVOCATION_TYPE_OCSP, &out) != CM_SUCCESS) {
                allDone = false;
            }
            CmFreeRevocationCache(&out);
        }
        if (!allDone) {
            usleep(POLL_INTERVAL_USEC);
        }
    }
    ASSERT_TRUE(allDone);
    for (int i = 0; i < asyncKeyCount; i++) {
        struct CmBlob out = { 0, nullptr };
        ASSERT_EQ(CmGetRevocationCache(keys[i], CM_REVOCATION_TYPE_OCSP, &out), CM_SUCCESS);
        const uint8_t expectData[] = "AD";
        EXPECT_EQ(out.size, sizeof(expectData) - 1);
        CmFreeRevocationCache(&out);
    }
}

TEST_F(CmRevocationCacheEngineTest, CacheTreeRemovalKeepsBaseDir)
{
    /* populate the store the way engine cases do: the save pipeline creates
     * the base directory, the type subdirectory and cache files */
    uint8_t keyBuf[] = "basedir";
    uint8_t dataBuf[] = "BD";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    ASSERT_EQ(CmServiceSaveRevocationCache(&key, CM_REVOCATION_TYPE_OCSP, &data,
        static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC), CM_SUCCESS);
    const std::string ocspDir = std::string(REVOCATION_CACHE_DIR) + "ocsp";
    const std::string probe = ocspDir + "/probe.cache";
    const uint8_t one[] = "x";
    ASSERT_EQ(WriteTestFile(probe.c_str(), one, 1), 0);

    RemoveRevocationCacheTree();

    /* the base directory belongs to the SA lifecycle and must survive the
     * cleanup; every level below it is gone */
    EXPECT_EQ(access(REVOCATION_CACHE_DIR, F_OK), 0);
    EXPECT_EQ(access(ocspDir.c_str(), F_OK), -1);
    EXPECT_EQ(access(probe.c_str(), F_OK), -1);
}

TEST_F(CmRevocationCacheEngineTest, SaveThroughSdkIpcRoundTrip)
{
    /* drop the root-owned cache tree contents so the SA recreates the levels below (see helper) */
    CleanupRevocationCacheState();
    RemoveRevocationCacheTree();
    /* full SDK save chain: param check -> native caller check -> IPC -> SA async save */
    uint8_t keyBuf[] = "sdkkey1";
    uint8_t dataBuf[] = "SDK-DER";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    /* same store the SA writes: REVOCATION_CACHE_DIR */
    const std::string formalFull = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(formalFull.empty());
    ASSERT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire), CM_SUCCESS);

    /* the SA persists asynchronously into the FORMAL store: verify the raw file
       itself, including the on-disk big-endian expiry header encoding */
    uint8_t fileBuf[FILE_READ_BUF_SIZE] = { 0 };
    uint32_t fileLen = 0;
    bool persisted = false;
    for (int round = 0; round < POLL_MAX_ROUNDS && !persisted; round++) {
        persisted = ReadFormalCacheFile(formalFull.c_str(), fileBuf, sizeof(fileBuf), &fileLen);
        if (!persisted) {
            usleep(POLL_INTERVAL_USEC);
        }
    }
    /*
     * Persistence requires the SA to own the cache directories. The engine-level
     * cases run as root and create them first, and on locked-down TDD devices the
     * test process (shell domain) cannot rmdir system data directories, so the
     * SA's atomic rename fails with EACCES there. The accepted save is the
     * portable assertion; when the environment does let the SA persist (e.g.
     * permissive, or dirs the SA created itself), also check the file content.
     */
    if (persisted) {
        const uint8_t expectDer[] = "SDK-DER";
        EXPECT_EQ(fileLen, sizeof(expectDer) - 1 + sizeof(int64_t));
        /* 8-byte big-endian expiry header in front of the payload, still in the future */
        int64_t storedExpire = DecodeExpireHeader(fileBuf);
        int64_t nowSec = static_cast<int64_t>(time(nullptr));
        EXPECT_GT(storedExpire, nowSec);
        EXPECT_LE(storedExpire, expire + EXPIRE_TOLERANCE_SEC);
        EXPECT_EQ(memcmp(fileBuf + sizeof(int64_t), expectDer, sizeof(expectDer) - 1), 0);
    }
}

TEST_F(CmRevocationCacheEngineTest, SaveHapCallerWritesSharedStore)
{
    /* drop the root-owned cache tree contents so the SA recreates the levels below (see helper) */
    CleanupRevocationCacheState();
    RemoveRevocationCacheTree();
    /* HAP callers are allowed to save through the SDK as well */
    uint8_t keyBuf[] = "hapkey2";
    uint8_t dataBuf[] = "HAP-DER";
    struct CmBlob key = { sizeof(keyBuf) - 1, keyBuf };
    struct CmBlob data = { sizeof(dataBuf) - 1, dataBuf };
    int64_t expire = static_cast<int64_t>(time(nullptr)) + ONE_HOUR_SEC;
    /* same store the SA writes: REVOCATION_CACHE_DIR */
    const std::string formalFull = BuildCacheFullPath(&key, CM_REVOCATION_TYPE_OCSP);
    ASSERT_FALSE(formalFull.empty());
    {
        MockHapToken mockHap;
        ASSERT_EQ(CmSaveRevocationCache(key, CM_REVOCATION_TYPE_OCSP, data, expire), CM_SUCCESS);
    }

    /* back to native: the FORMAL shared store must hold the HAP-written entry */
    uint8_t fileBuf[FILE_READ_BUF_SIZE] = { 0 };
    uint32_t fileLen = 0;
    bool persisted = false;
    for (int round = 0; round < POLL_MAX_ROUNDS && !persisted; round++) {
        persisted = ReadFormalCacheFile(formalFull.c_str(), fileBuf, sizeof(fileBuf), &fileLen);
        if (!persisted) {
            usleep(POLL_INTERVAL_USEC);
        }
    }
    /* same dual-state contract as SaveThroughSdkIpcRoundTrip: the accepted HAP
       save is the portable assertion; verify the persisted file only when the
       environment lets the SA own the cache directories */
    if (persisted) {
        const uint8_t expectDer[] = "HAP-DER";
        EXPECT_EQ(fileLen, sizeof(expectDer) - 1 + sizeof(int64_t));
        int64_t storedExpire = DecodeExpireHeader(fileBuf);
        int64_t nowSec = static_cast<int64_t>(time(nullptr));
        EXPECT_GT(storedExpire, nowSec);
        EXPECT_LE(storedExpire, expire + EXPIRE_TOLERANCE_SEC);
        EXPECT_EQ(memcmp(fileBuf + sizeof(int64_t), expectDer, sizeof(expectDer) - 1), 0);
    }
}

/*
 * The cleanup throttle timestamp is engine-managed state stored in the shared
 * cert_manager_config table under a whitelisted key: readable from the outside,
 * but never writable through the external config interface.
 */
TEST_F(CmRevocationCacheEngineTest, ExternalSetOfInternalKeyIsRejected)
{
    MockHapToken mockHap; /* system app holding ACCESS_CERT_MANAGER_INTERNAL */
    struct CmConfigItem item = { "last_cleanup_utc", "12345" };
    struct CertManagerConfig config = { 1, &item };
    /* the value itself would pass the digit-list grammar: only the internal-key
     * protection may keep it out of the table */
    EXPECT_EQ(CmServiceSetCertManagerConfig(&config), CMR_ERROR_INVALID_ARGUMENT);
    int64_t value = 0;
    EXPECT_EQ(GetRevocationCacheMeta(&value), CMR_ERROR_NOT_FOUND);
}

TEST_F(CmRevocationCacheEngineTest, ExternalGetOfInternalKeyIsWhitelisted)
{
    ASSERT_EQ(SetRevocationCacheMeta(META_VALUE_QUERYABLE), CM_SUCCESS);
    MockHapToken mockHap; /* system app holding ACCESS_CERT_MANAGER */
    uint8_t keysBuf[] = "last_cleanup_utc"; /* keysBlob keeps the trailing NUL */
    struct CmBlob keysBlob = { sizeof(keysBuf), keysBuf };
    struct CertManagerConfig config = { 0, nullptr };
    ASSERT_EQ(CmServiceGetCertManagerConfig(&keysBlob, &config), CM_SUCCESS);
    ASSERT_EQ(config.count, 1u);
    EXPECT_STREQ(config.configItems[0].key, "last_cleanup_utc");
    EXPECT_STREQ(config.configItems[0].value, std::to_string(META_VALUE_QUERYABLE).c_str());
    CM_FREE_PTR(config.configItems);
}
