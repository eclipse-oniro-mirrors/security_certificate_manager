/**
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

#include "cmrevocationcacherdbquery_fuzzer.h"

#include <cstdint>

#include "cm_config_rdb.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "securec.h"

using namespace CmFuzzTest;
namespace {
    const uint32_t UINT32_COUNT = 4;
    /* three fuzzed int64 fields: nowUtc / metaValue / seedExpireTimeUtc */
    const uint32_t INT64_FIELD_COUNT = 3;

    /* one fixed seed row: (KEY, TYPE) REPLACE keeps the table size constant
     * across long fuzz runs while the query arguments stay fuzzed */
    const char *SEED_KEY = "fuzzqueryseed";
    const char *SEED_TYPE = "ocsp";
    const char *SEED_FILE_PATH = "/data/local/tmp/cm_fuzz_seed.cache";

    /* parsed fuzz input; owned pointers are freed by FreeRevocationCacheQueryInput */
    struct RevocationCacheQueryInput {
        char *key = nullptr;
        char *type = nullptr;
        int64_t nowUtc = 0;
        int64_t metaValue = 0;
        int64_t seedExpireTimeUtc = 0;
        uint32_t seedDataSize = 0;
    };

    void FreeRevocationCacheQueryInput(struct RevocationCacheQueryInput *in)
    {
        delete[] in->key;
        delete[] in->type;
        in->key = nullptr;
        in->type = nullptr;
    }

    /* layout: [key string][type string]
     * [nowUtc int64][metaValue int64][seedExpireTimeUtc int64][seedDataSize uint32] */
    bool ParseRevocationCacheQueryInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct RevocationCacheQueryInput *in)
    {
        if (!GetDynamicStringFromBuffer(myData, remainSize, offset, &in->key) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->type)) {
            return false;
        }
        if (*remainSize >= sizeof(int64_t) * INT64_FIELD_COUNT) {
            if (memcpy_s(&in->nowUtc, sizeof(int64_t), myData + *offset,
                sizeof(int64_t)) != EOK) {
                in->nowUtc = 0;
            }
            *offset += sizeof(int64_t);
            if (memcpy_s(&in->metaValue, sizeof(int64_t), myData + *offset,
                sizeof(int64_t)) != EOK) {
                in->metaValue = 0;
            }
            *offset += sizeof(int64_t);
            if (memcpy_s(&in->seedExpireTimeUtc, sizeof(int64_t), myData + *offset,
                sizeof(int64_t)) != EOK) {
                in->seedExpireTimeUtc = 0;
            }
            *offset += sizeof(int64_t);
            *remainSize -= sizeof(int64_t) * INT64_FIELD_COUNT;
        }
        return GetUintFromBuffer(myData, remainSize, offset, &in->seedDataSize);
    }

    /* seed row + the whole query/meta surface of the revocation cache */
    void RunRevocationCacheQuery(const struct RevocationCacheQueryInput &in)
    {
        (void)CreateCertManagerConfigRdb();
        (void)CreateRevocationCacheRdb();

        struct RevocationCacheRecord seed = {};
        seed.expireTimeUtc = in.seedExpireTimeUtc;
        seed.dataSize = static_cast<uint64_t>(in.seedDataSize);
        (void)strcpy_s(seed.key, sizeof(seed.key), SEED_KEY);
        (void)strcpy_s(seed.type, sizeof(seed.type), SEED_TYPE);
        (void)strcpy_s(seed.filePath, sizeof(seed.filePath), SEED_FILE_PATH);
        (void)InsertRevocationCacheRecord(&seed);

        /* active sum excludes the queried (key, type) row itself */
        uint64_t totalSize = 0;
        (void)QueryRevocationCacheActiveSumSize(in.key, in.type, &totalSize);
        (void)QueryRevocationCacheDeletedSumSize(&totalSize);

        struct RevocationCacheRecord candidate = {};
        (void)QueryRevocationCacheEvictCandidate(in.key, in.type, &candidate);
        (void)QueryExpiredRevocationCacheRecord(in.nowUtc, &candidate);

        char **paths = nullptr;
        uint32_t pathCount = 0;
        if (QueryAllRevocationCacheFilePaths(&paths, &pathCount) == CM_SUCCESS) {
            FreeRevocationCacheFilePaths(paths, pathCount);
        }

        /* meta triple: stored in cert_manager_config as a decimal string */
        (void)SetRevocationCacheMeta(in.metaValue);
        int64_t metaOut = 0;
        (void)GetRevocationCacheMeta(&metaOut);
        (void)DeleteRevocationCacheMeta();

        /* invalid-argument branches of the query surface */
        (void)QueryRevocationCacheActiveSumSize(nullptr, nullptr, nullptr);
        (void)QueryRevocationCacheDeletedSumSize(nullptr);
        (void)QueryRevocationCacheEvictCandidate(nullptr, nullptr, nullptr);
        (void)QueryAllRevocationCacheFilePaths(nullptr, nullptr);
        (void)GetRevocationCacheMeta(nullptr);
    }
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT + sizeof(int64_t) * 3;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct RevocationCacheQueryInput in = {};

        bool parsed = ParseRevocationCacheQueryInput(myData, &remainSize, &offset, &in);
        if (parsed) {
            RunRevocationCacheQuery(in);
        }

        FreeRevocationCacheQueryInput(&in);
        CmFree(myData);
        return parsed;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
