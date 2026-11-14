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

#include "cmrevocationcacherdb_fuzzer.h"

#include <cstdint>
#include <cstring>

#include "cm_config_rdb.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_type.h"
#include "securec.h"

using namespace CmFuzzTest;
namespace {
    const uint32_t UINT32_COUNT = 4;

    void CopyStringTruncated(char *dst, uint32_t dstSize, const char *src)
    {
        size_t len = strlen(src);
        if (len >= dstSize) {
            len = dstSize - 1;
        }
        if (memcpy_s(dst, dstSize, src, len) != EOK) {
            dst[0] = '\0';
            return;
        }
        dst[len] = '\0';
    }

    /* parsed fuzz input; owned pointers are freed by FreeRevocationCacheInput */
    struct RevocationCacheInput {
        char *key = nullptr;
        char *type = nullptr;
        char *filePath = nullptr;
        int64_t expireTimeUtc = 0;
        uint32_t dataSize = 0;
    };

    void FreeRevocationCacheInput(struct RevocationCacheInput *in)
    {
        delete[] in->key;
        delete[] in->type;
        delete[] in->filePath;
        in->key = nullptr;
        in->type = nullptr;
        in->filePath = nullptr;
    }

    /* layout: [key string][type string][filePath string]
     * [expireTimeUtc int64][dataSize uint32][null-branch selector uint32] */
    bool ParseRevocationCacheInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct RevocationCacheInput *in)
    {
        if (!GetDynamicStringFromBuffer(myData, remainSize, offset, &in->key) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->type) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->filePath)) {
            return false;
        }
        if (*remainSize >= sizeof(int64_t)) {
            if (memcpy_s(&in->expireTimeUtc, sizeof(int64_t), myData + *offset,
                sizeof(int64_t)) != EOK) {
                in->expireTimeUtc = 0;
            }
            *offset += sizeof(int64_t);
            *remainSize -= sizeof(int64_t);
        }
        return GetUintFromBuffer(myData, remainSize, offset, &in->dataSize);
    }

    void DispatchRevocationCacheOp(const struct RevocationCacheInput &in, bool nullBranch)
    {
        /* both tables live in the shared cert_manager.db: create config first,
         * then the cache table (same ordering as the unit tests) */
        (void)CreateCertManagerConfigRdb();
        (void)CreateRevocationCacheRdb();

        struct RevocationCacheRecord record = {};
        record.expireTimeUtc = in.expireTimeUtc;
        record.dataSize = static_cast<uint64_t>(in.dataSize);
        CopyStringTruncated(record.key, sizeof(record.key), in.key);
        CopyStringTruncated(record.type, sizeof(record.type), in.type);
        CopyStringTruncated(record.filePath, sizeof(record.filePath), in.filePath);

        if (nullBranch) {
            /* invalid-argument branches of the write path */
            (void)InsertRevocationCacheRecord(nullptr);
            (void)DeleteRevocationCacheRecord(nullptr);
            (void)MarkRevocationCacheRecordDeleted(nullptr);
        } else {
            (void)InsertRevocationCacheRecord(&record);
            (void)MarkRevocationCacheRecordDeleted(in.filePath);
            (void)DeleteRevocationCacheRecord(in.filePath);
        }
    }
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT + sizeof(int64_t);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct RevocationCacheInput in = {};

        bool parsed = ParseRevocationCacheInput(myData, &remainSize, &offset, &in);
        if (parsed) {
            bool nullBranch = TenPercentChanceOfBeingTrue(myData, &remainSize, &offset);
            DispatchRevocationCacheOp(in, nullBranch);
        }

        FreeRevocationCacheInput(&in);
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
