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

#include "cmservicerevocationcache_fuzzer.h"

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

#include "cert_manager_revocation_cache.h"
#include "cert_manager_storage.h"
#include "cm_config_rdb.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_revocation_cache_rdb.h"
#include "cm_type.h"
#include "securec.h"

using namespace CmFuzzTest;

namespace {
    const uint32_t UINT32_COUNT = 4;
    const int64_t ONE_HOUR_SEC = 3600;
    const int64_t ALREADY_EXPIRED_SEC = 10;
    /* expire offsets are folded into the next ~68 years: most offsets land in
     * the future (accepted or clamped), a zero offset lands exactly on the
     * expire <= now rejection boundary */
    const int64_t EXPIRE_OFFSET_MASK = 0x7FFFFFFF;
    /* the type folds onto OCSP, CRL and the rejected third value */
    const uint32_t REVOCATION_TYPE_COUNT = 3;
    /* small seed rows for the cleanup, orphan and re-save scenarios */
    const uint32_t SEED_DATA_SIZE_SMALL = 100;
    /* the far-future clamp scenario saves a hundred days out */
    const int64_t FUTURE_EXPIRE_DAYS = 100;
    const int64_t HOURS_PER_DAY = 24;

    /* save-pipeline scenarios: each round drives one specific engine path */
    enum CacheScenario {
        CACHE_SCENARIO_PLAIN_SAVE = 0,        /* plain save with the reporter off */
        CACHE_SCENARIO_REJECTIONS = 1,        /* invalid-argument and expired-expire rejections */
        CACHE_SCENARIO_CLEANUP_PASS = 2,      /* expired row plus zero meta: the cleanup pass */
        CACHE_SCENARIO_LOGICAL_EVICTION = 3,  /* unexpired oversized row: eviction plus reporter */
        CACHE_SCENARIO_PHYSICAL_EVICTION = 4, /* expired oversized row: the capacity pass */
        CACHE_SCENARIO_ORPHAN_SCAN = 5,       /* logically deleted row: the orphan scan */
        CACHE_SCENARIO_REPLACE_RESAVE = 6,    /* same key twice: the REPLACE insert */
        CACHE_SCENARIO_FAR_FUTURE = 7,        /* far-future expire: the clamp branch */
    };
    const uint32_t CACHE_SCENARIO_COUNT = CACHE_SCENARIO_FAR_FUTURE + 1;

    /* telemetry probe mirroring the unit tests: counts the eviction reports */
    void TestEvictReporter(uint64_t deletedTotalSize)
    {
        (void)deletedTotalSize;
    }

    /* current wall clock in epoch seconds, same base as time(); the
     * clock_gettime return is consumed by the condition itself and a zero
     * base simply keeps the run going when the clock cannot be read */
    int64_t GetNowTimeSec()
    {
        struct timespec ts = { 0, 0 };
        if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            return 0;
        }
        return static_cast<int64_t>(ts.tv_sec);
    }

    /* parsed fuzz input */
    struct RevocationCacheInput {
        struct CmBlob key = { 0, nullptr };
        uint32_t type = 0;
        struct CmBlob data = { 0, nullptr };
        int64_t rawExpire = 0;
        uint32_t scenario = 0;
    };

    /* seed a raw cache row so the cleanup/eviction passes have shaped input:
     * hex key, type string and rel path must match the layout the save
     * pipeline itself produces (see the engine unit tests) */
    void SeedCacheRecord(const char *keyHex, const char *typeStr, const char *relPath,
        int64_t expireTimeUtc, uint64_t dataSize)
    {
        struct RevocationCacheRecord rec;
        (void)memset_s(&rec, sizeof(rec), 0, sizeof(rec));
        if (strncpy_s(rec.key, sizeof(rec.key), keyHex, strlen(keyHex)) != EOK ||
            strncpy_s(rec.type, sizeof(rec.type), typeStr, strlen(typeStr)) != EOK ||
            strncpy_s(rec.filePath, sizeof(rec.filePath), relPath, strlen(relPath)) != EOK) {
            return; /* malformed seed: skip the insert */
        }
        rec.expireTimeUtc = expireTimeUtc;
        rec.dataSize = dataSize;
        (void)InsertRevocationCacheRecord(&rec);
    }

    /* remove every cache file and row left by this or previous rounds: keeps
     * the capacity accounting and the RDB table bounded across long runs */
    void CleanupCacheState()
    {
        char **paths = nullptr;
        uint32_t count = 0;
        if (QueryAllRevocationCacheFilePaths(&paths, &count) != CM_SUCCESS || paths == nullptr) {
            return;
        }
        for (uint32_t i = 0; i < count; i++) {
            char full[PATH_MAX] = { 0 };
            if (snprintf_s(full, sizeof(full), sizeof(full) - 1, "%s%s", REVOCATION_CACHE_BASE,
                paths[i]) >= 0) {
                (void)unlink(full);
            }
            (void)DeleteRevocationCacheRecord(paths[i]);
        }
        FreeRevocationCacheFilePaths(paths, count);
    }

    /* scenario: invalid-argument and expired-expire rejections */
    void RunRejectionsScenario(const struct RevocationCacheInput &in, int64_t now, int64_t expire)
    {
        (void)CmServiceSaveRevocationCache(nullptr, in.type, &in.data, expire);
        (void)CmServiceSaveRevocationCache(&in.key, in.type, nullptr, expire);
        (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, now - ALREADY_EXPIRED_SEC);
    }

    /* scenario: an expired row plus a zero meta, so the save runs the cleanup pass */
    void RunCleanupPassScenario(const struct RevocationCacheInput &in, int64_t now, int64_t expire)
    {
        (void)SetRevocationCacheMeta(0);
        SeedCacheRecord("ee998877", "ocsp", "ocsp/ee998877.cache", now - ALREADY_EXPIRED_SEC,
            SEED_DATA_SIZE_SMALL);
        (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
    }

    /* scenario: an unexpired oversized row, driving the logical eviction plus the reporter */
    void RunLogicalEvictionScenario(const struct RevocationCacheInput &in, int64_t now, int64_t expire)
    {
        CmSetRevocationEvictReporter(TestEvictReporter);
        (void)SetRevocationCacheMeta(now); /* keep the cleanup pass away */
        SeedCacheRecord("65766931", "ocsp", "ocsp/65766931.cache", now + ONE_HOUR_SEC,
            REVOCATION_CACHE_MAX_TOTAL_BYTES);
        (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
    }

    /* scenario: an expired oversized row, driving the physical eviction of the capacity pass */
    void RunPhysicalEvictionScenario(const struct RevocationCacheInput &in, int64_t now, int64_t expire)
    {
        (void)SetRevocationCacheMeta(now);
        SeedCacheRecord("cafe0000", "ocsp", "ocsp/cafe0000.cache", now - ALREADY_EXPIRED_SEC,
            REVOCATION_CACHE_MAX_TOTAL_BYTES);
        (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
    }

    /* scenario: a logically deleted row, so the orphan scan must keep its file */
    void RunOrphanScanScenario(const struct RevocationCacheInput &in, int64_t now, int64_t expire)
    {
        (void)SetRevocationCacheMeta(0);
        SeedCacheRecord("6b657074", "ocsp", "ocsp/6b657074.cache", now + ONE_HOUR_SEC,
            SEED_DATA_SIZE_SMALL);
        (void)MarkRevocationCacheRecordDeleted("ocsp/6b657074.cache");
        (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
    }

    /* drive one save through the whole engine pipeline: validation, cleanup
     * pass, durable write, capacity eviction and the RDB row insert */
    void DispatchRevocationCacheScenario(const struct RevocationCacheInput &in, int64_t now,
        int64_t expire)
    {
        switch (in.scenario % CACHE_SCENARIO_COUNT) {
            case CACHE_SCENARIO_REJECTIONS:
                RunRejectionsScenario(in, now, expire);
                break;
            case CACHE_SCENARIO_CLEANUP_PASS:
                RunCleanupPassScenario(in, now, expire);
                break;
            case CACHE_SCENARIO_LOGICAL_EVICTION:
                RunLogicalEvictionScenario(in, now, expire);
                break;
            case CACHE_SCENARIO_PHYSICAL_EVICTION:
                RunPhysicalEvictionScenario(in, now, expire);
                break;
            case CACHE_SCENARIO_ORPHAN_SCAN:
                RunOrphanScanScenario(in, now, expire);
                break;
            case CACHE_SCENARIO_REPLACE_RESAVE:
                CmSetRevocationEvictReporter(nullptr);
                (void)SetRevocationCacheMeta(now);
                (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
                (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
                break;
            case CACHE_SCENARIO_FAR_FUTURE:
                (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data,
                    now + FUTURE_EXPIRE_DAYS * HOURS_PER_DAY * ONE_HOUR_SEC);
                break;
            case CACHE_SCENARIO_PLAIN_SAVE:
            default:
                CmSetRevocationEvictReporter(nullptr);
                (void)CmServiceSaveRevocationCache(&in.key, in.type, &in.data, expire);
                break;
        }
    }
}

namespace OHOS {
    /* drive the engine-level revocation cache (cert_manager_revocation_cache.c):
     * every scenario funnels through CmServiceSaveRevocationCache and covers
     * the validation, cleanup, orphan, eviction and reporting paths */
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(struct CmBlob) * 2 + sizeof(uint32_t) * UINT32_COUNT + sizeof(int64_t);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        struct RevocationCacheInput in;
        if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &in.key) ||
            !GetUintFromBuffer(myData, &remainSize, &offset, &in.type) ||
            !GetCmBlobFromBuffer(myData, &remainSize, &offset, &in.data)) {
            CmFree(myData);
            return false;
        }
        if (remainSize >= sizeof(int64_t)) {
            if (memcpy_s(&in.rawExpire, sizeof(int64_t), myData + offset, sizeof(int64_t)) != EOK) {
                in.rawExpire = 0; /* a failed copy keeps the zero expire */
            }
            offset += sizeof(int64_t);
            remainSize -= sizeof(int64_t);
        }
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &in.scenario)) {
            CmFree(myData);
            return false;
        }

        /* both tables live in the shared cert_manager.db: the cleanup meta row
         * lives in the config table, the cache rows in their own table */
        (void)CreateCertManagerConfigRdb();
        (void)CreateRevocationCacheRdb();

        int64_t now = GetNowTimeSec();
        int64_t expire = now + (in.rawExpire & EXPIRE_OFFSET_MASK);
        /* the type folds onto OCSP, CRL and the rejected third value */
        in.type = in.type % REVOCATION_TYPE_COUNT;

        DispatchRevocationCacheScenario(in, now, expire);

        CleanupCacheState();
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
