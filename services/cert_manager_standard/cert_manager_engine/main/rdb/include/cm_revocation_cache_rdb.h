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

#ifndef CM_REVOCATION_CACHE_RDB_H
#define CM_REVOCATION_CACHE_RDB_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* type string buffer: "ocsp" / "crl" plus headroom */
#define CM_REVOCATION_CACHE_TYPE_LEN 8
/* rel-path buffer: <type>/<prefix>/<encoded>.cache with the 128-char encoded name */
#define CM_REVOCATION_CACHE_FILE_PATH_LEN 256

/* expireTimeUtc stays first: scalar-led aggregates keep the "= { 0 }" idiom warning-free */
struct RevocationCacheRecord {
    int64_t expireTimeUtc;
    char key[CM_REVOCATION_CACHE_KEY_HEX_MAX_LEN + 1];
    char type[CM_REVOCATION_CACHE_TYPE_LEN];
    char filePath[CM_REVOCATION_CACHE_FILE_PATH_LEN];
    uint64_t dataSize;
};

int32_t CreateRevocationCacheRdb(void);

int32_t InsertRevocationCacheRecord(const struct RevocationCacheRecord *record);

int32_t DeleteRevocationCacheRecord(const char *filePath);

int32_t QueryRevocationCacheSumSize(uint64_t *totalSize);

int32_t QueryRevocationCacheRecordByExpireAsc(struct RevocationCacheRecord *record);

int32_t QueryExpiredRevocationCacheRecord(int64_t nowUtc, struct RevocationCacheRecord *record);

int32_t QueryAllRevocationCacheFilePaths(char ***paths, uint32_t *count);

void FreeRevocationCacheFilePaths(char **paths, uint32_t count);

int32_t GetRevocationCacheMeta(int64_t *value);

int32_t SetRevocationCacheMeta(int64_t value);

int32_t DeleteRevocationCacheMeta(void);

#ifdef __cplusplus
}
#endif

#endif /* CM_REVOCATION_CACHE_RDB_H */
