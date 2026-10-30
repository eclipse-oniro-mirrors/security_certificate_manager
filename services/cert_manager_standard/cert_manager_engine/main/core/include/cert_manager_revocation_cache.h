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

#ifndef CERT_MANAGER_REVOCATION_CACHE_H
#define CERT_MANAGER_REVOCATION_CACHE_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmServiceSaveRevocationCache(const struct CmBlob *key, uint32_t type, const struct CmBlob *data,
    int64_t expireTimeUtc);

int32_t CmRunSaveRevocationCacheAsync(const struct CmBlob *key, uint32_t type, const struct CmBlob *data,
    int64_t expireTimeUtc);

/* telemetry hook: invoked with the total DATA_SIZE of the IS_DELETED = 1 rows
 * right after a capacity eviction dropped unexpired entries; the SA registers
 * the hisysevent adapter at startup, NULL (the default) disables reporting */
typedef void (*CmRevocationEvictReporter)(uint64_t deletedTotalSize);

void CmSetRevocationEvictReporter(CmRevocationEvictReporter reporter);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_REVOCATION_CACHE_H */
