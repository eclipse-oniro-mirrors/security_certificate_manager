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

#ifndef CM_REVOCATION_CACHE_H
#define CM_REVOCATION_CACHE_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmRevocationCacheBuildRelPath(uint32_t type, const struct CmBlob *key,
    char *relPath, uint32_t relPathLen);

void CmRevocationCacheEncodeInt64Be(int64_t v, uint8_t *out8);

int64_t CmRevocationCacheDecodeInt64Be(const uint8_t *in8);

int32_t CmRevocationCacheValidateSaveParams(const struct CmBlob *key, uint32_t type,
    const struct CmBlob *data, int64_t expireTimeUtc, int64_t *clampedExpireUtc);

CM_API_EXPORT int32_t CmRevocationCacheBuildBasePath(int32_t tokenType, char *basePath,
    uint32_t basePathLen);

#ifdef __cplusplus
}
#endif

#endif /* CM_REVOCATION_CACHE_H */
