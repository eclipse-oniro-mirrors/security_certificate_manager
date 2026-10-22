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

/*
 * Caller token types accepted by the revocation cache API. These values mirror
 * OHOS::Security::AccessToken::ATokenTypeEnum; the duplication is checked at
 * compile time by static_assert in cm_revocation_cache_api.cpp.
 */
#define CM_REVOCATION_TOKEN_TYPE_HAP     0
#define CM_REVOCATION_TOKEN_TYPE_NATIVE  1
#define CM_REVOCATION_TOKEN_TYPE_SHELL   2

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmRevocationCacheBuildRelPath(uint32_t type, const struct CmBlob *key,
    char *relPath, uint32_t relPathLen);

/*
 * Strict whitelist for cache sub paths: "<type>/<encoded>.cache" where
 * <type> is "ocsp" or "crl" and <encoded> is
 * 1..CM_REVOCATION_CACHE_KEY_HEX_MAX_LEN lowercase hex chars. Everything else
 * (absolute paths, "..", case variations, non-hex names) is rejected, so any
 * path built from a validated rel path stays inside the cache root.
 */
int32_t CmRevocationCacheValidateRelPath(const char *relPath);

/*
 * Normalizes rootDir and path with realpath() and requires the resolved path
 * to stay inside the resolved root. Fails closed when either path does not
 * exist or when the path escapes the root through ".." components or symlinks.
 */
int32_t CmRevocationCacheCheckPathUnderRoot(const char *rootDir, const char *path);

/*
 * Encodes v as an 8-byte big-endian value into the first sizeof(int64_t) bytes
 * of out8->data. The buffer length travels inside the blob: a NULL blob, a
 * NULL data buffer, or a blob smaller than sizeof(int64_t) bytes is a no-op.
 */
void CmRevocationCacheEncodeInt64Be(int64_t v, const struct CmBlob *out8);

/*
 * Decodes an 8-byte big-endian value from the first sizeof(int64_t) bytes of
 * in8->data. Returns 0 for a NULL blob, a NULL data buffer, or a blob smaller
 * than sizeof(int64_t) bytes.
 */
int64_t CmRevocationCacheDecodeInt64Be(const struct CmBlob *in8);

int32_t CmRevocationCacheValidateSaveParams(const struct CmBlob *key, uint32_t type,
    const struct CmBlob *data, int64_t expireTimeUtc, int64_t *clampedExpireUtc);

CM_API_EXPORT int32_t CmRevocationCacheBuildBasePath(int32_t tokenType, char *basePath,
    uint32_t basePathLen);

#ifdef __cplusplus
}
#endif

#endif /* CM_REVOCATION_CACHE_H */
