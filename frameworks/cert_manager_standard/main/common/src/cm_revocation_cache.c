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

#include "cm_revocation_cache.h"

#include <stdio.h>
#include <time.h>

#include "cm_sha256.h"

#include "cm_log.h"
#include "cm_type.h"
#include "securec.h"

#define CM_REVOCATION_HEX_CHARS_PER_BYTE 2
#define CM_REVOCATION_NIBBLE_BITS 4 /* hex half-byte bits */
#define CM_REVOCATION_HEX_LEN (CM_SHA256_HASH_LEN * CM_REVOCATION_HEX_CHARS_PER_BYTE)

static bool CmRevocationCacheIsTypeValid(uint32_t type)
{
    return (type == CM_REVOCATION_TYPE_OCSP) || (type == CM_REVOCATION_TYPE_CRL);
}

int32_t CmRevocationCacheBuildRelPath(uint32_t type, const struct CmBlob *key,
    char *relPath, uint32_t relPathLen)
{
    if (!CmRevocationCacheIsTypeValid(type)) {
        CM_LOG_E("invalid revocation type: %u", type);
        return CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE;
    }
    if ((CmCheckBlob(key) != CM_SUCCESS) || (key->size > CM_REVOCATION_CACHE_KEY_MAX_LEN)) {
        CM_LOG_E("invalid revocation cache key");
        return CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY;
    }
    if ((relPath == NULL) || (relPathLen == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint8_t md[CM_SHA256_HASH_LEN] = { 0 };
    if (CmSha256(key->data, key->size, md) != CM_SUCCESS) {
        CM_LOG_E("failed to digest revocation cache key");
        /* legacy error code kept for compatibility; no OpenSSL involved anymore */
        return CMR_ERROR_OPENSSL_FAIL;
    }

    static const char hexDigits[] = "0123456789abcdef";
    char hex[CM_REVOCATION_HEX_LEN + 1] = { 0 };
    for (uint32_t i = 0; i < CM_SHA256_HASH_LEN; ++i) {
        hex[i * CM_REVOCATION_HEX_CHARS_PER_BYTE] = hexDigits[(md[i] >> CM_REVOCATION_NIBBLE_BITS) & 0x0F];
        hex[i * CM_REVOCATION_HEX_CHARS_PER_BYTE + 1] = hexDigits[md[i] & 0x0F];
    }

    const char *prefix = (type == CM_REVOCATION_TYPE_OCSP) ? "ocsp" : "crl";
    int ret = snprintf_s(relPath, relPathLen, relPathLen - 1, "%s/%c%c/%s.cache", prefix, hex[0], hex[1], hex);
    if (ret < 0) {
        CM_LOG_E("revocation cache rel path buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CM_SUCCESS;
}

void CmRevocationCacheEncodeInt64Be(int64_t v, uint8_t *out8)
{
    if (out8 == NULL) {
        return;
    }
    uint64_t u = (uint64_t)v;
    for (uint32_t i = 0; i < sizeof(int64_t); ++i) {
        out8[i] = (uint8_t)((u >> ((sizeof(int64_t) - 1 - i) * CM_BITS_PER_BYTE)) & 0xFF);
    }
}

int64_t CmRevocationCacheDecodeInt64Be(const uint8_t *in8)
{
    if (in8 == NULL) {
        return 0;
    }
    uint64_t u = 0;
    for (uint32_t i = 0; i < sizeof(int64_t); ++i) {
        u = (u << CM_BITS_PER_BYTE) | in8[i];
    }
    return (int64_t)u;
}

int32_t CmRevocationCacheValidateSaveParams(const struct CmBlob *key, uint32_t type,
    const struct CmBlob *data, int64_t expireTimeUtc, int64_t *clampedExpireUtc)
{
    if (clampedExpireUtc == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (!CmRevocationCacheIsTypeValid(type)) {
        return CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE;
    }
    if ((CmCheckBlob(key) != CM_SUCCESS) || (key->size > CM_REVOCATION_CACHE_KEY_MAX_LEN)) {
        return CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY;
    }
    if ((CmCheckBlob(data) != CM_SUCCESS) || (data->size > CM_REVOCATION_CACHE_DATA_MAX_LEN)) {
        return CMR_ERROR_INVALID_ARGUMENT_CACHE_DATA;
    }

    int64_t now = (int64_t)time(NULL);
    if (expireTimeUtc <= now) {
        return CMR_ERROR_INVALID_ARGUMENT_EXPIRE_TIME;
    }
    int64_t maxExpireUtc = now + CM_REVOCATION_CACHE_MAX_VALID_SEC;
    *clampedExpireUtc = (expireTimeUtc > maxExpireUtc) ? maxExpireUtc : expireTimeUtc;
    return CM_SUCCESS;
}
