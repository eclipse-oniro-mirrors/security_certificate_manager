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

#include "cm_log.h"
#include "cm_type.h"
#include "securec.h"

#define CM_REVOCATION_B64_INPUT_GROUP_BYTES 3
#define CM_REVOCATION_B64_OUTPUT_GROUP_CHARS 4
#define CM_REVOCATION_B64_BITS_PER_CHAR 6
#define CM_REVOCATION_B64_CHAR_MASK ((1U << CM_REVOCATION_B64_BITS_PER_CHAR) - 1)
/* worst case unpadded output length for a CM_REVOCATION_CACHE_KEY_MAX_LEN byte key */
#define CM_REVOCATION_B64_MAX_LEN \
    (((CM_REVOCATION_CACHE_KEY_MAX_LEN + CM_REVOCATION_B64_INPUT_GROUP_BYTES - 1) / \
    CM_REVOCATION_B64_INPUT_GROUP_BYTES) * CM_REVOCATION_B64_OUTPUT_GROUP_CHARS)

static bool CmRevocationCacheIsTypeValid(uint32_t type)
{
    return (type == CM_REVOCATION_TYPE_OCSP) || (type == CM_REVOCATION_TYPE_CRL);
}

/* RFC 4648 section 5 base64url without padding: the encoded key becomes the
 * storage file name, so the URL-safe alphabet keeps '/' out of derived paths. */
static int32_t CmRevocationCacheBase64UrlEncode(const uint8_t *data, uint32_t size,
    char *out, uint32_t outLen)
{
    uint32_t fullGroups = size / CM_REVOCATION_B64_INPUT_GROUP_BYTES;
    uint32_t tail = size % CM_REVOCATION_B64_INPUT_GROUP_BYTES;
    uint32_t need = fullGroups * CM_REVOCATION_B64_OUTPUT_GROUP_CHARS + ((tail == 0) ? 0 : (tail + 1));
    if (outLen < need + 1) { /* room for the terminator */
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    static const char b64UrlChars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    /* same MSB-first slicing as CmBase64Encode in cm_ukey_dialog_common.cpp, but
     * with the URL-safe alphabet and no padding: the result is a file name */
    uint32_t o = 0;
    uint32_t i = 0;
    for (; i + CM_REVOCATION_B64_INPUT_GROUP_BYTES <= size; i += CM_REVOCATION_B64_INPUT_GROUP_BYTES) {
        uint32_t v = 0;
        for (uint32_t b = 0; b < CM_REVOCATION_B64_INPUT_GROUP_BYTES; b++) {
            v = (v << CM_BITS_PER_BYTE) | data[i + b];
        }
        for (uint32_t c = CM_REVOCATION_B64_OUTPUT_GROUP_CHARS; c > 0; c--) {
            out[o++] = b64UrlChars[(v >> ((c - 1) * CM_REVOCATION_B64_BITS_PER_CHAR)) &
                CM_REVOCATION_B64_CHAR_MASK];
        }
    }
    if (tail != 0) {
        uint32_t v = 0;
        for (uint32_t b = 0; b < tail; b++) {
            v = (v << CM_BITS_PER_BYTE) | data[i + b];
        }
        /* left-align the tail group so it slices exactly like a full group */
        v <<= (CM_REVOCATION_B64_INPUT_GROUP_BYTES - tail) * CM_BITS_PER_BYTE;
        uint32_t tailChars = tail + 1; /* 1 byte -> 2 chars, 2 bytes -> 3 chars */
        for (uint32_t c = CM_REVOCATION_B64_OUTPUT_GROUP_CHARS;
            c > CM_REVOCATION_B64_OUTPUT_GROUP_CHARS - tailChars; c--) {
            out[o++] = b64UrlChars[(v >> ((c - 1) * CM_REVOCATION_B64_BITS_PER_CHAR)) &
                CM_REVOCATION_B64_CHAR_MASK];
        }
    }
    out[o] = '\0';
    return CM_SUCCESS;
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

    /* spec: the key itself is only base64-encoded to build the file name; hashing
     * long or raw key material is the caller's job, see the CmSaveRevocationCache comment */
    char encoded[CM_REVOCATION_B64_MAX_LEN + 1] = { 0 };
    if (CmRevocationCacheBase64UrlEncode(key->data, key->size, encoded, sizeof(encoded)) != CM_SUCCESS) {
        CM_LOG_E("revocation cache key encode buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    const char *prefix = (type == CM_REVOCATION_TYPE_OCSP) ? "ocsp" : "crl";
    int ret = snprintf_s(relPath, relPathLen, relPathLen - 1, "%s/%c%c/%s.cache", prefix,
        encoded[0], encoded[1], encoded);
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
