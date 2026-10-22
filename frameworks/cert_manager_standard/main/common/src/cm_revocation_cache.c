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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "cm_log.h"
#include "cm_type.h"
#include "securec.h"

#define CM_REVOCATION_HEX_CHARS_PER_BYTE 2
#define CM_REVOCATION_HEX_BITS_PER_NIBBLE 4
#define CM_REVOCATION_HEX_NIBBLE_MASK 0x0F

static bool CmRevocationCacheIsTypeValid(uint32_t type)
{
    return (type == CM_REVOCATION_TYPE_OCSP) || (type == CM_REVOCATION_TYPE_CRL);
}

/* lowercase hex: the encoded key becomes the storage file name, and the hex
 * alphabet can never introduce '/' into derived paths */
static int32_t CmRevocationCacheHexEncode(const uint8_t *data, uint32_t size, char *out, uint32_t outLen)
{
    uint32_t need = size * CM_REVOCATION_HEX_CHARS_PER_BYTE;
    if (outLen < need + 1) { /* room for the terminator */
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    static const char hexChars[] = "0123456789abcdef";
    for (uint32_t i = 0; i < size; i++) {
        out[i * CM_REVOCATION_HEX_CHARS_PER_BYTE] = hexChars[data[i] >> CM_REVOCATION_HEX_BITS_PER_NIBBLE];
        out[i * CM_REVOCATION_HEX_CHARS_PER_BYTE + 1] = hexChars[data[i] & CM_REVOCATION_HEX_NIBBLE_MASK];
    }
    out[need] = '\0';
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

    /* spec: the key itself is only hex-encoded to build the file name; hashing
     * long or raw key material is the caller's job, see the CmSaveRevocationCache comment */
    char encoded[CM_REVOCATION_CACHE_KEY_HEX_MAX_LEN + 1] = { 0 };
    if (CmRevocationCacheHexEncode(key->data, key->size, encoded, sizeof(encoded)) != CM_SUCCESS) {
        CM_LOG_E("revocation cache key encode buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    const char *prefix = (type == CM_REVOCATION_TYPE_OCSP) ? "ocsp" : "crl";
    int ret = snprintf_s(relPath, relPathLen, relPathLen - 1, "%s/%s.cache", prefix, encoded);
    if (ret < 0) {
        CM_LOG_E("revocation cache rel path buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CM_SUCCESS;
}

static bool CmRevocationCacheIsHexChar(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int32_t CmRevocationCacheValidateRelPath(const char *relPath)
{
    if ((relPath == NULL) || (relPath[0] == '\0')) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* "ocsp" or "crl", then the encoded name directly: the store dir holds
     * files only, any deeper hierarchy (including the retired fanout layout)
     * is rejected here */
    const char *name = NULL;
    if (strncmp(relPath, "ocsp/", strlen("ocsp/")) == 0) {
        name = relPath + strlen("ocsp/");
    } else if (strncmp(relPath, "crl/", strlen("crl/")) == 0) {
        name = relPath + strlen("crl/");
    } else {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strchr(name, '/') != NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    size_t nameLen = strlen(name);
    const size_t suffixLen = sizeof(".cache") - 1;
    if ((nameLen <= suffixLen) || (nameLen > (size_t)CM_REVOCATION_CACHE_KEY_HEX_MAX_LEN + suffixLen)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strcmp(name + nameLen - suffixLen, ".cache") != 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i < nameLen - suffixLen; ++i) {
        if (!CmRevocationCacheIsHexChar(name[i])) {
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    return CM_SUCCESS;
}

int32_t CmRevocationCacheCheckPathUnderRoot(const char *rootDir, const char *path)
{
    if ((rootDir == NULL) || (path == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    char realRoot[PATH_MAX] = {0};
    if (realpath(rootDir, realRoot) == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    char realPath[PATH_MAX] = {0};
    if (realpath(path, realPath) == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    size_t rootLen = strlen(realRoot);
    if ((strncmp(realPath, realRoot, rootLen) != 0) ||
        ((realPath[rootLen] != '/') && (realPath[rootLen] != '\0'))) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

void CmRevocationCacheEncodeInt64Be(int64_t v, const struct CmBlob *out8)
{
    if ((out8 == NULL) || (out8->data == NULL) || (out8->size < sizeof(int64_t))) {
        return;
    }
    uint64_t u = (uint64_t)v;
    for (uint32_t i = 0; i < sizeof(int64_t); ++i) {
        out8->data[i] = (uint8_t)((u >> ((sizeof(int64_t) - 1 - i) * CM_BITS_PER_BYTE)) & 0xFF);
    }
}

int64_t CmRevocationCacheDecodeInt64Be(const struct CmBlob *in8)
{
    if ((in8 == NULL) || (in8->data == NULL) || (in8->size < sizeof(int64_t))) {
        return 0;
    }
    uint64_t u = 0;
    for (uint32_t i = 0; i < sizeof(int64_t); ++i) {
        u = (u << CM_BITS_PER_BYTE) | in8->data[i];
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
