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

#include "cert_manager_api.h"

#include <cstdio>
#include <ctime>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access_token.h"
#include "accesstoken_compat_kit.h"
#include "ipc_skeleton.h"
#include "securec.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_revocation_cache.h"
#include "cm_ipc_client.h"

using namespace OHOS::Security::AccessToken;

static_assert(static_cast<int32_t>(ATokenTypeEnum::TOKEN_HAP) == CM_REVOCATION_TOKEN_TYPE_HAP,
    "CM_REVOCATION_TOKEN_TYPE_HAP must match ATokenTypeEnum::TOKEN_HAP");
static_assert(static_cast<int32_t>(ATokenTypeEnum::TOKEN_NATIVE) == CM_REVOCATION_TOKEN_TYPE_NATIVE,
    "CM_REVOCATION_TOKEN_TYPE_NATIVE must match ATokenTypeEnum::TOKEN_NATIVE");
static_assert(static_cast<int32_t>(ATokenTypeEnum::TOKEN_SHELL) == CM_REVOCATION_TOKEN_TYPE_SHELL,
    "CM_REVOCATION_TOKEN_TYPE_SHELL must match ATokenTypeEnum::TOKEN_SHELL");

static bool CmRevocationCacheIsCallerAllowed(void)
{
    auto tokenType = AccessTokenCompatKit::GetTokenTypeFlag(
        static_cast<AccessTokenID>(OHOS::IPCSkeleton::GetSelfTokenID()));
    return (tokenType == ATokenTypeEnum::TOKEN_HAP) || (tokenType == ATokenTypeEnum::TOKEN_NATIVE);
}

extern "C" CM_API_EXPORT int32_t CmRevocationCacheBuildBasePath(int32_t tokenType, char *basePath,
    uint32_t basePathLen)
{
    if (basePath == nullptr || basePathLen == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* one shared base for every allowed caller: the for-all-app location is
     * directly visible inside HAP sandboxes, so HAP and native readers use
     * the same path; shell and unknown tokens stay rejected */
    if (tokenType != static_cast<int32_t>(ATokenTypeEnum::TOKEN_HAP) &&
        tokenType != static_cast<int32_t>(ATokenTypeEnum::TOKEN_NATIVE)) {
        return CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID;  /* TOKEN_SHELL / unknown rejected */
    }
    if (strcpy_s(basePath, basePathLen, REVOCATION_CACHE_BASE) != EOK) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CM_SUCCESS;
}

/* sizes the open cache file with fstat: the stream position stays where
 * fopen left it, and only a regular file may be read; the expire header
 * must fit */
static int32_t GetCacheFileSize(FILE *fp, long *fileSize)
{
    struct stat st = { 0 };
    if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode)) {
        return CMR_ERROR_NOT_EXIST;
    }
    if (st.st_size < static_cast<off_t>(sizeof(int64_t))) {
        return CMR_ERROR_NOT_EXIST;
    }
    *fileSize = static_cast<long>(st.st_size);
    return CM_SUCCESS;
}

/* reads the expire header and the DER body; data is allocated only on success */
static int32_t ReadCacheContent(FILE *fp, long fileSize, struct CmBlob *data)
{
    uint8_t buf8[sizeof(int64_t)] = { 0 };
    if (fread(buf8, 1, sizeof(buf8), fp) != sizeof(buf8)) {
        return CMR_ERROR_READ_FILE_ERROR;
    }
    struct CmBlob expireBlob = { sizeof(buf8), buf8 };
    if (CmRevocationCacheDecodeInt64Be(&expireBlob) <= static_cast<int64_t>(time(nullptr))) {
        return CMR_ERROR_NOT_EXIST;
    }

    long derLen = fileSize - static_cast<long>(sizeof(int64_t));
    if (derLen <= 0 || derLen > static_cast<long>(MAX_OUT_BLOB_SIZE)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    data->data = static_cast<uint8_t *>(CmMalloc(static_cast<size_t>(derLen)));
    if (data->data == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    data->size = static_cast<uint32_t>(derLen);
    size_t rd = fread(data->data, 1, static_cast<size_t>(derLen), fp);
    if (rd != static_cast<size_t>(derLen)) {
        (void)memset_s(data->data, data->size, 0, data->size);
        CmFree(data->data);
        data->data = nullptr;
        data->size = 0;
        return CMR_ERROR_READ_FILE_ERROR;
    }
    return CM_SUCCESS;
}

static int32_t CmReadRevocationCacheFile(const char *basePath, const char *fullPath, struct CmBlob *data)
{
    /* normalize before use: a cache entry must never resolve outside its root,
     * which blocks symlinked entries planted in the shared directory */
    if (CmRevocationCacheCheckPathUnderRoot(basePath, fullPath) != CM_SUCCESS) {
        return CMR_ERROR_NOT_EXIST;
    }
    FILE *fp = fopen(fullPath, "rb");
    if (fp == nullptr) {
        return CMR_ERROR_NOT_EXIST;
    }
    long fileSize = 0;
    int32_t ret = GetCacheFileSize(fp, &fileSize);
    if (ret == CM_SUCCESS) {
        ret = ReadCacheContent(fp, fileSize, data);
    }
    (void)fclose(fp);
    return ret;
}

extern "C" CM_API_EXPORT int32_t CmGetRevocationCache(const struct CmBlob key, enum CmRevocationType type,
    struct CmBlob *data)
{
    if (data == nullptr) {
        return CMR_ERROR_NULL_POINTER;
    }
    data->data = nullptr;
    data->size = 0;

    if (type != CM_REVOCATION_TYPE_OCSP && type != CM_REVOCATION_TYPE_CRL) {
        return CMR_ERROR_INVALID_ARGUMENT_REVOCATION_TYPE;
    }
    if (CmCheckBlob(&key) != CM_SUCCESS || key.size > CM_REVOCATION_CACHE_KEY_MAX_LEN) {
        return CMR_ERROR_INVALID_ARGUMENT_CACHE_KEY;
    }

    char relPath[CERT_MAX_PATH_LEN] = { 0 };
    int32_t ret = CmRevocationCacheBuildRelPath(static_cast<uint32_t>(type), &key, relPath, sizeof(relPath));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    auto tokenType = AccessTokenCompatKit::GetTokenTypeFlag(
        static_cast<AccessTokenID>(OHOS::IPCSkeleton::GetSelfTokenID()));
    char basePath[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmRevocationCacheBuildBasePath(static_cast<int32_t>(tokenType), basePath, sizeof(basePath));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (CmRevocationCacheValidateRelPath(relPath) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char fullPath[CERT_MAX_PATH_LEN] = { 0 };
    int n = snprintf_s(fullPath, sizeof(fullPath), sizeof(fullPath) - 1, "%s%s", basePath, relPath);
    if (n < 0) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CmReadRevocationCacheFile(basePath, fullPath, data);
}

extern "C" CM_API_EXPORT void CmFreeRevocationCache(struct CmBlob *data)
{
    if (data != nullptr && data->data != nullptr) {
        (void)memset_s(data->data, data->size, 0, data->size);
        CmFree(data->data);
        data->data = nullptr;
        data->size = 0;
    }
}

extern "C" CM_API_EXPORT int32_t CmSaveRevocationCache(const struct CmBlob key, enum CmRevocationType type,
    const struct CmBlob data, int64_t expireTimeUTC)
{
    int64_t clamped = 0;
    int32_t ret = CmRevocationCacheValidateSaveParams(&key, static_cast<uint32_t>(type), &data,
        expireTimeUTC, &clamped);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    if (!CmRevocationCacheIsCallerAllowed()) {
        return CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID;
    }
    return CmClientSaveRevocationCache(&key, static_cast<uint32_t>(type), &data, clamped);
}
