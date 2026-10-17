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
#include "accesstoken_kit.h"
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
    auto tokenType = AccessTokenKit::GetTokenType(
        static_cast<AccessTokenID>(OHOS::IPCSkeleton::GetSelfTokenID()));
    return (tokenType == ATokenTypeEnum::TOKEN_HAP) || (tokenType == ATokenTypeEnum::TOKEN_NATIVE);
}

extern "C" CM_API_EXPORT int32_t CmRevocationCacheBuildBasePath(int32_t tokenType, char *basePath,
    uint32_t basePathLen)
{
    if (basePath == nullptr || basePathLen == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    const char *base = nullptr;
    if (tokenType == static_cast<int32_t>(ATokenTypeEnum::TOKEN_HAP)) {
        base = REVOCATION_CACHE_SANDBOX_BASE;
    } else if (tokenType == static_cast<int32_t>(ATokenTypeEnum::TOKEN_NATIVE)) {
        base = REVOCATION_CACHE_SERVICE_BASE;
    } else {
        return CMR_ERROR_REVOCATION_CACHE_CALLER_INVALID;  /* TOKEN_SHELL / unknown rejected */
    }
    if (strcpy_s(basePath, basePathLen, base) != EOK) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CM_SUCCESS;
}

static int32_t CmReadRevocationCacheFile(const char *fullPath, struct CmBlob *data)
{
    int fd = open(fullPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return CMR_ERROR_NOT_EXIST;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(int64_t)) {
        (void)close(fd);
        return CMR_ERROR_NOT_EXIST;
    }

    uint8_t buf8[sizeof(int64_t)] = { 0 };
    if (pread(fd, buf8, sizeof(buf8), 0) != (ssize_t)sizeof(buf8)) {
        (void)close(fd);
        return CMR_ERROR_READ_FILE_ERROR;
    }
    int64_t expire = CmRevocationCacheDecodeInt64Be(buf8);
    if (expire <= (int64_t)time(NULL)) {
        (void)close(fd);
        return CMR_ERROR_NOT_EXIST;
    }

    int64_t derLen = (int64_t)st.st_size - (int64_t)sizeof(int64_t);
    if (derLen <= 0 || derLen > MAX_OUT_BLOB_SIZE) {
        (void)close(fd);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    data->data = (uint8_t *)CmMalloc((size_t)derLen);
    if (data->data == nullptr) {
        (void)close(fd);
        return CMR_ERROR_MALLOC_FAIL;
    }
    data->size = (uint32_t)derLen;
    ssize_t rd = pread(fd, data->data, (size_t)derLen, (off_t)sizeof(int64_t));
    (void)close(fd);
    if (rd != (ssize_t)derLen) {
        (void)memset_s(data->data, data->size, 0, data->size);
        CmFree(data->data);
        data->data = nullptr;
        data->size = 0;
        return CMR_ERROR_READ_FILE_ERROR;
    }
    return CM_SUCCESS;
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
    int32_t ret = CmRevocationCacheBuildRelPath((uint32_t)type, &key, relPath, sizeof(relPath));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    auto tokenType = AccessTokenKit::GetTokenType(
        static_cast<AccessTokenID>(OHOS::IPCSkeleton::GetSelfTokenID()));
    char basePath[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmRevocationCacheBuildBasePath(static_cast<int32_t>(tokenType), basePath, sizeof(basePath));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    char fullPath[CERT_MAX_PATH_LEN] = { 0 };
    int n = snprintf_s(fullPath, sizeof(fullPath), sizeof(fullPath) - 1, "%s%s", basePath, relPath);
    if (n < 0) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CmReadRevocationCacheFile(fullPath, data);
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
