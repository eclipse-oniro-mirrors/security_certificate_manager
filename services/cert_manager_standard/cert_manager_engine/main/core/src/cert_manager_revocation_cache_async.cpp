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

#include "cert_manager_revocation_cache.h"

#include <thread>

#include "securec.h"

#include "cert_manager_mem.h"
#include "cm_error_code.h"

extern "C" int32_t CmServiceSaveRevocationCache(const struct CmBlob *key, uint32_t type, const struct CmBlob *data,
    int64_t expireTimeUtc);

static int32_t DeepCopyBlob(const struct CmBlob *src, struct CmBlob *dst)
{
    if (src == nullptr || dst == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    dst->data = nullptr;
    dst->size = 0;
    if (src->data == nullptr || src->size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    dst->data = (uint8_t *)CMMalloc(src->size);
    if (dst->data == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(dst->data, src->size, src->data, src->size) != EOK) {
        CMFree(dst->data);
        dst->data = nullptr;
        dst->size = 0;
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    dst->size = src->size;
    return CM_SUCCESS;
}

extern "C" int32_t CmRunSaveRevocationCacheAsync(const struct CmBlob *key, uint32_t type, const struct CmBlob *data,
    int64_t expireTimeUtc)
{
    if (key == nullptr || data == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CmBlob keyCopy = { 0, nullptr };
    struct CmBlob dataCopy = { 0, nullptr };
    int32_t ret = DeepCopyBlob(key, &keyCopy);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = DeepCopyBlob(data, &dataCopy);
    if (ret != CM_SUCCESS) {
        CMFree(keyCopy.data);
        keyCopy.data = nullptr;
        keyCopy.size = 0;
        return ret;
    }

    std::thread w([keyCopy, type, dataCopy, expireTimeUtc]() {
        (void)CmServiceSaveRevocationCache(&keyCopy, type, &dataCopy, expireTimeUtc);
        (void)memset_s(keyCopy.data, keyCopy.size, 0, keyCopy.size);
        (void)memset_s(dataCopy.data, dataCopy.size, 0, dataCopy.size);
        CMFree(keyCopy.data);
        CMFree(dataCopy.data);
    });
    w.detach();
    return CM_SUCCESS;
}
