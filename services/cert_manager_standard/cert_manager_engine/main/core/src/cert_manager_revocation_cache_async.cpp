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

#include <pthread.h>

#include "securec.h"

#include "cert_manager_mem.h"
#include "cm_error_code.h"
#include "cm_log.h"

/*
 * Upper bound of concurrent detached save worker threads. Beyond this limit the
 * save is executed synchronously on the caller thread to apply back-pressure,
 * so the service can never be driven into unbounded thread/memory growth by a
 * caller flooding CmSaveRevocationCache.
 */
static const uint32_t REVOCATION_CACHE_MAX_CONCURRENT_SAVES = 4;

static pthread_mutex_t g_revocationCacheWorkerLock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_revocationCacheActiveWorkers = 0;

static bool AcquireWorkerSlot(void)
{
    bool acquired = false;
    (void)pthread_mutex_lock(&g_revocationCacheWorkerLock);
    if (g_revocationCacheActiveWorkers < REVOCATION_CACHE_MAX_CONCURRENT_SAVES) {
        g_revocationCacheActiveWorkers++;
        acquired = true;
    }
    (void)pthread_mutex_unlock(&g_revocationCacheWorkerLock);
    return acquired;
}

static void ReleaseWorkerSlot(void)
{
    (void)pthread_mutex_lock(&g_revocationCacheWorkerLock);
    if (g_revocationCacheActiveWorkers > 0) {
        g_revocationCacheActiveWorkers--;
    }
    (void)pthread_mutex_unlock(&g_revocationCacheWorkerLock);
}

static void ZeroAndFreeBlob(struct CmBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr) {
        return;
    }
    if (blob->size > 0) {
        (void)memset_s(blob->data, blob->size, 0, blob->size);
    }
    CMFree(blob->data);
    blob->data = nullptr;
    blob->size = 0;
}

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

struct RevocationCacheAsyncTask {
    struct CmBlob key;
    struct CmBlob data;
    uint32_t type;
    int64_t expireTimeUtc;
};

static void *RevocationCacheAsyncWorker(void *arg)
{
    struct RevocationCacheAsyncTask *task = static_cast<struct RevocationCacheAsyncTask *>(arg);
    if (task != nullptr) {
        (void)CmServiceSaveRevocationCache(&task->key, task->type, &task->data, task->expireTimeUtc);
        ZeroAndFreeBlob(&task->key);
        ZeroAndFreeBlob(&task->data);
        CMFree(task);
    }
    ReleaseWorkerSlot();
    return nullptr;
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
        ZeroAndFreeBlob(&keyCopy);
        return ret;
    }

    if (!AcquireWorkerSlot()) {
        CM_LOG_W("revocation cache workers saturated, saving synchronously");
        int32_t syncRet = CmServiceSaveRevocationCache(&keyCopy, type, &dataCopy, expireTimeUtc);
        ZeroAndFreeBlob(&keyCopy);
        ZeroAndFreeBlob(&dataCopy);
        return syncRet;
    }

    struct RevocationCacheAsyncTask *task =
        static_cast<struct RevocationCacheAsyncTask *>(CMMalloc(sizeof(struct RevocationCacheAsyncTask)));
    if (task == nullptr) {
        ReleaseWorkerSlot();
        ZeroAndFreeBlob(&keyCopy);
        ZeroAndFreeBlob(&dataCopy);
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(task, sizeof(struct RevocationCacheAsyncTask), 0, sizeof(struct RevocationCacheAsyncTask));
    task->key = keyCopy;
    task->data = dataCopy;
    task->type = type;
    task->expireTimeUtc = expireTimeUtc;

    pthread_t tid;
    int32_t createRet = pthread_create(&tid, nullptr, RevocationCacheAsyncWorker, task);
    if (createRet != 0) {
        CM_LOG_E("failed to create revocation cache worker thread, err = %d", createRet);
        ReleaseWorkerSlot();
        ZeroAndFreeBlob(&keyCopy);
        ZeroAndFreeBlob(&dataCopy);
        CMFree(task);
        return CMR_ERROR_INVALID_OPERATION;
    }
    (void)pthread_detach(tid);
    return CM_SUCCESS;
}
