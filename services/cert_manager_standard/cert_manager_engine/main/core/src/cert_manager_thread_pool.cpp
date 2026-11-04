/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cert_manager_thread_pool.h"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <thread>

#include "thread_pool.h"

#include "cm_log.h"

namespace {
/* core = maximum = 4 worker threads: c_utils ThreadPool has no grow
 * phase, so core and maximum coincide in a fixed pool */
constexpr uint32_t CM_THREAD_POOL_CORE_THREADS = 4;
/* bounded work queue: when it is full the task is discarded with an
 * error log instead of blocking the caller; callers drop the task or
 * fall back to synchronous execution */
constexpr size_t CM_THREAD_POOL_QUEUE_SIZE = 8;

struct CmPooledTask {
    void (*task)(void *);
    void *arg;
    uint32_t delayMs;
};

/* process-lifetime singleton: the pool is intentionally never destroyed,
 * worker threads die with the service process. The underlying
 * OHOS::ThreadPool cannot reap idle threads (workers wait on an internal
 * condition variable and Stop() can never be followed by Start()), so an
 * idle keep-alive is not implementable on top of it; releasing idle
 * workers is delegated to the SA recycle strategy instead. This also
 * avoids join delays (delayed tasks sleep up to their delayMs) when the
 * SA is recycled */
OHOS::ThreadPool *g_cmThreadPool = nullptr;
std::once_flag g_cmThreadPoolOnce;

void CmRunPooledTask(const std::shared_ptr<CmPooledTask> &pooled)
{
    if (pooled->delayMs > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(pooled->delayMs));
    }
    pooled->task(pooled->arg);
}

void EnsureCmThreadPoolStarted()
{
    std::call_once(g_cmThreadPoolOnce, []() {
        OHOS::ThreadPool *pool = new (std::nothrow) OHOS::ThreadPool("CmPool");
        if (pool == nullptr) {
            CM_LOG_E("alloc cm thread pool failed");
            return;
        }
        /* no SetMaxTaskNum: the native bound makes AddTask BLOCK on a full
         * queue, and a blocked worker that nests AddTask (retry chains do)
         * could deadlock the pool; the wrapper enforces its own bound */
        uint32_t ret = pool->Start(CM_THREAD_POOL_CORE_THREADS);
        if (ret != 0) { /* 0 is ERR_OK of ThreadPool::Start */
            CM_LOG_E("start cm thread pool failed, ret = %u", ret);
            delete pool;
            return;
        }
        /* publish the pool only with live workers: with no worker thread
         * c_utils AddTask would run the task on the CALLER thread */
        g_cmThreadPool = pool;
    });
}
} // namespace

int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs)
{
    if (task == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    EnsureCmThreadPoolStarted();
    OHOS::ThreadPool *pool = g_cmThreadPool;
    if (pool == nullptr) {
        return CMR_ERROR;
    }
    /* work queue full (with a fixed pool the workers are busy by then):
     * discard the task, log it and let the caller decide the fallback */
    if (pool->GetCurTaskNum() >= CM_THREAD_POOL_QUEUE_SIZE) {
        CM_LOG_E("cm thread pool queue is full, task discarded");
        return CMR_ERROR;
    }

    auto pooled = std::make_shared<CmPooledTask>(CmPooledTask{task, arg, delayMs});
    pool->AddTask([pooled]() { CmRunPooledTask(pooled); });
    return CM_SUCCESS;
}
