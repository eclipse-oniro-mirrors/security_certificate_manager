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

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

#include <pthread.h>

#include "cm_log.h"

namespace {
/* core = maximum = 4 workers: spawned lazily, at most one per submitted
 * task while fewer than the bound are alive, so the pool ramps up with
 * load instead of holding resident threads */
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

/* process-lifetime pool state, intentionally never destroyed: workers
 * are detached and die with the service process, so no shutdown path
 * can join threads and delay the SA (delayed tasks sleep up to their
 * delayMs). Idle workers exit on their own after the keep-alive, so an
 * idle pool holds no threads */
std::mutex g_cmPoolMutex;
std::condition_variable g_cmPoolCv;
std::deque<std::shared_ptr<CmPooledTask>> g_cmPoolQueue;
uint32_t g_cmPoolLiveWorkers = 0;
std::atomic<uint32_t> g_cmPoolKeepAliveMs{CM_THREAD_POOL_KEEP_ALIVE_MS};

void *CmPoolWorkerEntry(void *arg)
{
    (void)arg;
    (void)pthread_setname_np(pthread_self(), "CmPool");
    std::unique_lock<std::mutex> lock(g_cmPoolMutex);
    bool workerAlive = true;
    while (workerAlive) {
        if (!g_cmPoolQueue.empty()) {
            std::shared_ptr<CmPooledTask> pooled = g_cmPoolQueue.front();
            g_cmPoolQueue.pop_front();
            lock.unlock();
            if (pooled->delayMs > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(pooled->delayMs));
            }
            pooled->task(pooled->arg);
            lock.lock();
            continue;
        }
        bool timedOut = g_cmPoolCv.wait_for(lock,
            std::chrono::milliseconds(g_cmPoolKeepAliveMs.load())) == std::cv_status::timeout;
        if (timedOut && g_cmPoolQueue.empty()) {
            g_cmPoolLiveWorkers--;
            CM_LOG_I("cm thread pool worker exited after idle");
            workerAlive = false;
        }
    }
    return nullptr;
}
} // namespace

int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs)
{
    if (task == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    auto pooled = std::make_shared<CmPooledTask>(CmPooledTask{task, arg, delayMs});

    std::unique_lock<std::mutex> lock(g_cmPoolMutex);
    if (g_cmPoolQueue.size() >= CM_THREAD_POOL_QUEUE_SIZE) {
        CM_LOG_E("cm thread pool queue is full, task discarded");
        return CMR_ERROR;
    }
    g_cmPoolQueue.push_back(pooled);
    if (g_cmPoolLiveWorkers < CM_THREAD_POOL_CORE_THREADS) {
        pthread_t threadId;
        int ret = pthread_create(&threadId, nullptr, CmPoolWorkerEntry, nullptr);
        if (ret == 0) {
            g_cmPoolLiveWorkers++;
            (void)pthread_detach(threadId);
        } else {
            CM_LOG_E("create cm thread pool worker failed, ret = %d", ret);
            if (g_cmPoolLiveWorkers == 0) {
                /* no worker can ever pick the task up, take it back */
                g_cmPoolQueue.pop_back();
                return CMR_ERROR;
            }
        }
    }
    g_cmPoolCv.notify_one();
    return CM_SUCCESS;
}

void CmThreadPoolSetKeepAliveMsForTest(uint32_t keepAliveMs)
{
    g_cmPoolKeepAliveMs.store(keepAliveMs);
}

uint32_t CmThreadPoolGetWorkerCountForTest(void)
{
    std::unique_lock<std::mutex> lock(g_cmPoolMutex);
    return g_cmPoolLiveWorkers;
}
