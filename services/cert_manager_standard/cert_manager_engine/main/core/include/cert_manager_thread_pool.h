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

#ifndef CERT_MANAGER_THREAD_POOL_H
#define CERT_MANAGER_THREAD_POOL_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Process-wide generic worker pool shared by cert manager features for
 * fire-and-forget background work (common event retry, asynchronous
 * revocation cache saving and similar follow-ups).
 *
 * Workers are self-managed: spawned lazily while fewer than the fixed
 * bound (core = maximum = 4) are alive and reaped by their own idle
 * keep-alive (CM_THREAD_POOL_KEEP_ALIVE_MS), so an idle pool holds no
 * threads. The work queue is bounded (8 tasks): when it is full the
 * task is DISCARDED with an error log and a negative return value
 * instead of blocking the caller, so best-effort callers can drop the
 * task and the revocation cache can fall back to saving synchronously.
 *
 * @param task the function to run on a pool worker
 * @param arg caller-owned argument passed through to task; the pool never
 *            touches it, ownership stays with the task function
 * @param delayMs delay before the task runs on the worker; 0 runs as
 *                soon as a worker picks it up
 * @return CM_SUCCESS if the task was accepted; CMR_ERROR_INVALID_ARGUMENT
 *         for a null task; CMR_ERROR when the queue is full (task
 *         discarded) or no worker could be created
 */
int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs);

/* test-only: shorten the worker idle keep-alive (milliseconds) so thread
 * reaping and respawn can be exercised without waiting for the 30 s
 * default; production code must not call this */
void CmThreadPoolSetKeepAliveMsForTest(uint32_t keepAliveMs);

/* test-only: live worker count for lifecycle assertions */
uint32_t CmThreadPoolGetWorkerCountForTest(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <functional>
#include <memory>
#include <utility>

/* default idle keep-alive of pool workers, in milliseconds */
constexpr uint32_t CM_THREAD_POOL_KEEP_ALIVE_MS = 30000;

/*
 * C++ convenience wrapper over CmThreadPoolAddTask for std::function tasks.
 * Keep this header-free of engine headers so both the C engine sources and
 * the C++ service sources can include it.
 */

/* adapter that runs a std::function owned through a void* and frees it */
inline void CmRunFunctionTask(void *raw)
{
    using FnContext = std::function<void()>;
    std::unique_ptr<FnContext> context(static_cast<FnContext *>(raw));
    (*context)();
}

inline int32_t CmThreadPoolPost(std::function<void()> task, uint32_t delayMs)
{
    if (task == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    auto taskContext = std::make_unique<std::function<void()>>(std::move(task));
    int32_t ret = CmThreadPoolAddTask(CmRunFunctionTask, taskContext.get(), delayMs);
    if (ret == CM_SUCCESS) {
        taskContext.release(); /* ownership moved to the pool worker */
    }
    return ret;
}
#endif /* __cplusplus */

#endif /* CERT_MANAGER_THREAD_POOL_H */
