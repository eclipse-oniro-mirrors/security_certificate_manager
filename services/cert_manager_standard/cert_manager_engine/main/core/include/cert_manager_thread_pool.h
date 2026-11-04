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

#include <stdint.h>

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Process-wide generic worker pool shared by cert manager features for
 * fire-and-forget background work (common event retry, asynchronous
 * revocation cache saving and similar follow-ups).
 *
 * The pool is lazily started with a fixed set of worker threads (core =
 * maximum = 4) and a bounded work queue (8 tasks): when the queue is full
 * the task is DISCARDED with an error log and a negative return value
 * instead of blocking the caller, so best-effort callers can drop the
 * task and the revocation cache can fall back to saving synchronously.
 * Idle workers are not reaped (not supported by the underlying pool);
 * they live for the process lifetime.
 *
 * @param task the function to run on a pool thread
 * @param arg caller-owned argument passed through to task; the pool never
 *            touches it, ownership stays with the task function
 * @param delayMs delay before the task runs on the pool thread; 0 runs as
 *                soon as a worker picks it up
 * @return CM_SUCCESS if the task was accepted; CMR_ERROR_INVALID_ARGUMENT
 *         for a null task; CMR_ERROR when the pool is unavailable or the
 *         queue is full (task discarded)
 */
int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <functional>
#include <memory>
#include <utility>

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
