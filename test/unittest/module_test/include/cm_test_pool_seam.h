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

#ifndef CM_TEST_POOL_SEAM_H
#define CM_TEST_POOL_SEAM_H

#include <cstdint>
#include <vector>

/*
 * Shared link seam over the generic thread pool, split out of the cert
 * status event suite: cm_module_test compiles pool users (the cert
 * status retry, the cloud policy sync round) but NOT the production
 * pool TU, so the pool entry symbol is the recording stub defined in
 * cm_test_pool_seam.cpp instead. Pooled work never runs on a worker
 * thread in this binary; each suite drives the queued tasks
 * synchronously through RunAllPooledTasksOnce, which keeps
 * pool-dependent code deterministic in tests.
 */
struct PooledTaskRecord {
    void (*task)(void *);
    void *arg;
    uint32_t delayMs;
};

/* accepted tasks in post order; drained by RunAllPooledTasksOnce */
extern std::vector<PooledTaskRecord> g_pooledTasks;
/* how many tasks were handed to the pool stub, accepted or rejected */
extern int32_t g_addTaskCallCount;
/* when false the stub rejects every task: the pool-full or no-worker shape */
extern bool g_acceptPoolTask;

/* run the queued tasks in post order until the queue drains; a task
 * may enqueue its successor while running (the retry pattern), hence
 * the loop */
void RunAllPooledTasksOnce(void);

#endif /* CM_TEST_POOL_SEAM_H */
