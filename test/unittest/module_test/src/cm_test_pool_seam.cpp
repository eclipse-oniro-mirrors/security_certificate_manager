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

#include "cm_test_pool_seam.h"

#include "cm_type.h"

std::vector<PooledTaskRecord> g_pooledTasks;
int32_t g_addTaskCallCount = 0;
bool g_acceptPoolTask = true;

void RunAllPooledTasksOnce(void)
{
    /* a retry task may enqueue its successor while running; loop until drained */
    while (!g_pooledTasks.empty()) {
        PooledTaskRecord record = g_pooledTasks.front();
        g_pooledTasks.erase(g_pooledTasks.begin());
        record.task(record.arg);
    }
}

/*
 * Link seam: the test target links the pool users (cm_cert_status_event.cpp,
 * cm_cloud_policy_sync.cpp) but not cert_manager_thread_pool.cpp, so this
 * definition replaces the real pool entry and only records what was
 * scheduled; running the tasks stays with the suites, each through
 * RunAllPooledTasksOnce.
 */
extern "C" int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs)
{
    g_addTaskCallCount++;
    if (!g_acceptPoolTask) {
        return CMR_ERROR;
    }
    g_pooledTasks.push_back(PooledTaskRecord{task, arg, delayMs});
    return CM_SUCCESS;
}
