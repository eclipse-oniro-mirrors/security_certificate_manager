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

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

#include "cert_manager_thread_pool.h"
#include "cm_type.h"

using namespace testing::ext;

namespace {
/* pinned pool configuration this suite asserts against */
constexpr uint32_t POOL_TEST_WORKER_COUNT = 4;
constexpr uint32_t POOL_TEST_QUEUE_CAPACITY = 8;
/* timings for polling assertions, generous for slow devices */
constexpr uint32_t POOL_TEST_WAIT_TIMEOUT_MS = 3000;
constexpr uint32_t POOL_TEST_POLL_INTERVAL_MS = 5;
constexpr uint32_t POOL_TEST_DELAY_MS = 200;
constexpr uint32_t POOL_TEST_KEEP_ALIVE_MS = 100;
constexpr uint32_t POOL_TEST_IDLE_WAIT_MS = 500;

void SetFlag(void *arg)
{
    *static_cast<std::atomic<uint32_t> *>(arg) = 1;
}

struct BlockContext {
    std::atomic<uint32_t> *release;
    std::atomic<uint32_t> *started;
    std::atomic<uint32_t> *completed;
};

/* occupies its worker until release is set, counting start and finish */
void BlockUntilReleased(void *arg)
{
    auto *ctx = static_cast<BlockContext *>(arg);
    ctx->started->fetch_add(1);
    while (ctx->release->load() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(POOL_TEST_POLL_INTERVAL_MS));
    }
    ctx->completed->fetch_add(1);
}

bool WaitForValue(const std::atomic<uint32_t> &value, uint32_t expected)
{
    for (uint32_t elapsed = 0; elapsed < POOL_TEST_WAIT_TIMEOUT_MS; elapsed += POOL_TEST_POLL_INTERVAL_MS) {
        if (value.load() == expected) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POOL_TEST_POLL_INTERVAL_MS));
    }
    return value.load() == expected;
}
} // namespace

class CmThreadPoolTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CmThreadPoolTest::SetUpTestCase(void) {}

void CmThreadPoolTest::TearDownTestCase(void) {}

void CmThreadPoolTest::SetUp() {}

void CmThreadPoolTest::TearDown()
{
    /* restore the production keep-alive for tests that follow */
    CmThreadPoolSetKeepAliveMsForTest(CM_THREAD_POOL_KEEP_ALIVE_MS);
}

/**
 * @tc.name: CmThreadPoolTest001
 * @tc.desc: idle workers exit after the keep-alive and respawn on demand
 */
HWTEST_F(CmThreadPoolTest, CmThreadPoolTest001, TestSize.Level0)
{
    /* shrink the keep-alive first: the sliced idle wait re-reads it, so
     * workers already waiting under a longer value also exit soon */
    CmThreadPoolSetKeepAliveMsForTest(POOL_TEST_KEEP_ALIVE_MS);

    /* order-independent entry: drain workers an earlier test may have left
     * behind before asserting against a fresh pool */
    bool drained = false;
    for (uint32_t elapsed = 0; elapsed < POOL_TEST_WAIT_TIMEOUT_MS;
        elapsed += POOL_TEST_POLL_INTERVAL_MS) {
        if (CmThreadPoolGetWorkerCountForTest() == 0) {
            drained = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POOL_TEST_POLL_INTERVAL_MS));
    }
    EXPECT_TRUE(drained) << "pool did not drain before CmThreadPoolTest001";

    std::atomic<uint32_t> done{0};
    int32_t ret = CmThreadPoolAddTask(SetFlag, &done, 0);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_TRUE(WaitForValue(done, 1));
    EXPECT_EQ(CmThreadPoolGetWorkerCountForTest(), 1);

    /* outlive the keep-alive: the worker must exit, leaving no threads */
    std::this_thread::sleep_for(std::chrono::milliseconds(POOL_TEST_IDLE_WAIT_MS));
    EXPECT_EQ(CmThreadPoolGetWorkerCountForTest(), 0);

    /* a later task must still run: the pool respawns workers on demand */
    std::atomic<uint32_t> doneAgain{0};
    ret = CmThreadPoolAddTask(SetFlag, &doneAgain, 0);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_TRUE(WaitForValue(doneAgain, 1));
    EXPECT_EQ(CmThreadPoolGetWorkerCountForTest(), 1);
}

/**
 * @tc.name: CmThreadPoolTest002
 * @tc.desc: a submitted task runs on a pool worker
 */
HWTEST_F(CmThreadPoolTest, CmThreadPoolTest002, TestSize.Level0)
{
    std::atomic<uint32_t> done{0};
    int32_t ret = CmThreadPoolAddTask(SetFlag, &done, 0);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_TRUE(WaitForValue(done, 1));
}

/**
 * @tc.name: CmThreadPoolTest003
 * @tc.desc: the delay elapses on the worker before the task runs
 */
HWTEST_F(CmThreadPoolTest, CmThreadPoolTest003, TestSize.Level0)
{
    std::atomic<uint32_t> done{0};
    auto start = std::chrono::steady_clock::now();
    int32_t ret = CmThreadPoolAddTask(SetFlag, &done, POOL_TEST_DELAY_MS);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_TRUE(WaitForValue(done, 1));
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    EXPECT_GE(elapsedMs, POOL_TEST_DELAY_MS);
}

/**
 * @tc.name: CmThreadPoolTest004
 * @tc.desc: a full queue discards the task and reports failure
 */
HWTEST_F(CmThreadPoolTest, CmThreadPoolTest004, TestSize.Level0)
{
    std::atomic<uint32_t> release{0};
    std::atomic<uint32_t> started{0};
    std::atomic<uint32_t> completed{0};
    BlockContext ctx{&release, &started, &completed};

    /* occupy every worker with blocked tasks */
    for (uint32_t i = 0; i < POOL_TEST_WORKER_COUNT; ++i) {
        int32_t ret = CmThreadPoolAddTask(BlockUntilReleased, &ctx, 0);
        EXPECT_EQ(ret, CM_SUCCESS);
    }
    /* wait until the workers actually hold the blocked tasks, otherwise
     * rapid submits could transiently overflow the queue */
    EXPECT_TRUE(WaitForValue(started, POOL_TEST_WORKER_COUNT));
    for (uint32_t i = 0; i < POOL_TEST_QUEUE_CAPACITY; ++i) {
        int32_t ret = CmThreadPoolAddTask(BlockUntilReleased, &ctx, 0);
        EXPECT_EQ(ret, CM_SUCCESS);
    }

    /* queue is full: the next task must be discarded */
    int32_t ret = CmThreadPoolAddTask(BlockUntilReleased, &ctx, 0);
    EXPECT_EQ(ret, CMR_ERROR);

    release.store(1);
    EXPECT_TRUE(WaitForValue(completed, POOL_TEST_WORKER_COUNT + POOL_TEST_QUEUE_CAPACITY));
}

/**
 * @tc.name: CmThreadPoolTest005
 * @tc.desc: a null task is rejected without spawning work
 */
HWTEST_F(CmThreadPoolTest, CmThreadPoolTest005, TestSize.Level0)
{
    int32_t ret = CmThreadPoolAddTask(nullptr, nullptr, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
}
