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

#include <string>
#include <vector>

#include "want.h"

#include "cert_manager_thread_pool.h"
#include "cm_cert_status_event.h"
#include "cm_cert_status_event_publish.h"
#include "cm_root_ca_store_rdb.h"
#include "cm_type.h"

namespace {
/* records the last event handed to the publish seam */
struct PublishRecord {
    std::string action;
    std::string type;
    std::string operation;
    std::string data;
    bool hasDataParam = false;
    int32_t callCount = 0;
    bool publishResult = true;
};

PublishRecord g_publishRecord;

/* fake of the generic pool: records accepted tasks, lets the test run them */
struct PooledTaskRecord {
    void (*task)(void *);
    void *arg;
    uint32_t delayMs;
};

std::vector<PooledTaskRecord> g_pooledTasks;
int32_t g_addTaskCallCount = 0;
bool g_acceptPoolTask = true;

/* retry policy fixed as part of the event contract */
constexpr uint32_t EXPECTED_RETRY_DELAY_MS = 50;
constexpr uint32_t EXPECTED_MAX_RETRY_COUNT = 3;

/* 64-char uppercase hex stand-in: the value only has to round-trip */
const char *PK_HASH_STANDIN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

void RunAllPooledTasksOnce()
{
    /* a retry task may enqueue its successor while running; loop until drained */
    while (!g_pooledTasks.empty()) {
        PooledTaskRecord record = g_pooledTasks.front();
        g_pooledTasks.erase(g_pooledTasks.begin());
        record.task(record.arg);
    }
}
} // namespace

/* link seam: the test target links cm_cert_status_event.cpp but NOT
 * cm_cert_status_event_publish.cpp nor cert_manager_thread_pool.cpp, so
 * these definitions replace the real common event service and pool calls
 * and only record what was built and scheduled; the seam taking no
 * subscriber permissions is itself the no-permission contract */
bool CmPublishCommonEventToCes(const OHOS::AAFwk::Want &want)
{
    g_publishRecord.action = want.GetActionRef();
    g_publishRecord.type = want.GetStringParam(CM_EVENT_PARAM_TYPE);
    g_publishRecord.operation = want.GetStringParam(CM_EVENT_PARAM_OPERATION);
    g_publishRecord.data = want.GetStringParam(CM_EVENT_PARAM_DATA);
    g_publishRecord.hasDataParam = want.HasParameter(CM_EVENT_PARAM_DATA);
    g_publishRecord.callCount++;
    return g_publishRecord.publishResult;
}

extern "C" int32_t CmThreadPoolAddTask(void (*task)(void *), void *arg, uint32_t delayMs)
{
    g_addTaskCallCount++;
    if (!g_acceptPoolTask) {
        return CMR_ERROR;
    }
    g_pooledTasks.push_back(PooledTaskRecord{task, arg, delayMs});
    return CM_SUCCESS;
}

using namespace testing::ext;
namespace OHOS {
class CmCertStatusEventTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmCertStatusEventTest::SetUpTestCase(void)
{
}

void CmCertStatusEventTest::TearDownTestCase(void)
{
}

void CmCertStatusEventTest::SetUp()
{
    g_publishRecord = PublishRecord{};
    g_pooledTasks.clear();
    g_addTaskCallCount = 0;
    g_acceptPoolTask = true;
}

void CmCertStatusEventTest::TearDown()
{
}

/**
* @tc.name: CmCertStatusEventTest001
* @tc.desc: user enable publishes SYSTEM_CA + ENABLE + the cert pk hash
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest001, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_ENABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_publishRecord.action, std::string(CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED));
    EXPECT_EQ(g_publishRecord.type, std::string(CM_EVENT_TYPE_SYSTEM_CA));
    EXPECT_EQ(g_publishRecord.operation, std::string(CM_EVENT_OPERATION_ENABLE));
    EXPECT_EQ(g_publishRecord.data, std::string(PK_HASH_STANDIN));
    EXPECT_TRUE(g_publishRecord.hasDataParam);
}

/**
* @tc.name: CmCertStatusEventTest002
* @tc.desc: user disable publishes SYSTEM_CA + DISABLE + the cert pk hash
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest002, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_publishRecord.action, std::string(CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED));
    EXPECT_EQ(g_publishRecord.type, std::string(CM_EVENT_TYPE_SYSTEM_CA));
    EXPECT_EQ(g_publishRecord.operation, std::string(CM_EVENT_OPERATION_DISABLE));
    EXPECT_EQ(g_publishRecord.data, std::string(PK_HASH_STANDIN));
    EXPECT_TRUE(g_publishRecord.hasDataParam);
}

/**
* @tc.name: CmCertStatusEventTest003
* @tc.desc: null pk hash is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest003, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent(nullptr, CERT_STATUS_ENABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest004
* @tc.desc: empty pk hash is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest004, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent("", CERT_STATUS_ENABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest005
* @tc.desc: pk hash that is not CM_ROOT_CA_PK_HASH_HEX_LEN chars is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest005, TestSize.Level0)
{
    std::string badLen(CM_ROOT_CA_PK_HASH_HEX_LEN - 1, 'A'); /* 63 chars, not 64 */
    int32_t ret = CmPublishSystemCaStatusEvent(badLen.c_str(), CERT_STATUS_ENABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest006
* @tc.desc: status other than enabled/disabled is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest006, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, 2); // 2 is not a valid status
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest007
* @tc.desc: force-check policy update publishes REVOCATION_FORCE_CHECK + UPDATE with no data param
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest007, TestSize.Level0)
{
    int32_t ret = CmPublishForceCheckPolicyUpdatedEvent();
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_publishRecord.action, std::string(CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED));
    EXPECT_EQ(g_publishRecord.type, std::string(CM_EVENT_TYPE_REVOCATION_FORCE_CHECK));
    EXPECT_EQ(g_publishRecord.operation, std::string(CM_EVENT_OPERATION_UPDATE));
    EXPECT_FALSE(g_publishRecord.hasDataParam);
}

/**
* @tc.name: CmCertStatusEventTest008
* @tc.desc: first publish failure enqueues one delayed retry and returns success
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest008, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    ASSERT_EQ(g_pooledTasks.size(), 1);
    EXPECT_EQ(g_pooledTasks[0].delayMs, EXPECTED_RETRY_DELAY_MS);
}

/**
* @tc.name: CmCertStatusEventTest009
* @tc.desc: retry chain stops after the next attempt succeeds
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest009, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);

    /* the retry attempt succeeds */
    g_publishRecord.publishResult = true;
    RunAllPooledTasksOnce();
    EXPECT_EQ(g_publishRecord.callCount, 2);
    EXPECT_TRUE(g_pooledTasks.empty());
    EXPECT_EQ(g_addTaskCallCount, 1);
}

/**
* @tc.name: CmCertStatusEventTest010
* @tc.desc: retries are capped: 1 immediate attempt plus at most 3 retries
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest010, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);

    RunAllPooledTasksOnce();
    EXPECT_EQ(g_publishRecord.callCount, 1 + EXPECTED_MAX_RETRY_COUNT);
    EXPECT_TRUE(g_pooledTasks.empty());
    EXPECT_EQ(g_addTaskCallCount, EXPECTED_MAX_RETRY_COUNT);
}

/**
* @tc.name: CmCertStatusEventTest011
* @tc.desc: pool rejection makes the publish report failure, no retry scheduled
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest011, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    g_acceptPoolTask = false;
    int32_t ret = CmPublishSystemCaStatusEvent(PK_HASH_STANDIN, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CMR_ERROR);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_addTaskCallCount, 1);
    EXPECT_TRUE(g_pooledTasks.empty());
}
} // namespace OHOS
