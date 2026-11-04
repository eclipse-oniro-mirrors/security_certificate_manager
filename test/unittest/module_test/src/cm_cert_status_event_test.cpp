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
#include "cm_type.h"

namespace {
/* records the last event handed to the publish seam */
struct PublishRecord {
    std::string action;
    std::string certUri;
    bool enabled = false;
    bool hasEnabledParam = false;
    std::vector<std::string> subscriberPermissions;
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
 * and only record what was built and scheduled */
bool CmPublishCommonEventToCes(const OHOS::AAFwk::Want &want,
    const std::vector<std::string> &subscriberPermissions)
{
    g_publishRecord.action = want.GetActionRef();
    g_publishRecord.certUri = want.GetStringParam(CM_EVENT_PARAM_CERT_URI);
    g_publishRecord.enabled = want.GetBoolParam(CM_EVENT_PARAM_ENABLED, true);
    g_publishRecord.hasEnabledParam = want.HasParameter(CM_EVENT_PARAM_ENABLED);
    g_publishRecord.subscriberPermissions = subscriberPermissions;
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
* @tc.desc: disabled status publishes event carrying the uri and enabled=false
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest001, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_publishRecord.action, std::string(CM_EVENT_ACTION_SYSTEM_CA_STATUS_CHANGED));
    EXPECT_EQ(g_publishRecord.certUri, std::string("system://ca0"));
    EXPECT_FALSE(g_publishRecord.enabled);
    EXPECT_TRUE(g_publishRecord.hasEnabledParam);
    ASSERT_FALSE(g_publishRecord.subscriberPermissions.empty());
    EXPECT_EQ(g_publishRecord.subscriberPermissions[0],
        std::string("ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"));
}

/**
* @tc.name: CmCertStatusEventTest002
* @tc.desc: enabled status publishes event carrying enabled=true
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest002, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca1", CERT_STATUS_ENABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_publishRecord.action, std::string(CM_EVENT_ACTION_SYSTEM_CA_STATUS_CHANGED));
    EXPECT_EQ(g_publishRecord.certUri, std::string("system://ca1"));
    EXPECT_TRUE(g_publishRecord.enabled);
    EXPECT_TRUE(g_publishRecord.hasEnabledParam);
}

/**
* @tc.name: CmCertStatusEventTest003
* @tc.desc: null uri is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest003, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent(nullptr, CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest004
* @tc.desc: empty uri is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest004, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent("", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest005
* @tc.desc: uri longer than MAX_LEN_URI is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest005, TestSize.Level0)
{
    std::string tooLongUri(MAX_LEN_URI, 'a');
    int32_t ret = CmPublishSystemCaStatusEvent(tooLongUri.c_str(), CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest006
* @tc.desc: status other than enabled/disabled is rejected without publishing
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest006, TestSize.Level0)
{
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", 2); // 2 is not a valid status
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(g_publishRecord.callCount, 0);
}

/**
* @tc.name: CmCertStatusEventTest007
* @tc.desc: first publish failure enqueues one delayed retry and returns success
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest007, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    ASSERT_EQ(g_pooledTasks.size(), 1);
    EXPECT_EQ(g_pooledTasks[0].delayMs, EXPECTED_RETRY_DELAY_MS);
}

/**
* @tc.name: CmCertStatusEventTest008
* @tc.desc: retry chain stops after the next attempt succeeds
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest008, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);

    /* the retry attempt succeeds */
    g_publishRecord.publishResult = true;
    RunAllPooledTasksOnce();
    EXPECT_EQ(g_publishRecord.callCount, 2);
    EXPECT_TRUE(g_pooledTasks.empty());
    EXPECT_EQ(g_addTaskCallCount, 1);
}

/**
* @tc.name: CmCertStatusEventTest009
* @tc.desc: retries are capped: 1 immediate attempt plus at most 3 retries
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest009, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CM_SUCCESS);

    RunAllPooledTasksOnce();
    EXPECT_EQ(g_publishRecord.callCount, 1 + EXPECTED_MAX_RETRY_COUNT);
    EXPECT_TRUE(g_pooledTasks.empty());
    EXPECT_EQ(g_addTaskCallCount, EXPECTED_MAX_RETRY_COUNT);
}

/**
* @tc.name: CmCertStatusEventTest010
* @tc.desc: pool rejection makes the publish report failure, no retry scheduled
*/
HWTEST_F(CmCertStatusEventTest, CmCertStatusEventTest010, TestSize.Level0)
{
    g_publishRecord.publishResult = false;
    g_acceptPoolTask = false;
    int32_t ret = CmPublishSystemCaStatusEvent("system://ca0", CERT_STATUS_DISABLED);
    EXPECT_EQ(ret, CMR_ERROR);
    EXPECT_EQ(g_publishRecord.callCount, 1);
    EXPECT_EQ(g_addTaskCallCount, 1);
    EXPECT_TRUE(g_pooledTasks.empty());
}
} // namespace OHOS
