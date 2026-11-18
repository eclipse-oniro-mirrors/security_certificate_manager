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

#include <cstdint>
#include <string>
#include <vector>

#include "cm_cloud_policy_store.h"
#include "cm_cloud_policy_sync.h"
#include "cm_cloud_setting_helper.h"
#include "cm_cloud_zip.h"
#include "cm_hsdr_client.h"
#include "cm_mem.h"
#include "cm_type.h"

namespace {
/* the call order the stubs record: one tag per pipeline step, in call
 * order; the writeversion tag carries the value it was handed */
std::vector<std::string> g_callOrder;

/* results the stubs hand back and the versions they advertise */
bool g_selfHealResult = true;
bool g_queryResult = true;
bool g_fetchResult = true;
uint64_t g_localVersion = 0;
uint64_t g_cloudVersion = 0;

/* what the orchestration handed to the steps, for argument assertions */
uint32_t g_fetchSceneCmdId = 0;
std::string g_extractMemberName;
std::string g_extractDestDir;
bool g_extractZipNonNull = false;
uint32_t g_extractZipSize = 0;
std::string g_publishSrcPath;
std::string g_publishDestName;
mode_t g_publishMode = 0;
uint64_t g_writtenVersion = 0;
int32_t g_writeVersionCallCount = 0;

/* sentinel of the TmpDirPath stub: proves the publish source path is
 * composed from this stub's return value, not a hard-coded path */
const char *STUB_TMP_DIR_PATH = "/stub/cloud_tmp";
/* the zip bytes the fetch stub hands out: a real CmMalloc block, so the
 * task's CM_FREE_BLOB release path is exercised */
constexpr uint32_t STUB_ZIP_SIZE = 16;

void ResetStubs(void)
{
    g_callOrder.clear();
    g_selfHealResult = true;
    g_queryResult = true;
    g_fetchResult = true;
    g_localVersion = 0;
    g_cloudVersion = 0;
    g_fetchSceneCmdId = 0;
    g_extractMemberName = "";
    g_extractDestDir = "";
    g_extractZipNonNull = false;
    g_extractZipSize = 0;
    g_publishSrcPath = "";
    g_publishDestName = "";
    g_publishMode = 0;
    g_writtenVersion = 0;
    g_writeVersionCallCount = 0;
}

/* the recorder installed through the CM_TEST_API_ENABLE event seam: this
 * binary already links cm_cert_status_event.cpp, which defines the
 * exported CmPublishForceCheckPolicyUpdatedEvent, so the event publish
 * cannot be stubbed as a symbol here (a duplicate definition); the seam
 * is the observation point instead */
int32_t RecordEventPublish(void)
{
    g_callOrder.push_back("event");
    return CM_SUCCESS;
}
} // namespace

/* link seams: the test target compiles the sync TU but none of the TUs
 * behind these symbols, so these definitions replace the cloud store,
 * the settings query, the zip extraction and the HSDR fetch and only
 * record what the orchestration asked for, in order; taking no service
 * identity and touching no file system is itself part of the contract */

int32_t CmCloudStoreSelfHealPreset(void)
{
    g_callOrder.push_back("selfheal");
    return g_selfHealResult ? CM_SUCCESS : CMR_ERROR;
}

int32_t CmCloudStoreReadVersion(uint64_t &version)
{
    g_callOrder.push_back("read");
    version = g_localVersion;
    return CM_SUCCESS;
}

int32_t CmCloudStoreWriteVersion(uint64_t version)
{
    g_callOrder.push_back("writeversion:" + std::to_string(version));
    g_writtenVersion = version;
    ++g_writeVersionCallCount;
    return CM_SUCCESS;
}

int32_t CmCloudStorePrepareTmpDir(void)
{
    g_callOrder.push_back("prepare");
    return CM_SUCCESS;
}

/* pure getter: records nothing (not a pipeline step); the sentinel makes
 * the composed publish source path verifiable */
const char *CmCloudStoreTmpDirPath(void)
{
    return STUB_TMP_DIR_PATH;
}

int32_t CmCloudStoreCleanupTmpDir(void)
{
    g_callOrder.push_back("cleanup");
    return CM_SUCCESS;
}

int32_t CmCloudStorePublishFile(const std::string &srcPath, const char *destName, mode_t mode)
{
    g_callOrder.push_back("publish");
    g_publishSrcPath = srcPath;
    g_publishDestName = (destName != nullptr) ? destName : "";
    g_publishMode = mode;
    return CM_SUCCESS;
}

int32_t CmCloudQuerySettingVersion(uint64_t &versionOut)
{
    g_callOrder.push_back("query");
    if (!g_queryResult) {
        /* the out parameter stays untouched, per the helper contract */
        return CMR_ERROR;
    }
    versionOut = g_cloudVersion;
    return CM_SUCCESS;
}

int32_t CmHsdrFetchCloudZip(const CloudResourceScene &scene, struct CmBlob &zipOut)
{
    g_callOrder.push_back("fetch");
    g_fetchSceneCmdId = scene.cmdId;
    if (!g_fetchResult) {
        /* zipOut stays exactly as passed in, per the client contract */
        return CMR_ERROR;
    }
    zipOut.size = STUB_ZIP_SIZE;
    zipOut.data = static_cast<uint8_t *>(CmMalloc(zipOut.size));
    if (zipOut.data == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    return CM_SUCCESS;
}

extern "C" int32_t CmCloudZipExtractWhitelisted(const struct CmBlob *zipData,
    const char *memberName, const char *destDir)
{
    g_callOrder.push_back("extract");
    g_extractZipNonNull = (zipData != nullptr);
    g_extractZipSize = (zipData != nullptr) ? zipData->size : 0;
    g_extractMemberName = (memberName != nullptr) ? memberName : "";
    g_extractDestDir = (destDir != nullptr) ? destDir : "";
    return CM_SUCCESS;
}

using namespace testing::ext;

namespace OHOS {
class CmCloudPolicySyncTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetStubs();
        /* start every test with no renewal injected (the null-renewal
         * path of the entry/exit renewals is exercised by every test)
         * and with the event seam recording into the call order */
        CmCloudPolicySyncSetUnloadRenewal(nullptr);
        CmCloudPolicySyncSetEventPublisherForTest(&RecordEventPublish);
    }

    void TearDown() override
    {
    }
};

/**
* @tc.name: TaskQuietEndsWhenQueryFails
* @tc.desc: a failed settings query ends the round quietly before any
*           fetch, publish, event or version write, and leaves nothing
*           staged (this round never created the tmp dir)
*/
HWTEST_F(CmCloudPolicySyncTest, TaskQuietEndsWhenQueryFails, TestSize.Level0)
{
    g_queryResult = false;

    CmCloudPolicySyncTask();

    const std::vector<std::string> expectedOrder = {
        "selfheal",
        "read",
        "query",
    };
    EXPECT_EQ(g_callOrder, expectedOrder);
    EXPECT_EQ(g_writeVersionCallCount, 0);
}

/**
* @tc.name: TaskQuietEndsWhenGateNotMet
* @tc.desc: equal cloud and local versions gate the round out as quietly
*           as a failed query, before any staging
*/
HWTEST_F(CmCloudPolicySyncTest, TaskQuietEndsWhenGateNotMet, TestSize.Level0)
{
    g_localVersion = 5;
    g_cloudVersion = 5;

    CmCloudPolicySyncTask();

    const std::vector<std::string> expectedOrder = {
        "selfheal",
        "read",
        "query",
    };
    EXPECT_EQ(g_callOrder, expectedOrder);
    EXPECT_EQ(g_writeVersionCallCount, 0);
}

/**
* @tc.name: TaskQuietEndsWhenFetchFails
* @tc.desc: a failed fetch cleans the staging dir and ends the round
*           without publish, version write or event (the last entry is
*           the cleanup of the prepared tmp dir)
*/
HWTEST_F(CmCloudPolicySyncTest, TaskQuietEndsWhenFetchFails, TestSize.Level0)
{
    g_fetchResult = false;
    g_localVersion = 0;
    g_cloudVersion = 9;

    CmCloudPolicySyncTask();

    const std::vector<std::string> expectedOrder = {
        "selfheal",
        "read",
        "query",
        "cleanup",
        "prepare",
        "fetch",
        "cleanup",
    };
    EXPECT_EQ(g_callOrder, expectedOrder);
    EXPECT_EQ(g_writeVersionCallCount, 0);
}

/**
* @tc.name: TaskSucceedsEndToEndWithStubs
* @tc.desc: the full round runs exactly once in flow order, publishes
*           tmp/<member> with the scene's name and mode and advances the
*           version to the cloud value after the publish
*/
HWTEST_F(CmCloudPolicySyncTest, TaskSucceedsEndToEndWithStubs, TestSize.Level0)
{
    g_localVersion = 2;
    g_cloudVersion = 9;

    CmCloudPolicySyncTask();

    const std::vector<std::string> expectedOrder = {
        "selfheal",
        "read",
        "query",
        "cleanup",
        "prepare",
        "fetch",
        "extract",
        "publish",
        "writeversion:9",
        "cleanup",
        "event",
    };
    EXPECT_EQ(g_callOrder, expectedOrder);
    EXPECT_EQ(g_writeVersionCallCount, 1);
    EXPECT_EQ(g_writtenVersion, g_cloudVersion);

    /* the scene table and the TmpDirPath return drive every argument */
    EXPECT_EQ(g_fetchSceneCmdId, CLOUD_POLICY_SCENE.cmdId);
    EXPECT_EQ(g_extractMemberName, std::string(CLOUD_POLICY_SCENE.zipMember));
    EXPECT_EQ(g_extractDestDir, std::string(STUB_TMP_DIR_PATH));
    EXPECT_TRUE(g_extractZipNonNull);
    EXPECT_EQ(g_extractZipSize, STUB_ZIP_SIZE);
    EXPECT_EQ(g_publishSrcPath,
        std::string(STUB_TMP_DIR_PATH) + "/" + CLOUD_POLICY_SCENE.zipMember);
    EXPECT_EQ(g_publishDestName, std::string(CLOUD_POLICY_SCENE.destFile));
    EXPECT_EQ(g_publishMode, CLOUD_POLICY_SCENE.destMode);
}

/**
* @tc.name: TaskSelfHealFailureAbortsEarly
* @tc.desc: a failed preset self-heal ends the round with zero calls
*           after it
*/
HWTEST_F(CmCloudPolicySyncTest, TaskSelfHealFailureAbortsEarly, TestSize.Level0)
{
    g_selfHealResult = false;

    CmCloudPolicySyncTask();

    const std::vector<std::string> expectedOrder = {
        "selfheal",
    };
    EXPECT_EQ(g_callOrder, expectedOrder);
    EXPECT_EQ(g_writeVersionCallCount, 0);
}

/**
* @tc.name: TaskRenewsUnloadAtStartAndEnd
* @tc.desc: the round renews the injected unload timer at entry and at
*           exit, so a full sync cannot be torn down mid-flight
*/
HWTEST_F(CmCloudPolicySyncTest, TaskRenewsUnloadAtStartAndEnd, TestSize.Level0)
{
    /* the trailing renewal belongs to the completed round (brief flow),
     * so the stubs must let this round run through: cloud newer than
     * local passes the gate */
    g_localVersion = 0;
    g_cloudVersion = 9;

    uint32_t renewalCount = 0;
    CmCloudPolicySyncSetUnloadRenewal([&renewalCount]() { ++renewalCount; });

    CmCloudPolicySyncTask();

    /* one renewal at the task entry plus one at the task exit */
    EXPECT_GE(renewalCount, static_cast<uint32_t>(2));
}
} // namespace OHOS
