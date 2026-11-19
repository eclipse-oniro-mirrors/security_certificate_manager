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

#include "cm_cloud_policy_sync.h"

#include <cstdint>
#include <string>

#include "cert_manager_thread_pool.h"
#include "cm_cert_status_event.h"
#include "cm_cloud_policy_store.h"
#include "cm_cloud_setting_helper.h"
#include "cm_cloud_zip.h"
#include "cm_hsdr_client.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"

namespace {
/* the injected idle-unload renewal hook (see the header contract); a
 * null hook turns the renewals into no-ops, which is the module test
 * shape or a SA that has not injected one */
std::function<void()> g_unloadRenewal;

/* the posted round needs no delay: the pool only takes it off the SA
 * startup path */
constexpr uint32_t SYNC_TASK_POST_DELAY_MS = 0;

void RenewUnloadTimer(void)
{
    if (g_unloadRenewal != nullptr) {
        g_unloadRenewal();
    }
}

/*
 * Stage the round's bundle: a fresh empty staging dir, then the HSDR
 * fetch and the whitelisted extraction into it. The archive blob is
 * freed on every path. CMR codes only.
 */
int32_t FetchAndExtractCloudPolicy(void)
{
    if (CmCloudStorePrepareTmpDir() != CM_SUCCESS) {
        CM_LOG_E("prepare cloud staging directory failed");
        return CMR_ERROR;
    }
    struct CmBlob zipBlob = { 0, nullptr };
    int32_t ret = CmHsdrFetchCloudZip(CLOUD_POLICY_SCENE, zipBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("fetch cloud policy zip failed, ret = %d", ret);
        return ret;
    }
    ret = CmCloudZipExtractWhitelisted(&zipBlob, CLOUD_POLICY_SCENE.zipMember,
        CmCloudStoreTmpDirPath());
    /* the archive bytes are consumed by the extraction; released here on
     * both outcomes so no step after the fetch leaks them */
    CM_FREE_BLOB(zipBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("extract cloud policy zip member failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

/*
 * Publish the staged member into the forceCheck directory under the
 * scene's published file name and mode, then advance the version
 * counter only after the file replacement: any failure above leaves the
 * old version in place, so the next SA start re-runs the round against
 * the same cloud version (idempotent convergence). CMR codes only.
 */
int32_t PublishCloudPolicy(uint64_t cloudVersion)
{
    const std::string stagedMember =
        std::string(CmCloudStoreTmpDirPath()) + "/" + CLOUD_POLICY_SCENE.zipMember;
    int32_t ret = CmCloudStorePublishFile(stagedMember, CLOUD_POLICY_SCENE.destFile,
        CLOUD_POLICY_SCENE.destMode);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("publish cloud policy file failed, ret = %d", ret);
        return ret;
    }
    ret = CmCloudStoreWriteVersion(cloudVersion);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("write cloud policy version failed, ret = %d", ret);
    }
    return ret;
}
} // namespace

#ifdef CM_TEST_API_ENABLE
namespace {
/* test seam for the final event publish: cm_module_test links
 * cm_cert_status_event.cpp, which defines the exported
 * CmPublishForceCheckPolicyUpdatedEvent, so a test symbol stub would be
 * a duplicate definition in that binary; the module test installs its
 * recorder through the exported *ForTest setter instead. Production
 * builds do not define the macro and carry none of this. */
int32_t (*g_publishEventForTest)(void) = nullptr;
} // namespace

void CmCloudPolicySyncSetEventPublisherForTest(int32_t (*publisher)(void))
{
    g_publishEventForTest = publisher;
}
#endif /* CM_TEST_API_ENABLE */

void CmCloudPolicySyncSetUnloadRenewal(std::function<void()> renewal)
{
    g_unloadRenewal = std::move(renewal);
}

void CmCloudPolicySyncStart(void)
{
    /* renew once up front so the idle-unload timer cannot fire between
     * the SA startup and the pool worker picking the round up, then
     * hand the round to the pool: fire-and-forget, a post failure only
     * logs and never affects the SA startup; the SA calls this exactly
     * once per OnStart, so at most one round is ever in flight (the
     * store and zip writers serialize behind that) */
    RenewUnloadTimer();
    int32_t ret = CmThreadPoolPost(CmCloudPolicySyncTask, SYNC_TASK_POST_DELAY_MS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("post cloud policy sync task failed, ret = %d", ret);
    }
}

void CmCloudPolicySyncTask(void)
{
    /* renew the timer at entry and at exit: the round runs on a pool
     * worker with no IPC traffic to reset it, so without these renewals
     * the SA could be torn down mid-round */
    RenewUnloadTimer();

    /* every failure below ends the round quietly: no fault reporting,
     * no retry, the next SA start walks the whole round again */

    /* the forceCheck directory must exist before anything inside it is
     * read or written; the preset self-heal itself never publishes the
     * update event, the preset is not a policy change */
    if (CmCloudStoreSelfHealPreset() != CM_SUCCESS) {
        CM_LOG_E("cloud policy preset self-heal failed");
        return;
    }

    uint64_t localVersion = 0;
    /* ReadVersion never fails: a missing, empty or malformed version.cfg
     * reads as 0 and keeps the gate honest, and the hard IO problems
     * surface at write/publish time, so there is no defensive branch */
    (void)CmCloudStoreReadVersion(localVersion);

    uint64_t cloudVersion = 0;
    int32_t ret = CmCloudQuerySettingVersion(cloudVersion);
    if (ret != CM_SUCCESS) {
        /* fail-closed and quiet: no settings row (yet) means no cloud
         * push to apply, not a fault */
        CM_LOG_I("no cloud policy version to sync, ret = %d, local version = %llu",
            ret, static_cast<unsigned long long>(localVersion));
        return;
    }

    if (!CmCloudVersionNeedsSync(cloudVersion, localVersion)) {
        /* the steady state: the published policy already holds the
         * advertised version (equal) or the push is stale (rollback) */
        CM_LOG_I("cloud policy already up to date, cloud version = %llu, local version = %llu",
            static_cast<unsigned long long>(cloudVersion),
            static_cast<unsigned long long>(localVersion));
        return;
    }

    /* clear whatever a previously interrupted round left staged, then
     * FetchAndExtractCloudPolicy recreates the staging directory empty
     * for this download; on any failure below the staged remains are
     * cleared again so the next round starts clean */
    if (CmCloudStoreCleanupTmpDir() != CM_SUCCESS) {
        CM_LOG_E("clean cloud staging directory failed");
        return;
    }
    if (FetchAndExtractCloudPolicy() != CM_SUCCESS) {
        (void)CmCloudStoreCleanupTmpDir();
        return;
    }
    if (PublishCloudPolicy(cloudVersion) != CM_SUCCESS) {
        (void)CmCloudStoreCleanupTmpDir();
        return;
    }

    (void)CmCloudStoreCleanupTmpDir();

    /* best-effort notification of the force-check readers: the policy is
     * already published and versioned, a dropped event must not roll
     * the round back */
#ifdef CM_TEST_API_ENABLE
    if (g_publishEventForTest != nullptr) {
        (void)g_publishEventForTest();
    } else {
        (void)CmPublishForceCheckPolicyUpdatedEvent();
    }
#else
    (void)CmPublishForceCheckPolicyUpdatedEvent();
#endif

    RenewUnloadTimer();
}
