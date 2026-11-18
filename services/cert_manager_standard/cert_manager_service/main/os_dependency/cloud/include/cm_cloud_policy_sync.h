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

#ifndef CM_CLOUD_POLICY_SYNC_H
#define CM_CLOUD_POLICY_SYNC_H

#include <cstdint>
#include <functional>

/*
 * Inject the SA idle-unload renewal hook (the ukey dialog
 * SetUnloadRenewal pattern): the sync round runs on a pool worker with no
 * IPC traffic to reset the idle-unload timer, so the timer is renewed at
 * Start, at the round's entry and at its exit. The sync module must not
 * depend on cm_sa.h, so the SA side injects the hook; passing an empty
 * function leaves the round running without renewals (the module test
 * shape, or a test injecting a counter).
 */
void CmCloudPolicySyncSetUnloadRenewal(std::function<void()> renewal);

/*
 * Kick off one cloud revocation policy sync round: renew the unload
 * timer once, then hand the round to the process pool fire-and-forget
 * (delay 0), so the SA startup path never waits on the network. A post
 * failure only logs and never affects the SA startup; the SA calls this
 * exactly once per OnStart, so at most one round is in flight (the store
 * and zip modules serialize their writers through fixed tmp names and
 * rely on that).
 */
void CmCloudPolicySyncStart(void);

/*
 * One full sync round, exported for the module test to drive directly
 * (never on the SA path itself except through the pool):
 *  1. renew the unload timer
 *  2. CmCloudStoreSelfHealPreset (a failure ends the round; the preset
 *     itself never publishes the update event)
 *  3. CmCloudStoreReadVersion (never fails: malformed reads as 0)
 *  4. CmCloudQuerySettingVersion (a failure ends the round quietly,
 *     without fault reporting)
 *  5. the CmCloudVersionNeedsSync gate (equal or stale cloud versions
 *     end the round quietly)
 *  6. CmCloudStoreCleanupTmpDir + PrepareTmpDir (clear any residue of
 *     an interrupted round, then stage this download)
 *  7. CmHsdrFetchCloudZip(CLOUD_POLICY_SCENE) (a failure cleans the
 *     staging dir and ends the round)
 *  8. CmCloudZipExtractWhitelisted into the staging dir
 *  9. CmCloudStorePublishFile(tmp/<scene.zipMember>, scene.destFile,
 *     scene.destMode) - only now does the published policy change
 * 10. CmCloudStoreWriteVersion(cloudVersion) - the version advances
 *     strictly after the file replacement, so a failure before this
 *     point makes the next SA start re-run the whole round (idempotent
 *     convergence)
 * 11. CmCloudStoreCleanupTmpDir
 * 12. CmPublishForceCheckPolicyUpdatedEvent, best-effort: a dropped
 *     event must not roll the published round back
 * 13. renew the unload timer
 *
 * Every step failure ends the round quietly: no fault reporting, no
 * retry. The zip blob is released with CM_FREE_BLOB on every path after
 * the fetch.
 */
void CmCloudPolicySyncTask(void);

/* test-only interfaces, compiled only when the build target defines
 * CM_TEST_API_ENABLE (the thread pool / dialog *ForTest precedent):
 * production artifacts carry none of these symbols, so a production call
 * site fails at compile time */
#ifdef CM_TEST_API_ENABLE
/*
 * Replace the final CmPublishForceCheckPolicyUpdatedEvent call for the
 * module test. The event publish cannot be a symbol stub there: the
 * module test binary already links cm_cert_status_event.cpp, which
 * defines the exported symbol, and a stub definition would collide with
 * it. When no publisher is installed the round calls the real one.
 *
 * @param publisher the test recorder, or nullptr to restore the real
 *        event publish
 */
void CmCloudPolicySyncSetEventPublisherForTest(int32_t (*publisher)(void));
#endif /* CM_TEST_API_ENABLE */

#endif /* CM_CLOUD_POLICY_SYNC_H */
