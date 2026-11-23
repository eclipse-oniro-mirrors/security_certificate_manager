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

#ifndef CM_CLOUD_SETTING_HELPER_H
#define CM_CLOUD_SETTING_HELPER_H

#include <cstdint>
#include <string>

#include "cm_cloud_setting_value.h"
#include "cm_type.h"

/* the settingsdata table keyword holding the cloud-pushed cert revocation
 * policy state; the VALUE column read for it is attacker-controllable
 * cloud input and is only ever consumed through CmCloudParseSettingValue
 * (declared in cm_cloud_setting_value.h) */
inline constexpr char CM_CLOUD_SETTINGS_KEYWORD[] =
    "certManagerConfig_com.huawei.certmanager.certRevocationPolicy_config";

/*
 * The sync gate: a download round is needed only when the cloud advertises
 * a strictly newer version than the published local one. Equal versions
 * (the steady state) and stale cloud values (a rollback or a replayed
 * push) must not trigger a sync.
 *
 * @param cloudVersion the version parsed from the settings VALUE
 * @param localVersion the version of the published local policy
 * @return true when cloudVersion is strictly greater than localVersion
 */
inline bool CmCloudVersionNeedsSync(uint64_t cloudVersion, uint64_t localVersion)
{
    return cloudVersion > localVersion;
}

/*
 * Query the cloud-pushed policy version from the DataShare settings table
 * and parse it with CmCloudParseSettingValue. Implemented in
 * cm_cloud_setting_helper.cpp following the print_fwk settings query
 * precedent: samgr -> SA 3512 remote -> DataShareHelper -> Query the
 * KEYWORD row -> read VALUE -> strict parse.
 *
 * Fail-closed and quiet by design: a missing key, an unreachable settings
 * service, an empty result or a malformed VALUE returns a negative code
 * and the caller (the sync orchestration) ends the round silently, without
 * fault reporting and without retries. No local stub exists for the live
 * DataShare settings service; runtime behavior is covered by the
 * orchestration test stub and on-device manual steps.
 *
 * @param versionOut receives the parsed cloud version on success only
 * @return CM_SUCCESS with versionOut set, or a negative CmErrorCode when
 *         any step of the query fails or the VALUE does not parse
 */
int32_t CmCloudQuerySettingVersion(uint64_t &versionOut);

#endif /* CM_CLOUD_SETTING_HELPER_H */
