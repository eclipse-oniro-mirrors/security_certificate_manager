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

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>

#include "cm_type.h"

/* the settingsdata table keyword holding the cloud-pushed cert revocation
 * policy state; the VALUE column read for it is attacker-controllable
 * cloud input and is only ever consumed through CmCloudParseSettingValue */
inline constexpr char CM_CLOUD_SETTINGS_KEYWORD[] =
    "certManagerConfig_com.huawei.certmanager_certmanager_config";

/*
 * Strictly parse a settings VALUE of the shape "<version>,<download date>".
 *
 * The VALUE arrives from an external cloud channel and must be treated as
 * hostile: it must contain a comma, and the version field before the comma
 * must be non-empty ASCII digits only. The explicit digit walk rejects a
 * leading '-' (and any other sign, space or junk) BEFORE the numeric
 * parse runs, because a silently wrapped "-1" would gate a needless sync
 * round as a phantom new version. The parse must stay in range (a value
 * above UINT64_MAX is malformed, not a version) and must consume exactly
 * the digit field, never past the comma. On any rule violation the
 * function returns CMR_ERROR_INVALID_ARGUMENT and leaves versionOut
 * untouched.
 *
 * Inline here rather than in cm_cloud_setting_helper.cpp because the
 * unit test binary compiles the parse suite against this header alone,
 * without linking the DataShare-dependent query TU.
 *
 * @param value the raw settings VALUE string, never trusted
 * @param versionOut receives the parsed version on success only
 * @return CM_SUCCESS with versionOut set, or CMR_ERROR_INVALID_ARGUMENT
 *         for an empty string, a missing comma, a non-numeric version
 *         field, a leading '-' or any overflow of uint64
 */
inline int32_t CmCloudParseSettingValue(const std::string &value, uint64_t &versionOut)
{
    const std::size_t commaPos = value.find(',');
    if (commaPos == std::string::npos || commaPos == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    for (std::size_t i = 0; i < commaPos; ++i) {
        if (value[i] < '0' || value[i] > '9') {
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }

    uint64_t parsed = 0;
    /* safe only because the field was proven all-digits above: from_chars
     * consumes exactly the digit field and stops on the comma; a digit
     * count above UINT64_MAX reports result_out_of_range, not a version */
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + commaPos, parsed);
    if ((ec != std::errc()) || (ptr != value.data() + commaPos)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    versionOut = parsed;
    return CM_SUCCESS;
}

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
