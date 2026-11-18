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

#include "cm_cloud_setting_helper.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "datashare_helper.h"
#include "iservice_registry.h"

#include "cm_log.h"
#include "cm_sa.h"

namespace {
/* the global settings table and its DataAbility extension, the same
 * endpoints the print_fwk settings helper reads; module-internal so no
 * other unit can build a settings query of its own from this header */
const char SETTINGS_DATA_URI[] =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
const char SETTINGS_DATA_EXT_URI[] = "datashare:///com.ohos.settingsdata.DataAbility";
/* settings table columns: the keyword to match and the VALUE to read */
const char SETTINGS_KEYWORD_COLUMN[] = "KEYWORD";
const char SETTINGS_VALUE_COLUMN[] = "VALUE";

/* the certificate manager SA id (3512), the token whose remote object
 * authorizes the silent DataShare settings access */
using OHOS::Security::CertManager::SA_ID_KEYSTORE_SERVICE;

/*
 * The DataShare query, print_fwk's print_setting_data_helper.cpp pattern:
 * samgr -> the SA 3512 remote object -> a DataShareHelper on the global
 * settings table -> the KEYWORD row -> the VALUE column. A fresh helper
 * is created per call and released on every return path.
 *
 * @param value receives the raw VALUE string on success
 * @return CM_SUCCESS, or CMR_ERROR when any step fails (no key row,
 *         unreachable settings service, empty result)
 */
int32_t QuerySettingValue(std::string &value)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> samgr =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        CM_LOG_E("cloud setting query failed, no system ability manager");
        return CMR_ERROR;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObj = samgr->GetSystemAbility(SA_ID_KEYSTORE_SERVICE);
    if (remoteObj == nullptr) {
        CM_LOG_E("cloud setting query failed, no keystore service remote");
        return CMR_ERROR;
    }
    auto [ret, helper] = OHOS::DataShare::DataShareHelper::Create(remoteObj, SETTINGS_DATA_URI,
        SETTINGS_DATA_EXT_URI);
    if (ret != 0 || helper == nullptr) {
        CM_LOG_E("cloud setting query failed, data share helper create ret = %d", ret);
        return CMR_ERROR;
    }

    const std::string keyword(CM_CLOUD_SETTINGS_KEYWORD);
    OHOS::Uri settingsUri = OHOS::Uri(std::string(SETTINGS_DATA_URI) + "&key=" + keyword);
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_KEYWORD_COLUMN, keyword);
    std::vector<std::string> columns;
    std::shared_ptr<OHOS::DataShare::DataShareResultSet> result =
        helper->Query(settingsUri, predicates, columns);
    if (result == nullptr) {
        CM_LOG_E("cloud setting query failed, empty result set");
        helper->Release();
        return CMR_ERROR;
    }
    if (result->GoToFirstRow() != OHOS::DataShare::E_OK) {
        CM_LOG_E("cloud setting query failed, no key row");
        result->Close();
        helper->Release();
        return CMR_ERROR;
    }

    int columnIndex = -1;
    if (result->GetColumnIndex(SETTINGS_VALUE_COLUMN, columnIndex) != OHOS::DataShare::E_OK) {
        CM_LOG_E("cloud setting query failed, no value column");
        result->Close();
        helper->Release();
        return CMR_ERROR;
    }
    /* the raw VALUE is cloud-pushed input: it is parsed below and never
     * logged or stored anywhere else */
    std::string rawValue = "";
    if (result->GetString(columnIndex, rawValue) != OHOS::DataShare::E_OK) {
        CM_LOG_E("cloud setting query failed, read value column");
        result->Close();
        helper->Release();
        return CMR_ERROR;
    }
    result->Close();
    helper->Release();

    value = rawValue;
    return CM_SUCCESS;
}
} // namespace

int32_t CmCloudQuerySettingVersion(uint64_t &versionOut)
{
    std::string value = "";
    int32_t ret = QuerySettingValue(value);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    /* strict parse of the hostile VALUE: a malformed push reports a
     * negative code, which the caller treats as "no round this time" */
    ret = CmCloudParseSettingValue(value, versionOut);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cloud setting value parse failed, ret = %d", ret);
        return ret;
    }
    CM_LOG_I("cloud setting version queried, version = %llu",
        static_cast<unsigned long long>(versionOut));
    return CM_SUCCESS;
}
