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

#include "cm_cert_status_event.h"

#include <cstring>
#include <string>
#include <vector>

#include "want.h"

#include "cm_cert_status_event_publish.h"
#include "cm_log.h"
#include "cm_type.h"

int32_t CmPublishSystemCaStatusEvent(const char *certUri, uint32_t status)
{
    if (certUri == nullptr || certUri[0] == '\0') {
        CM_LOG_E("invalid cert uri for system ca status event");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strlen(certUri) >= MAX_LEN_URI) {
        CM_LOG_E("cert uri too long for system ca status event");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (status != CERT_STATUS_ENABLED && status != CERT_STATUS_DISABLED) {
        CM_LOG_E("invalid status for system ca status event, status = %u", status);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    bool enabled = (status == CERT_STATUS_ENABLED);
    OHOS::AAFwk::Want want;
    want.SetAction(CM_EVENT_ACTION_SYSTEM_CA_STATUS_CHANGED);
    want.SetParam(CM_EVENT_PARAM_CERT_URI, std::string(certUri));
    want.SetParam(CM_EVENT_PARAM_ENABLED, enabled);

    std::vector<std::string> subscriberPermissions = { CM_EVENT_SUBSCRIBER_PERMISSION };
    if (!CmPublishCommonEventToCes(want, subscriberPermissions)) {
        CM_LOG_E("publish system ca status event failed, uri = %s", certUri);
        return CMR_ERROR;
    }

    CM_LOG_I("publish system ca status event, uri = %s, enabled = %d", certUri, enabled);
    return CM_SUCCESS;
}
