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
#include <functional>
#include <string>
#include <vector>

#include "want.h"

#include "cert_manager_thread_pool.h"
#include "cm_cert_status_event_publish.h"
#include "cm_log.h"
#include "cm_type.h"

namespace {
/* retry policy for the broadcast: at most 3 delayed retries, 50ms apart,
 * after the first synchronous publish attempt fails */
constexpr uint32_t CM_STATUS_EVENT_RETRY_DELAY_MS = 50;
constexpr uint32_t CM_STATUS_EVENT_MAX_RETRY_COUNT = 3;

bool CmPublishSystemCaStatusEventNow(const OHOS::AAFwk::Want &want)
{
    std::vector<std::string> subscriberPermissions = { CM_EVENT_SUBSCRIBER_PERMISSION };
    return CmPublishCommonEventToCes(want, subscriberPermissions);
}

void CmRetrySystemCaStatusEvent(OHOS::AAFwk::Want want, uint32_t remainingRetry)
{
    if (CmPublishSystemCaStatusEventNow(want)) {
        CM_LOG_I("system ca status event published on retry");
        return;
    }
    if (remainingRetry == 0) {
        CM_LOG_E("system ca status event dropped, retries exhausted");
        return;
    }
    int32_t ret = CmThreadPoolPost(
        std::bind(CmRetrySystemCaStatusEvent, want, remainingRetry - 1), CM_STATUS_EVENT_RETRY_DELAY_MS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("schedule retry of system ca status event failed, ret = %d", ret);
    }
}
} // namespace

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

    if (CmPublishSystemCaStatusEventNow(want)) {
        CM_LOG_I("publish system ca status event, uri = %s, enabled = %d", certUri, enabled);
        return CM_SUCCESS;
    }

    /* first attempt failed: hand the retry chain to the generic pool so the
     * IPC thread returns immediately; delivery stays best-effort */
    CM_LOG_E("publish system ca status event failed, uri = %s, enqueue retry", certUri);
    int32_t ret = CmThreadPoolPost(
        std::bind(CmRetrySystemCaStatusEvent, want, CM_STATUS_EVENT_MAX_RETRY_COUNT - 1),
        CM_STATUS_EVENT_RETRY_DELAY_MS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("enqueue retry of system ca status event failed, ret = %d", ret);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}
