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

#include "want.h"

#include "cert_manager_thread_pool.h"
#include "cm_cert_status_event_publish.h"
#include "cm_log.h"
#include "cm_root_ca_store_rdb.h"
#include "cm_type.h"

namespace {
/* retry policy for the broadcast: at most 3 delayed retries, 50ms apart,
 * after the first synchronous publish attempt fails */
constexpr uint32_t CM_STATUS_EVENT_RETRY_DELAY_MS = 50;
constexpr uint32_t CM_STATUS_EVENT_MAX_RETRY_COUNT = 3;

bool CmPublishCertStatusEventNow(const OHOS::AAFwk::Want &want)
{
    return CmPublishCommonEventToCes(want);
}

void CmRetryCertStatusEvent(OHOS::AAFwk::Want want, uint32_t remainingRetry)
{
    if (CmPublishCertStatusEventNow(want)) {
        CM_LOG_I("cert status event published on retry");
        return;
    }
    if (remainingRetry == 0) {
        CM_LOG_E("cert status event dropped, retries exhausted");
        return;
    }
    int32_t ret = CmThreadPoolPost(
        std::bind(CmRetryCertStatusEvent, want, remainingRetry - 1), CM_STATUS_EVENT_RETRY_DELAY_MS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("schedule retry of cert status event failed, ret = %d", ret);
    }
}

/* shared publish path: immediate attempt, then the delayed retry chain */
int32_t PublishCertStatusEvent(const OHOS::AAFwk::Want &want, const char *type, const char *operation)
{
    if (CmPublishCertStatusEventNow(want)) {
        CM_LOG_I("publish cert status event, type = %s, operation = %s", type, operation);
        return CM_SUCCESS;
    }

    /* first attempt failed: hand the retry chain to the generic pool so the
     * IPC thread returns immediately; delivery stays best-effort */
    CM_LOG_E("publish cert status event failed, type = %s, operation = %s, enqueue retry", type, operation);
    int32_t ret = CmThreadPoolPost(
        std::bind(CmRetryCertStatusEvent, want, CM_STATUS_EVENT_MAX_RETRY_COUNT - 1),
        CM_STATUS_EVENT_RETRY_DELAY_MS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("enqueue retry of cert status event failed, ret = %d", ret);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}
} // namespace

int32_t CmPublishSystemCaStatusEvent(const char *certPkHash, uint32_t status)
{
    if (certPkHash == nullptr || certPkHash[0] == '\0') {
        CM_LOG_E("invalid cert pk hash for system ca status event");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strlen(certPkHash) != CM_ROOT_CA_PK_HASH_HEX_LEN) {
        CM_LOG_E("cert pk hash must be %d hex chars, got %u",
            CM_ROOT_CA_PK_HASH_HEX_LEN, (uint32_t)strlen(certPkHash));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (status != CERT_STATUS_ENABLED && status != CERT_STATUS_DISABLED) {
        CM_LOG_E("invalid status for system ca status event, status = %u", status);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    const char *operation = (status == CERT_STATUS_ENABLED) ? CM_EVENT_OPERATION_ENABLE
                                                           : CM_EVENT_OPERATION_DISABLE;
    OHOS::AAFwk::Want want;
    want.SetAction(CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED);
    want.SetParam(CM_EVENT_PARAM_TYPE, std::string(CM_EVENT_TYPE_SYSTEM_CA));
    want.SetParam(CM_EVENT_PARAM_OPERATION, std::string(operation));
    want.SetParam(CM_EVENT_PARAM_DATA, std::string(certPkHash));

    return PublishCertStatusEvent(want, CM_EVENT_TYPE_SYSTEM_CA, operation);
}

int32_t CmPublishForceCheckPolicyUpdatedEvent(void)
{
    /* scenario REVOCATION_FORCE_CHECK: a cloud push updated the force-check
     * policy file; this scenario carries no data parameter */
    OHOS::AAFwk::Want want;
    want.SetAction(CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED);
    want.SetParam(CM_EVENT_PARAM_TYPE, std::string(CM_EVENT_TYPE_REVOCATION_FORCE_CHECK));
    want.SetParam(CM_EVENT_PARAM_OPERATION, std::string(CM_EVENT_OPERATION_UPDATE));

    return PublishCertStatusEvent(want, CM_EVENT_TYPE_REVOCATION_FORCE_CHECK, CM_EVENT_OPERATION_UPDATE);
}
