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

#ifndef CM_CERT_STATUS_EVENT_H
#define CM_CERT_STATUS_EVENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* custom common event published after a system root CA certificate status
 * change has been committed by the cert manager service */
#define CM_EVENT_ACTION_SYSTEM_CA_STATUS_CHANGED "action.certmanager.systemCaStatusChanged"
#define CM_EVENT_PARAM_CERT_URI                  "certUri"
#define CM_EVENT_PARAM_ENABLED                   "enabled"
/* subscribers must hold the internal cert manager permission, the same
 * permission checked on the set-status path */
#define CM_EVENT_SUBSCRIBER_PERMISSION           "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"

/*
 * Publish the system CA status changed common event.
 *
 * @param certUri the uri of the system root CA whose status changed
 * @param status CERT_STATUS_ENABLED or CERT_STATUS_DISABLED
 * @return CM_SUCCESS on publish; CMR_ERROR_INVALID_ARGUMENT on bad input;
 *         CMR_ERROR when the publish call fails. Best-effort by design:
 *         the status change has already been committed when this is called,
 *         so callers should not fail the committed operation on this result.
 */
int32_t CmPublishSystemCaStatusEvent(const char *certUri, uint32_t status);

#ifdef __cplusplus
}
#endif

#endif /* CM_CERT_STATUS_EVENT_H */
