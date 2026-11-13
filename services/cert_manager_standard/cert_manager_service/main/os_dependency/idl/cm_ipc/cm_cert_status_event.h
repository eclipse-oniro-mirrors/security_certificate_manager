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

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* custom common event published by the cert manager service:
 * certmanager.event.CA_CERT_STATUS_CHANGED. Two scenarios, every parameter
 * value is a string:
 *  1. the user enabled/disabled a system root CA:
 *       type = SYSTEM_CA, operation = ENABLE or DISABLE,
 *       data = the pk hash of the changed certificate (SPKI SHA256,
 *       uppercase hex, CM_ROOT_CA_PK_HASH_HEX_LEN chars) - the same value
 *       stored in root_ca_cert_store and written to the force-check
 *       policy file
 *  2. reserved, no publisher yet: a cloud push updated the force-check
 *       policy file: type = REVOCATION_FORCE_CHECK, operation = UPDATE;
 *       this scenario carries no data parameter */
#define CM_EVENT_ACTION_CA_CERT_STATUS_CHANGED "certmanager.event.CA_CERT_STATUS_CHANGED"

#define CM_EVENT_PARAM_TYPE      "type"
#define CM_EVENT_PARAM_OPERATION "operation"
#define CM_EVENT_PARAM_DATA      "data"

#define CM_EVENT_TYPE_SYSTEM_CA              "SYSTEM_CA"
#define CM_EVENT_TYPE_REVOCATION_FORCE_CHECK "REVOCATION_FORCE_CHECK"

#define CM_EVENT_OPERATION_ENABLE  "ENABLE"
#define CM_EVENT_OPERATION_DISABLE "DISABLE"
#define CM_EVENT_OPERATION_UPDATE  "UPDATE"

/*
 * Publish scenario 1: the user enabled or disabled a system root CA.
 *
 * @param certPkHash the pk hash of the changed certificate, carried in
 *        the data parameter (CM_ROOT_CA_PK_HASH_HEX_LEN uppercase hex
 *        chars, NUL-terminated)
 * @param status CERT_STATUS_ENABLED or CERT_STATUS_DISABLED, deciding
 *        the operation parameter
 * @return CM_SUCCESS on publish; CMR_ERROR_INVALID_ARGUMENT on bad input;
 *         CMR_ERROR when the publish call fails. Best-effort by design:
 *         the status change has already been committed when this is called,
 *         so callers should not fail the committed operation on this result.
 */
int32_t CmPublishSystemCaStatusEvent(const char *certPkHash, uint32_t status);

/*
 * Publish scenario 2 (reserved, no caller yet): a cloud push updated the
 * force-check policy file. Same best-effort contract as scenario 1.
 */
int32_t CmPublishForceCheckPolicyUpdatedEvent(void);

#ifdef __cplusplus
}
#endif

#endif /* CM_CERT_STATUS_EVENT_H */
