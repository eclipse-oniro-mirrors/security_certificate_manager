/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#ifndef CERT_MANAGER_STATUS_H
#define CERT_MANAGER_STATUS_H

#include "cert_manager_mem.h"
#include "cm_type.h"

#define  CERT_STATUS_ENANLED           ((uint32_t) 0)
#define  CERT_STATUS_DISABLED          ((uint32_t) 1)

#define ASSERT_ARGS(c) if (!(c)) { CM_LOG_W("Invalid args: %s\n", #c); return CMR_ERROR_INVALID_ARGUMENT; }

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status);

/* set the manual enable/disable state of one SYSTEM root CA certificate
 * (certUri must match a file enumerated from the system store); writes the
 * root_ca_cert_store row and regenerates the force-check policy file */
int32_t CmSetSystemCertStatus(const struct CmContext *context,
    const struct CmBlob *certUri, uint32_t status);

/* rewrite the force-check policy file from the disabled rows of
 * root_ca_cert_store (atomic tmp + rename); 0 bytes when nothing is disabled */
int32_t CmRegenerateRevocationPolicyFile(void);
#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_STATUS_H