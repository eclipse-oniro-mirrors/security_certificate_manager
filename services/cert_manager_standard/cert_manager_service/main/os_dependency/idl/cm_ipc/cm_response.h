/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CM_RESPONSE_H
#define CM_RESPONSE_H

#include "cm_type_inner.h"

/* capacity of the IPC reply parcel, applied by CmSendResponse */
#define CM_IPC_REPLY_MAX_CAPACITY (1 * 1024 * 1024)

/* bytes CmSendResponse writes into the reply parcel before the response body:
 * the int32 result code and the uint32 response length */
#define CM_IPC_REPLY_HEADER_SIZE (sizeof(int32_t) + sizeof(uint32_t))

#ifdef __cplusplus
extern "C" {
#endif

void CmSendResponse(const struct CmContext *context, int32_t result, const struct CmBlob *response);

void CmSendResponseParcel(uint32_t code, const struct CmContext *context, int32_t result, void *data);

int32_t CmGetProcessInfoForIPC(struct CmContext *cmContext);

#ifdef __cplusplus
}
#endif

#endif
