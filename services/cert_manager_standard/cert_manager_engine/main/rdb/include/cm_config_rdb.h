/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CM_CONFIG_RDB_H
#define CM_CONFIG_RDB_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateCertManagerConfigRdb(void);

int32_t InsertOrUpdateConfig(const char *key, const char *value);

int32_t QueryConfigByKey(const char *key, char *value, uint32_t valueLen);

int32_t QueryAllConfig(struct CertManagerConfig *config);

#ifdef __cplusplus
}
#endif

#endif // CM_CONFIG_RDB_H
