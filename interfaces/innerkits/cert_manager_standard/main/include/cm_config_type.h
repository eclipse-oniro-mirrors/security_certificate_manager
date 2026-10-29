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

#ifndef CM_CONFIG_TYPE_H
#define CM_CONFIG_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LEN_CONFIG_KEY       64
#define MAX_LEN_CONFIG_VALUE     1024
#define MAX_COUNT_CONFIG_ITEM    4

struct CmConfigItem {
    char key[MAX_LEN_CONFIG_KEY];
    char value[MAX_LEN_CONFIG_VALUE];
};

struct CertManagerConfig {
    uint32_t count;
    struct CmConfigItem *configItems;
};

#ifdef __cplusplus
}
#endif

#endif /* CM_CONFIG_TYPE_H */
