/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CERT_UTIL_H
#define CERT_UTIL_H

#include <stdint.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

int32_t CmIsNumeric(const char *str, const size_t length, uint32_t *value);

#ifdef __cplusplus
}
#endif
#endif
