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

#ifndef CM_CLOUD_SETTING_VALUE_H
#define CM_CLOUD_SETTING_VALUE_H

#include <cstdint>
#include <string>

#include "cm_type.h"

/*
 * Strictly parse a settings VALUE of the shape "<version>,<download date>".
 *
 * The VALUE arrives from an external cloud channel and must be treated as
 * hostile: it must contain a comma, and the version field before the comma
 * must be non-empty ASCII digits only. The explicit digit walk rejects a
 * leading '-' (and any other sign, space or junk) BEFORE the numeric
 * parse runs, because a silently wrapped "-1" would gate a needless sync
 * round as a phantom new version. The parse must stay in range (a value
 * above UINT64_MAX is malformed, not a version) and must consume exactly
 * the digit field, never past the comma. On any rule violation the
 * function returns CMR_ERROR_INVALID_ARGUMENT and leaves versionOut
 * untouched.
 *
 * Split from cm_cloud_setting_helper.h into its own TU: the unit test
 * binary compiles the parse suite against this small module alone,
 * without linking the DataShare-dependent query TU.
 *
 * @param value the raw settings VALUE string, never trusted
 * @param versionOut receives the parsed version on success only
 * @return CM_SUCCESS with versionOut set, or CMR_ERROR_INVALID_ARGUMENT
 *         for an empty string, a missing comma, a non-numeric version
 *         field, a leading '-' or any overflow of uint64
 */
int32_t CmCloudParseSettingValue(const std::string &value, uint64_t &versionOut);

#endif /* CM_CLOUD_SETTING_VALUE_H */
