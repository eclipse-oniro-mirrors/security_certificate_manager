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

#include "cm_cloud_setting_value.h"

#include <charconv>
#include <cstddef>
#include <system_error>

int32_t CmCloudParseSettingValue(const std::string &value, uint64_t &versionOut)
{
    const std::size_t commaPos = value.find(',');
    if (commaPos == std::string::npos || commaPos == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    for (std::size_t i = 0; i < commaPos; ++i) {
        if (value[i] < '0' || value[i] > '9') {
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }

    uint64_t parsed = 0;
    /* safe only because the field was proven all-digits above: from_chars
     * consumes exactly the digit field and stops on the comma; a digit
     * count above UINT64_MAX reports result_out_of_range, not a version */
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + commaPos, parsed);
    if ((ec != std::errc()) || (ptr != value.data() + commaPos)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    versionOut = parsed;
    return CM_SUCCESS;
}
