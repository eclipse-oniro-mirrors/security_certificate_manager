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

#include <gtest/gtest.h>

#include <climits>
#include <cstdint>

#include "cm_cloud_setting_helper.h"

namespace {
/* preloaded into versionOut before every parse call: the fail cases
 * assert the parser leaves it untouched, so a wrapped or partially
 * written "-1" cannot slip through; it deliberately differs from
 * ULLONG_MAX so the assertion is not vacuous */
constexpr uint64_t VERSION_SENTINEL = 0x5A5A5A5A5A5A5A5A;
} // namespace

/* the settings VALUE is attacker-controllable cloud input: these cases
 * pin the strict shape "<digits>,<download date>" the parser accepts */
TEST(CmCloudSettingValueTest, ParseSettingValueSuccess)
{
    uint64_t version = VERSION_SENTINEL;
    int32_t ret = CmCloudParseSettingValue("5,2026-11-18", version);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(version, 5U);
}

TEST(CmCloudSettingValueTest, ParseSettingValueNoCommaFails)
{
    uint64_t version = VERSION_SENTINEL;
    int32_t ret = CmCloudParseSettingValue("5", version);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(version, VERSION_SENTINEL);
}

TEST(CmCloudSettingValueTest, ParseSettingValueEmptyFails)
{
    uint64_t version = VERSION_SENTINEL;
    int32_t ret = CmCloudParseSettingValue("", version);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(version, VERSION_SENTINEL);
}

TEST(CmCloudSettingValueTest, ParseSettingValueNonNumericFails)
{
    uint64_t version = VERSION_SENTINEL;
    int32_t ret = CmCloudParseSettingValue("abc,d", version);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(version, VERSION_SENTINEL);
}

TEST(CmCloudSettingValueTest, ParseSettingValueNegativeFails)
{
    uint64_t version = VERSION_SENTINEL;
    int32_t ret = CmCloudParseSettingValue("-1,d", version);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    /* the sentinel surviving proves the leading '-' was rejected before
     * a wrapped parse could yield ULLONG_MAX and gate a needless sync */
    EXPECT_EQ(version, VERSION_SENTINEL);
    EXPECT_NE(version, ULLONG_MAX);
}

TEST(CmCloudSettingValueTest, ParseSettingValueOverflowFails)
{
    uint64_t version = VERSION_SENTINEL;
    /* 2^64: one past the last uint64 value */
    int32_t ret = CmCloudParseSettingValue("18446744073709551616,d", version);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(version, VERSION_SENTINEL);
}

/* the gate: only a strictly newer cloud version triggers a sync round */
TEST(CmCloudSettingValueTest, VersionNeedsSyncGate)
{
    EXPECT_TRUE(CmCloudVersionNeedsSync(5, 4));
    EXPECT_FALSE(CmCloudVersionNeedsSync(5, 5));
    EXPECT_FALSE(CmCloudVersionNeedsSync(4, 5));
    EXPECT_FALSE(CmCloudVersionNeedsSync(0, 0));
}
