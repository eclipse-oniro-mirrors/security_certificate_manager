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
#include <cstring>
#include <string>
#include <vector>

#include "securec.h"
#include "cert_manager_api.h"
#include "cert_manager_service.h"
#include "cm_config_type.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_test_log.h"
#include "cm_type.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
static uint32_t g_selfTokenId = 0;
static MockHapToken *g_MockHap = nullptr;

/* supported config keys (must match g_supportedConfigKeys in cert_manager_check.c) */
static const char *SUPPORTED_KEY_DEFAULT_CONFIG = "installGlobalUserCA_defaultConfig";
static const char *SUPPORTED_KEY_ENABLE_LIST = "enableInstallGlobalUserCA_userList";
static const char *SUPPORTED_KEY_DISABLE_LIST = "disableInstallGlobalUserCA_userList";

static struct CmConfigItem g_setItems[3];

static void InitSetItems()
{
    (void)memset_s(g_setItems, sizeof(g_setItems), 0, sizeof(g_setItems));
    (void)strcpy_s(g_setItems[0].key, MAX_LEN_CONFIG_KEY, SUPPORTED_KEY_DEFAULT_CONFIG);
    (void)strcpy_s(g_setItems[0].value, MAX_LEN_CONFIG_VALUE, "disable");
    (void)strcpy_s(g_setItems[1].key, MAX_LEN_CONFIG_KEY, SUPPORTED_KEY_ENABLE_LIST);
    (void)strcpy_s(g_setItems[1].value, MAX_LEN_CONFIG_VALUE, "100,200");
    (void)strcpy_s(g_setItems[2].key, MAX_LEN_CONFIG_KEY, SUPPORTED_KEY_DISABLE_LIST);
    (void)strcpy_s(g_setItems[2].value, MAX_LEN_CONFIG_VALUE, "300");
}

class CmCertManagerConfigTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CmCertManagerConfigTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    CmTestCommon::SetTestEnvironment(g_selfTokenId);
}

void CmCertManagerConfigTest::TearDownTestCase(void)
{
    CmTestCommon::ResetTestEnvironment();
}

void CmCertManagerConfigTest::SetUp()
{
    InitSetItems();
    g_MockHap = new (std::nothrow) MockHapToken();
}

void CmCertManagerConfigTest::TearDown()
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }
}

static struct CmBlob *BuildKeysBlob(const std::vector<std::string> &keys)
{
    if (keys.empty()) {
        return nullptr;
    }
    uint32_t totalSize = 1; /* trailing \0 */
    for (const auto &k : keys) {
        totalSize += static_cast<uint32_t>(k.size()) + 1;
    }
    uint8_t *buf = static_cast<uint8_t *>(CmMalloc(totalSize));
    if (buf == nullptr) {
        return nullptr;
    }
    (void)memset_s(buf, totalSize, 0, totalSize);
    uint32_t offset = 0;
    for (const auto &k : keys) {
        if (memcpy_s(buf + offset, totalSize - offset, k.c_str(), k.size() + 1) != EOK) {
            CM_FREE_PTR(buf);
            return nullptr;
        }
        offset += static_cast<uint32_t>(k.size()) + 1;
    }
    struct CmBlob *blob = static_cast<struct CmBlob *>(CmMalloc(sizeof(struct CmBlob)));
    if (blob == nullptr) {
        CM_FREE_PTR(buf);
        return nullptr;
    }
    blob->data = buf;
    blob->size = totalSize;
    return blob;
}

static void FreeKeysBlob(struct CmBlob *&blob)
{
    if (blob == nullptr) {
        return;
    }
    CM_FREE_PTR(blob->data);
    CmFree(blob);
    blob = nullptr;
}
}  // namespace

/**
 * @tc.name: SetAndGetConfig001
 * @tc.desc: Test CmServiceSetCertManagerConfig and CmServiceGetCertManagerConfig round-trip
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, SetAndGetConfig001, TestSize.Level0)
{
    struct CertManagerConfig setConfig = {
        .count = sizeof(g_setItems) / sizeof(g_setItems[0]),
        .configItems = g_setItems,
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceSetCertManagerConfig failed, ret = " << ret;

    struct CertManagerConfig getConfig = { 0, nullptr };
    ret = CmServiceGetCertManagerConfig(nullptr, &getConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceGetCertManagerConfig(NULL) failed, ret = " << ret;
    EXPECT_EQ(getConfig.count, setConfig.count) << "config count mismatch";

    CmFreeCertManagerConfig(&getConfig);
}

/**
 * @tc.name: GetConfigBySingleKey002
 * @tc.desc: Test CmServiceGetCertManagerConfig with a single key
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, GetConfigBySingleKey002, TestSize.Level0)
{
    /* ensure the key is set */
    struct CertManagerConfig setConfig = {
        .count = 1,
        .configItems = &g_setItems[0],
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceSetCertManagerConfig failed, ret = " << ret;

    struct CmBlob *keysBlob = BuildKeysBlob({ SUPPORTED_KEY_DEFAULT_CONFIG });
    ASSERT_NE(keysBlob, nullptr);

    struct CertManagerConfig getConfig = { 0, nullptr };
    ret = CmServiceGetCertManagerConfig(keysBlob, &getConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceGetCertManagerConfig(single key) failed, ret = " << ret;
    EXPECT_GE(getConfig.count, 1u) << "should return at least 1 item";

    bool found = false;
    for (uint32_t i = 0; i < getConfig.count; i++) {
        if (strcmp(getConfig.configItems[i].key, SUPPORTED_KEY_DEFAULT_CONFIG) == 0) {
            EXPECT_STREQ(getConfig.configItems[i].value, "disable");
            found = true;
        }
    }
    EXPECT_TRUE(found) << "key not found in result";

    CmFreeCertManagerConfig(&getConfig);
    FreeKeysBlob(keysBlob);
}

/**
 * @tc.name: GetConfigByMultiKeys003
 * @tc.desc: Test CmServiceGetCertManagerConfig with multiple keys
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, GetConfigByMultiKeys003, TestSize.Level0)
{
    /* set all keys */
    struct CertManagerConfig setConfig = {
        .count = sizeof(g_setItems) / sizeof(g_setItems[0]),
        .configItems = g_setItems,
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceSetCertManagerConfig failed, ret = " << ret;

    struct CmBlob *keysBlob = BuildKeysBlob({
        SUPPORTED_KEY_DEFAULT_CONFIG,
        SUPPORTED_KEY_ENABLE_LIST,
        SUPPORTED_KEY_DISABLE_LIST,
    });
    ASSERT_NE(keysBlob, nullptr);

    struct CertManagerConfig getConfig = { 0, nullptr };
    ret = CmServiceGetCertManagerConfig(keysBlob, &getConfig);
    EXPECT_EQ(ret, CM_SUCCESS) << "CmServiceGetCertManagerConfig(multi keys) failed, ret = " << ret;
    EXPECT_EQ(getConfig.count, 3u) << "should return 3 items";

    CmFreeCertManagerConfig(&getConfig);
    FreeKeysBlob(keysBlob);
}

/**
 * @tc.name: GetConfigInvalidKey004
 * @tc.desc: Test CmServiceGetCertManagerConfig with an unsupported key
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, GetConfigInvalidKey004, TestSize.Level0)
{
    struct CmBlob *keysBlob = BuildKeysBlob({ "unsupported_key_name" });
    ASSERT_NE(keysBlob, nullptr);

    struct CertManagerConfig getConfig = { 0, nullptr };
    int32_t ret = CmServiceGetCertManagerConfig(keysBlob, &getConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "unsupported key should return invalid argument";

    CmFreeCertManagerConfig(&getConfig);
    FreeKeysBlob(keysBlob);
}

/**
 * @tc.name: SetConfigInvalidValue005
 * @tc.desc: Test CmServiceSetCertManagerConfig with an invalid value for defaultConfig
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, SetConfigInvalidValue005, TestSize.Level0)
{
    struct CmConfigItem badItem;
    (void)memset_s(&badItem, sizeof(badItem), 0, sizeof(badItem));
    (void)strcpy_s(badItem.key, MAX_LEN_CONFIG_KEY, SUPPORTED_KEY_DEFAULT_CONFIG);
    (void)strcpy_s(badItem.value, MAX_LEN_CONFIG_VALUE, "invalid_value");

    struct CertManagerConfig setConfig = {
        .count = 1,
        .configItems = &badItem,
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "invalid value should return invalid argument";
}

/**
 * @tc.name: SetConfigNullParam006
 * @tc.desc: Test CmServiceSetCertManagerConfig with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, SetConfigNullParam006, TestSize.Level0)
{
    int32_t ret = CmServiceSetCertManagerConfig(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "null config should return invalid argument";

    struct CertManagerConfig emptyConfig = { 0, nullptr };
    ret = CmServiceSetCertManagerConfig(&emptyConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "zero count config should return invalid argument";
}

/**
 * @tc.name: GetConfigNullParam007
 * @tc.desc: Test CmServiceGetCertManagerConfig with null config out param
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, GetConfigNullParam007, TestSize.Level0)
{
    // both keysBlob and config are null
    int32_t ret = CmServiceGetCertManagerConfig(nullptr, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "both null should return invalid argument";

    // keysBlob is null, config is not null
    struct CertManagerConfig outConfig = { 0, nullptr };
    ret = CmServiceGetCertManagerConfig(nullptr, &outConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "null keysBlob should return invalid argument";
    CmFreeCertManagerConfig(&outConfig);

    // keysBlob has null data
    struct CmBlob emptyBlob = { nullptr, 0 };
    ret = CmServiceGetCertManagerConfig(&emptyBlob, &outConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "null keysBlob data should return invalid argument";
    CmFreeCertManagerConfig(&outConfig);

    // keysBlob has zero size
    uint8_t dummy = 0;
    struct CmBlob zeroBlob = { &dummy, 0 };
    ret = CmServiceGetCertManagerConfig(&zeroBlob, &outConfig);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_ARGUMENT) << "zero-size keysBlob should return invalid argument";
    CmFreeCertManagerConfig(&outConfig);
}

/**
 * @tc.name: SetConfigNotSystemApp008
 * @tc.desc: Test CmServiceSetCertManagerConfig without system app identity
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, SetConfigNotSystemApp008, TestSize.Level0)
{
    /* TearDown deletes MockHapToken, restoring the original (non-system) token */
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }

    struct CertManagerConfig setConfig = {
        .count = 1,
        .configItems = &g_setItems[0],
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    /* without ACCESS_CERT_MANAGER_INTERNAL permission, should be denied */
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED) << "non-privileged caller should be denied";
}

/**
 * @tc.name: GetConfigNotSystemApp009
 * @tc.desc: Test CmServiceGetCertManagerConfig without system app identity
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, GetConfigNotSystemApp009, TestSize.Level0)
{
    if (g_MockHap != nullptr) {
        delete g_MockHap;
        g_MockHap = nullptr;
    }

    struct CertManagerConfig getConfig = { 0, nullptr };
    int32_t ret = CmServiceGetCertManagerConfig(nullptr, &getConfig);
    /* without ACCESS_CERT_MANAGER permission or system app, should be denied */
    EXPECT_EQ(ret, CMR_ERROR_PERMISSION_DENIED) << "non-system caller should be denied";

    CmFreeCertManagerConfig(&getConfig);
}

/**
 * @tc.name: FreeCertManagerConfig010
 * @tc.desc: Test CmFreeCertManagerConfig with null and after get
 * @tc.type: FUNC
 */
HWTEST_F(CmCertManagerConfigTest, FreeCertManagerConfig010, TestSize.Level0)
{
    /* free null should not crash */
    CmFreeCertManagerConfig(nullptr);

    struct CertManagerConfig emptyConfig = { 0, nullptr };
    CmFreeCertManagerConfig(&emptyConfig);
    EXPECT_EQ(emptyConfig.count, 0u);

    /* set then get, then free */
    struct CertManagerConfig setConfig = {
        .count = 1,
        .configItems = &g_setItems[0],
    };
    int32_t ret = CmServiceSetCertManagerConfig(&setConfig);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CertManagerConfig getConfig = { 0, nullptr };
    ret = CmServiceGetCertManagerConfig(nullptr, &getConfig);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeCertManagerConfig(&getConfig);
    EXPECT_EQ(getConfig.count, 0u);
    EXPECT_EQ(getConfig.configItems, nullptr);
}
