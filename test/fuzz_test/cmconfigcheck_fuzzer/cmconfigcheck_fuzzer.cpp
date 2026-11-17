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

#include "cmconfigcheck_fuzzer.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "cert_manager_check.h"
#include "cert_manager_service.h"
#include "cm_config_rdb.h"
#include "cm_config_type.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "securec.h"

using namespace CmFuzzTest;

namespace {
    const uint32_t UINT32_COUNT = 8;
    const uint32_t CONFIG_ITEM_SLOT_COUNT = 2; /* two selector pairs consumed up front */

    /* key pool: supported keys, the engine-managed protected key, an empty key,
     * an unsupported key and a key whose length is exactly MAX_LEN_CONFIG_KEY,
     * so every validation branch of the check helpers is reachable */
    const char *g_keyPool[] = {
        "installGlobalUserCA_defaultConfig",
        "enableInstallGlobalUserCA_userList",
        "disableInstallGlobalUserCA_userList",
        "last_cleanup_utc",
        "",
        "unsupported_key",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", /* len == MAX_LEN_CONFIG_KEY */
    };
    const uint32_t KEY_POOL_SIZE = sizeof(g_keyPool) / sizeof(g_keyPool[0]);

    /* value pool: both legal shapes plus the empty string (legal for user-list keys only) */
    const char *g_valuePool[] = { "enable", "disable", "100|101", "" };
    const uint32_t VALUE_POOL_SIZE = sizeof(g_valuePool) / sizeof(g_valuePool[0]);
    const uint32_t VALUE_SELECTOR_DYNAMIC = VALUE_POOL_SIZE; /* fuzzed dynamic string */

    /* named pool indices the keys-blob modes rely on */
    const uint32_t KEY_INDEX_DEFAULT_CONFIG = 0; /* "installGlobalUserCA_defaultConfig" */
    const uint32_t KEY_INDEX_USER_LIST = 1;      /* "enableInstallGlobalUserCA_userList" */
    const uint32_t KEY_INDEX_CLEANUP_UTC = 3;    /* "last_cleanup_utc" */
    const uint32_t KEY_INDEX_MAX_LEN = 6;        /* the MAX_LEN_CONFIG_KEY-sized key */

    /* keys buffer: room for three max-length keys plus terminators and slack */
    const uint32_t KEYS_BUF_KEY_CAPACITY = 3;
    const uint32_t KEYS_BUF_EXTRA_BYTES = 8;

    /* the non-system-app rejection of the get check runs on one selector in ten */
    const uint32_t NON_SYS_SELECTOR_MODULUS = 10;
    const uint32_t NON_SYS_SELECTOR_HIT = 9;

    /* keys-blob shapes driven by the mode selector */
    enum KeysBlobMode {
        KEYS_MODE_NULL_BLOB = 0,           /* NULL blob: query all config items */
        KEYS_MODE_EMPTY_BLOB = 1,          /* empty blob: query all config items */
        KEYS_MODE_TWO_SUPPORTED_KEYS = 2,  /* two supported keys: the multi-key loop */
        KEYS_MODE_MISSING_TERMINATOR = 3,  /* missing terminator: the not-null-terminated rejection */
        KEYS_MODE_MAX_LEN_KEY = 4,         /* key at exactly MAX_LEN_CONFIG_KEY: the strnlen break */
        KEYS_MODE_FUZZED_KEY = 5,          /* fuzzed key with terminator */
        KEYS_MODE_LEADING_TERMINATOR = 6,  /* leading terminator: zero-length key breaks the loop */
    };
    const uint32_t KEYS_BLOB_MODE_COUNT = KEYS_MODE_LEADING_TERMINATOR + 1;

    void CopyStringToBuffer(char *dst, uint32_t dstSize, const char *src)
    {
        size_t len = strlen(src);
        if (len >= dstSize) {
            len = dstSize - 1;
        }
        if (memcpy_s(dst, dstSize, src, len) != EOK) {
            dst[0] = '\0';
            return;
        }
        dst[len] = '\0';
    }

    /* fill one config item: the key comes from the semantic pool (so the
     * supported/protected/empty/unsupported/max-len branches stay reachable),
     * the value comes from the pool or, on selector, from the fuzzed string */
    void FillConfigItem(struct CmConfigItem *item, uint32_t keySelector,
        uint32_t valueSelector, const char *dynamicValue)
    {
        CopyStringToBuffer(item->key, sizeof(item->key), g_keyPool[keySelector % KEY_POOL_SIZE]);
        const char *value = nullptr;
        if (valueSelector % (VALUE_POOL_SIZE + 1) == VALUE_SELECTOR_DYNAMIC && dynamicValue != nullptr) {
            value = dynamicValue;
        } else {
            value = g_valuePool[valueSelector % VALUE_POOL_SIZE];
        }
        CopyStringToBuffer(item->value, sizeof(item->value), value);
    }

    /* case KEYS_MODE_TWO_SUPPORTED_KEYS: two supported keys, both NUL-terminated,
     * so the get path walks the multi-key loop */
    void BuildTwoSupportedKeysBlob(struct CmBlob *keysBlob, char *keysBuf, uint32_t keysBufSize)
    {
        uint32_t used = static_cast<uint32_t>(strlen(g_keyPool[KEY_INDEX_DEFAULT_CONFIG])) + 1;
        if (memcpy_s(keysBuf, keysBufSize, g_keyPool[KEY_INDEX_DEFAULT_CONFIG], used) != EOK) {
            keysBlob->size = 0;
            return;
        }
        if (strcat_s(keysBuf, keysBufSize, g_keyPool[KEY_INDEX_CLEANUP_UTC]) != EOK) {
            keysBlob->size = used; /* keep the first key only */
            return;
        }
        used += static_cast<uint32_t>(strlen(g_keyPool[KEY_INDEX_CLEANUP_UTC])) + 1;
        keysBlob->size = used;
    }

    /* case KEYS_MODE_FUZZED_KEY: the fuzzed key (or a pool fallback) with its
     * terminator, capped to the buffer */
    void BuildFuzzedKeyBlob(const char *dynamicKey, struct CmBlob *keysBlob, char *keysBuf,
        uint32_t keysBufSize)
    {
        if (dynamicKey == nullptr) {
            dynamicKey = g_keyPool[KEY_INDEX_USER_LIST];
        }
        keysBlob->size = static_cast<uint32_t>(strlen(dynamicKey)) + 1;
        if (keysBlob->size > keysBufSize) {
            keysBlob->size = keysBufSize;
        }
        if (memcpy_s(keysBuf, keysBufSize, dynamicKey, keysBlob->size) != EOK) {
            keysBuf[0] = '\0';
            keysBlob->size = 1;
        }
    }

    /* build the keys blob for the get path; *outPtr stays NULL for the
     * query-all branch, otherwise it points at a NUL-separated key list with
     * the exact shape the selected mode prescribes */
    void BuildKeysBlob(uint32_t mode, const char *dynamicKey, struct CmBlob **outPtr,
        struct CmBlob *keysBlob, char *keysBuf, uint32_t keysBufSize)
    {
        *outPtr = keysBlob;
        keysBlob->data = reinterpret_cast<uint8_t *>(keysBuf);
        keysBlob->size = 0;
        (void)memset_s(keysBuf, keysBufSize, 0, keysBufSize);

        switch (mode % KEYS_BLOB_MODE_COUNT) {
            case KEYS_MODE_NULL_BLOB:
                *outPtr = nullptr;
                return;
            case KEYS_MODE_EMPTY_BLOB:
                return;
            case KEYS_MODE_TWO_SUPPORTED_KEYS:
                BuildTwoSupportedKeysBlob(keysBlob, keysBuf, keysBufSize);
                return;
            case KEYS_MODE_MISSING_TERMINATOR:
                /* "last_cleanup_utc" without '\0' */
                keysBlob->size = static_cast<uint32_t>(strlen(g_keyPool[KEY_INDEX_CLEANUP_UTC]));
                if (memcpy_s(keysBuf, keysBufSize, g_keyPool[KEY_INDEX_CLEANUP_UTC],
                    keysBlob->size) != EOK) {
                    keysBlob->size = 0;
                }
                return;
            case KEYS_MODE_MAX_LEN_KEY:
                keysBlob->size = MAX_LEN_CONFIG_KEY + 1; /* key plus terminator */
                if (memcpy_s(keysBuf, keysBufSize, g_keyPool[KEY_INDEX_MAX_LEN], MAX_LEN_CONFIG_KEY) != EOK) {
                    keysBlob->size = 0;
                }
                return;
            case KEYS_MODE_FUZZED_KEY:
                BuildFuzzedKeyBlob(dynamicKey, keysBlob, keysBuf, keysBufSize);
                return;
            case KEYS_MODE_LEADING_TERMINATOR:
            default:
                keysBuf[0] = '\0';
                keysBlob->size = 1;
                return;
        }
    }

    /* parse the selector header and the two dynamic strings; returns false
     * when the fuzz input is too short to carry the full header */
    bool ParseConfigSelectors(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        uint32_t *keySel, uint32_t *valSel, uint32_t *countSel, uint32_t *keysMode,
        uint32_t *nonSysSel, char **dynamicValue, char **dynamicKey)
    {
        /* two selector pairs up front: the item slots consumed by count */
        for (uint32_t i = 0; i < CONFIG_ITEM_SLOT_COUNT; i++) {
            if (!GetUintFromBuffer(myData, remainSize, offset, &keySel[i]) ||
                !GetUintFromBuffer(myData, remainSize, offset, &valSel[i])) {
                return false;
            }
        }
        if (!GetUintFromBuffer(myData, remainSize, offset, countSel) ||
            !GetUintFromBuffer(myData, remainSize, offset, keysMode) ||
            !GetUintFromBuffer(myData, remainSize, offset, nonSysSel)) {
            return false;
        }
        /* dynamic value/key: parsing may fail (zero length), the pools cover it */
        (void)GetDynamicStringFromBuffer(myData, remainSize, offset, dynamicValue);
        (void)GetDynamicStringFromBuffer(myData, remainSize, offset, dynamicKey);
        return true;
    }

    /* build the item array: count folds to 0 (rejected), 1..MAX (accepted)
     * and MAX+1 (rejected); the array carries one extra slot so the >MAX
     * case stays in bounds */
    uint32_t BuildConfigItems(uint32_t countSel, const uint32_t *keySel, const uint32_t *valSel,
        const char *dynamicValue, struct CmConfigItem *items)
    {
        uint32_t count = countSel % (MAX_COUNT_CONFIG_ITEM + 2);
        for (uint32_t i = 0; i < count && i <= MAX_COUNT_CONFIG_ITEM; i++) {
            FillConfigItem(&items[i], keySel[i % CONFIG_ITEM_SLOT_COUNT],
                valSel[i % CONFIG_ITEM_SLOT_COUNT], dynamicValue);
        }
        return count;
    }

    /* stage 1: caller without the mocked permissions hits the denial branches */
    void RunUnmockedConfigChecks(const struct CertManagerConfig *config, const struct CmBlob *keysPtr)
    {
        (void)CmServiceSetCertManagerConfigCheck(config);
        (void)CmServiceGetCertManagerConfigCheck(keysPtr);
        (void)CmServiceGetCertManagerConfigCheckKeys(keysPtr);
    }

    /* stage 2: the full-permission system app walks the deep RDB paths,
     * including the non-system-app rejection of the get check */
    void RunMockedConfigChecks(const struct CertManagerConfig *config, const struct CmBlob *keysPtr,
        uint32_t nonSysSel)
    {
        CertmanagerTest::MockHapToken mockHap;
        (void)CmServiceSetCertManagerConfigCheck(config);
        (void)CmServiceGetCertManagerConfigCheck(keysPtr);
        (void)CmServiceGetCertManagerConfigCheckKeys(keysPtr);

        (void)CreateCertManagerConfigRdb();
        (void)CmServiceSetCertManagerConfig(config); /* InsertOrUpdateConfig deep path */

        struct CertManagerConfig outConfig = { 0, nullptr };
        (void)CmServiceGetCertManagerConfig(keysPtr, &outConfig); /* QueryAll/QuerySpecific deep path */
        CmFree(outConfig.configItems); /* the engine allocates the array with CmMalloc */

        /* non-system app with the common permission: the get check rejection */
        if (nonSysSel % NON_SYS_SELECTOR_MODULUS == NON_SYS_SELECTOR_HIT) {
            std::vector<std::string> perms = { "ohos.permission.ACCESS_CERT_MANAGER" };
            CertmanagerTest::MockHapToken nonSysMock(perms, false);
            (void)CmServiceGetCertManagerConfigCheck(keysPtr);
        }
    }

    /* keep the config table from growing across long fuzz runs */
    void CleanupConfigItems(const struct CmConfigItem *items, uint32_t count)
    {
        (void)CreateCertManagerConfigRdb();
        for (uint32_t i = 0; i < count && i < MAX_COUNT_CONFIG_ITEM; i++) {
            if (items[i].key[0] != '\0') {
                (void)DeleteConfigByKey(items[i].key);
            }
        }
    }
}

namespace OHOS {
    /* exercise the config check helpers (cert_manager_check.c) and the config
     * service entry points (cert_manager_service.c) with both an unmocked
     * caller (permission-denied branches) and the mocked system app (the deep
     * RDB paths), plus the non-system-app rejection of the get path */
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        uint32_t keySel[CONFIG_ITEM_SLOT_COUNT] = { 0, 0 };
        uint32_t valSel[CONFIG_ITEM_SLOT_COUNT] = { 0, 0 };
        uint32_t countSel = 0;
        uint32_t keysMode = 0;
        uint32_t nonSysSel = 0;
        char *dynamicValue = nullptr;
        char *dynamicKey = nullptr;
        if (!ParseConfigSelectors(myData, &remainSize, &offset, keySel, valSel, &countSel,
            &keysMode, &nonSysSel, &dynamicValue, &dynamicKey)) {
            CmFree(myData);
            return false;
        }

        struct CmConfigItem items[MAX_COUNT_CONFIG_ITEM + 1] = {};
        uint32_t count = BuildConfigItems(countSel, keySel, valSel, dynamicValue, items);
        struct CertManagerConfig config = { count, items };

        char keysBuf[MAX_LEN_CONFIG_KEY * KEYS_BUF_KEY_CAPACITY + KEYS_BUF_EXTRA_BYTES] = { 0 };
        struct CmBlob keysBlob = { 0, nullptr };
        struct CmBlob *keysPtr = nullptr;
        BuildKeysBlob(keysMode, dynamicKey, &keysPtr, &keysBlob, keysBuf, sizeof(keysBuf));

        RunUnmockedConfigChecks(&config, keysPtr);
        RunMockedConfigChecks(&config, keysPtr, nonSysSel);
        CleanupConfigItems(items, count);

        delete[] dynamicValue;
        delete[] dynamicKey;
        CmFree(myData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
