/**
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

#include "cmconfigrdb_fuzzer.h"

#include "cm_config_rdb.h"
#include "cm_config_type.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"

using namespace CmFuzzTest;
namespace {
    const uint32_t UINT32_COUNT = 4;
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        /* layout: [key string][value string][valueLen selector uint32][null-branch selector uint32] */
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        char *key = nullptr;
        char *value = nullptr;
        if (!GetDynamicStringFromBuffer(myData, &remainSize, &offset, &key) ||
            !GetDynamicStringFromBuffer(myData, &remainSize, &offset, &value)) {
            delete[] key;
            delete[] value;
            CmFree(myData);
            return false;
        }

        uint32_t valueLenSel = 0;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &valueLenSel)) {
            delete[] key;
            delete[] value;
            CmFree(myData);
            return false;
        }

        (void)CreateCertManagerConfigRdb();

        if (TenPercentChanceOfBeingTrue(myData, &remainSize, &offset)) {
            /* invalid-argument branches of every entry point */
            (void)InsertOrUpdateConfig(nullptr, nullptr);
            (void)QueryConfigByKey(nullptr, nullptr, 0);
            (void)QueryAllConfig(nullptr);
            (void)DeleteConfigByKey(nullptr);
        } else {
            (void)InsertOrUpdateConfig(key, value);

            /* valueLen folds to 0 (invalid) / short (memcpy_s guard) / enough (success) */
            char outBuf[MAX_LEN_CONFIG_VALUE + 1] = { 0 };
            uint32_t queryLen = valueLenSel % (MAX_LEN_CONFIG_VALUE + 2);
            (void)QueryConfigByKey(key, outBuf, queryLen);

            struct CertManagerConfig config = { 0, nullptr };
            if (QueryAllConfig(&config) == CM_SUCCESS && config.configItems != nullptr) {
                CmFree(config.configItems); /* engine allocates the array with CmMalloc */
            }

            /* delete the row again so long fuzz runs do not grow the table */
            (void)DeleteConfigByKey(key);
        }

        delete[] key;
        delete[] value;
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
