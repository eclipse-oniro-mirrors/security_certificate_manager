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

#include "cmrdbopencallback_fuzzer.h"

#include <memory>

#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "cm_rdb_open_callback.h"
#include "securec.h"

using namespace CmFuzzTest;
using namespace OHOS::Security::CertManager;
namespace {
    const uint32_t UINT32_COUNT = 4;
    const uint32_t MAX_VERSION_SEL = 4; /* {0,1,2,3}: (1,2) hits the ALTER TABLE upgrade branch */
    const char *FUZZ_DB_NAME = "/cert_manager_fuzz_cb.db"; /* isolated from the formal tables */

    RdbConfig BuildCallbackRdbConfig(void)
    {
        RdbConfig rdbConfig;
        rdbConfig.dbName = FUZZ_DB_NAME;
        rdbConfig.tableName = "fuzz_callback_tab";
        rdbConfig.createTableSql = "CREATE TABLE IF NOT EXISTS fuzz_callback_tab(ID INTEGER PRIMARY KEY)";
        return rdbConfig;
    }
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        /* layout: [currentVersion byte][targetVersion byte] (uint8 keeps the
         * version space small so mutation reaches the (1,2) upgrade pair) */
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        RdbConfig rdbConfig = BuildCallbackRdbConfig();
        CmRdbOpenCallback openCallback(rdbConfig);

        /* open a real store first: OnCreate/OnOpen also fire through the
         * RdbHelper path, and the store reference feeds the direct calls */
        int32_t errCode = OHOS::NativeRdb::E_OK;
        OHOS::NativeRdb::RdbStoreConfig storeConfig(rdbConfig.dbPath + rdbConfig.dbName);
        storeConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel::S1);
        std::shared_ptr<OHOS::NativeRdb::RdbStore> store =
            OHOS::NativeRdb::RdbHelper::GetRdbStore(storeConfig, rdbConfig.version, openCallback, errCode);
        if (store == nullptr) {
            /* no writable rdb directory in this environment: only the direct
             * calls below would be reachable, skip safely */
            CmFree(myData);
            return false;
        }

        int32_t currentVersion = static_cast<int32_t>(myData[0] % MAX_VERSION_SEL);
        int32_t targetVersion = static_cast<int32_t>(myData[1] % MAX_VERSION_SEL);

        (void)openCallback.OnCreate(*store);
        (void)openCallback.OnUpgrade(*store, currentVersion, targetVersion);
        (void)openCallback.OnDowngrade(*store, currentVersion, targetVersion);
        (void)openCallback.OnOpen(*store);

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
