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

#include "cmrdbdatamanager_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "securec.h"

using namespace CmFuzzTest;
using namespace OHOS::Security::CertManager;
namespace NativeRdb = OHOS::NativeRdb;
namespace {
    const uint32_t UINT32_COUNT = 4;
    const uint32_t MAX_TABLE_SUFFIX_LEN = 16;
    const char *FUZZ_DB_NAME = "/cert_manager_fuzz_dm.db"; /* isolated from the formal tables */
    const char *FUZZ_TABLE_PREFIX = "fuzz_tab_";

    /* keep only [A-Za-z0-9_]: the table name is concatenated into SQL
     * statements (ExecuteSql / QueryBySql), so no other character may pass */
    std::string SanitizeTableSuffix(const char *suffix)
    {
        std::string out;
        for (size_t i = 0; suffix[i] != '\0' && out.size() < MAX_TABLE_SUFFIX_LEN; i++) {
            char c = suffix[i];
            bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_';
            out.push_back(alnum ? c : '_');
        }
        return out;
    }

    /* parsed fuzz input; owned pointers are freed by FreeRdbDataManagerInput */
    struct RdbDataManagerInput {
        char *tableSuffix = nullptr;
        char *nameValue = nullptr;
        uint32_t primKey = 0;
        bool malformedDdl = false;
    };

    void FreeRdbDataManagerInput(struct RdbDataManagerInput *in)
    {
        delete[] in->tableSuffix;
        delete[] in->nameValue;
        in->tableSuffix = nullptr;
        in->nameValue = nullptr;
    }

    /* layout: [tableSuffix string][nameValue string][primKey uint32]
     * [invalid-ddl selector uint32] */
    bool ParseRdbDataManagerInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct RdbDataManagerInput *in)
    {
        if (!GetDynamicStringFromBuffer(myData, remainSize, offset, &in->tableSuffix) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->nameValue)) {
            return false;
        }
        if (!GetUintFromBuffer(myData, remainSize, offset, &in->primKey)) {
            return false;
        }
        in->malformedDdl = TenPercentChanceOfBeingTrue(myData, remainSize, offset);
        return true;
    }

    RdbConfig BuildRdbConfig(const struct RdbDataManagerInput &in)
    {
        RdbConfig rdbConfig;
        rdbConfig.dbName = FUZZ_DB_NAME;
        rdbConfig.tableName = std::string(FUZZ_TABLE_PREFIX) + SanitizeTableSuffix(in.tableSuffix);
        if (in.malformedDdl) {
            /* malformed DDL: CreateTable/ExecuteSql failure branches */
            rdbConfig.createTableSql = std::string(in.tableSuffix);
        } else {
            rdbConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " + rdbConfig.tableName +
                "(ID INTEGER PRIMARY KEY, NAME TEXT)";
        }
        return rdbConfig;
    }

    void CloseResultSet(std::shared_ptr<NativeRdb::AbsSharedResultSet> resultSet)
    {
        if (resultSet != nullptr) {
            resultSet->Close();
        }
    }

    /* full CRUD sequence against the isolated fuzz database */
    void RunRdbDataManagerFlow(const RdbConfig &rdbConfig, const struct RdbDataManagerInput &in)
    {
        std::shared_ptr<CmRdbDataManager> manager = std::make_shared<CmRdbDataManager>(rdbConfig);

        bool tableReady = manager->CreateTable();

        NativeRdb::ValuesBucket bucket;
        bucket.PutInt("ID", static_cast<int32_t>(in.primKey));
        bucket.PutString("NAME", std::string(in.nameValue));
        (void)manager->InsertData(bucket);

        std::string primKeyStr = std::to_string(in.primKey);
        (void)manager->UpdateData(primKeyStr, "ID", bucket);

        CloseResultSet(manager->QueryData(primKeyStr, "ID"));
        CloseResultSet(manager->QueryAllData());
        CloseResultSet(manager->QueryDataWithPredicates(
            NativeRdb::AbsRdbPredicates(rdbConfig.tableName)));

        if (tableReady) {
            std::vector<NativeRdb::ValueObject> deleteArgs;
            deleteArgs.emplace_back(std::string(primKeyStr));
            (void)manager->ExecuteSql("DELETE FROM " + rdbConfig.tableName + " WHERE ID = ?",
                deleteArgs);
            CloseResultSet(manager->QueryBySql("SELECT COUNT(*) FROM " + rdbConfig.tableName,
                std::vector<NativeRdb::ValueObject>()));
        }

        (void)manager->DeleteData(primKeyStr, "ID");
    }
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct RdbDataManagerInput in = {};

        bool parsed = ParseRdbDataManagerInput(myData, &remainSize, &offset, &in);
        if (parsed) {
            RunRdbDataManagerFlow(BuildRdbConfig(in), in);
        }

        FreeRdbDataManagerInput(&in);
        CmFree(myData);
        return parsed;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
