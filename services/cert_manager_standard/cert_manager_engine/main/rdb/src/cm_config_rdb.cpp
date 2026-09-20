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

#include "cm_config_rdb.h"

#include <string>
#include <vector>

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "cm_rdb_open_callback.h"
#include "cm_scope_guard.h"

#include "securec.h"

namespace OHOS {
namespace Security {
namespace CertManager {

static std::shared_ptr<CmRdbDataManager> cmConfigRdbDataManager = nullptr;

} // namespace CertManager
} // namespace Security
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Security::CertManager;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateCertManagerConfigRdb(void)
{
    CM_LOG_D("enter CreateCertManagerConfigRdb");
    RdbConfig rdbConfig;
    rdbConfig.dbName = CERT_MANAGER_RDB_NAME;
    rdbConfig.tableName = CERT_MANAGER_CONFIG_TABLE_NAME;
    rdbConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + CERT_MANAGER_CONFIG_TABLE_NAME +
        "(CONFIG_KEY TEXT PRIMARY KEY, CONFIG_VALUE TEXT NOT NULL)");
    cmConfigRdbDataManager = std::make_shared<CmRdbDataManager>(rdbConfig);
    bool ret = cmConfigRdbDataManager->CreateTable();
    if (!ret) {
        CM_LOG_E("Failed to create cert_manager_config table");
        cmConfigRdbDataManager = nullptr;
        return CMR_ERROR_CREATE_RDB_TABLE_FAIL;
    }
    return CM_SUCCESS;
}

int32_t InsertOrUpdateConfig(const char *key, const char *value)
{
    CM_LOG_D("enter InsertOrUpdateConfig");
    if (key == nullptr || value == nullptr) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmConfigRdbDataManager == nullptr) {
        CM_LOG_E("cmConfigRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(COLUMN_CONFIG_KEY, std::string(key));
    valuesBucket.PutString(COLUMN_CONFIG_VALUE, std::string(value));
    bool ret = cmConfigRdbDataManager->InsertData(valuesBucket);
    if (!ret) {
        CM_LOG_E("Failed to insert/update config:%s", key);
        return CMR_ERROR_INSERT_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

static int32_t ReadConfigValueFromResultSet(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    char *value, uint32_t valueLen)
{
    int32_t ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("GoToFirstRow failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int columnIndex = 0;
    ret = resultSet->GetColumnIndex(COLUMN_CONFIG_VALUE, columnIndex);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    std::string strValue;
    ret = resultSet->GetString(columnIndex, strValue);
    resultSet->Close();
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("GetString failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    if (memcpy_s(value, valueLen, strValue.c_str(), strValue.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s fail");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

int32_t QueryConfigByKey(const char *key, char *value, uint32_t valueLen)
{
    CM_LOG_D("enter QueryConfigByKey");
    if (key == nullptr || value == nullptr || valueLen == 0) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmConfigRdbDataManager == nullptr) {
        CM_LOG_E("cmConfigRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    auto absSharedResultSet = cmConfigRdbDataManager->QueryData(std::string(key), COLUMN_CONFIG_KEY);
    if (absSharedResultSet == nullptr) {
        CM_LOG_E("query config:%s failed", key);
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (!absSharedResultSet->HasBlock()) {
        CM_LOG_D("config:%s not found", key);
        absSharedResultSet->Close();
        return CMR_ERROR_NOT_FOUND;
    }

    int32_t rowCount = 0;
    auto ret = absSharedResultSet->GetRowCount(rowCount);
    if (ret != NativeRdb::E_OK || rowCount == 0) {
        CM_LOG_D("config:%s not found, rowCount:%d", key, rowCount);
        absSharedResultSet->Close();
        return CMR_ERROR_NOT_FOUND;
    }

    return ReadConfigValueFromResultSet(absSharedResultSet, value, valueLen);
}

static int32_t ReadConfigRow(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    struct CmConfigItem *item)
{
    int keyIndex = 0;
    auto keyRet = resultSet->GetColumnIndex(COLUMN_CONFIG_KEY, keyIndex);
    if (keyRet != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for key failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string keyStr;
    keyRet = resultSet->GetString(keyIndex, keyStr);
    if (keyRet != NativeRdb::E_OK) {
        CM_LOG_E("GetString for key failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int valueIndex = 0;
    auto valueRet = resultSet->GetColumnIndex(COLUMN_CONFIG_VALUE, valueIndex);
    if (valueRet != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for value failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string valueStr;
    valueRet = resultSet->GetString(valueIndex, valueStr);
    if (valueRet != NativeRdb::E_OK) {
        CM_LOG_E("GetString for value failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    if (memcpy_s(item->key, MAX_LEN_CONFIG_KEY, keyStr.c_str(), keyStr.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s key failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(item->value, MAX_LEN_CONFIG_VALUE, valueStr.c_str(), valueStr.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s value failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

static int32_t ReadAllConfigRows(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, uint32_t itemCount,
    struct CmConfigItem **items, uint32_t *validCount)
{
    uint32_t allocSize = sizeof(struct CmConfigItem) * itemCount;
    struct CmConfigItem *itemArr = static_cast<struct CmConfigItem *>(CmMalloc(allocSize));
    if (itemArr == nullptr) {
        CM_LOG_E("malloc failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(itemArr, allocSize, 0, allocSize);

    uint32_t count = 0;
    int32_t ret = resultSet->GoToFirstRow();
    while (ret == NativeRdb::E_OK) {
        int32_t readRet = ReadConfigRow(resultSet, &itemArr[count]);
        if (readRet != CM_SUCCESS) {
            break;
        }
        count++;
        ret = resultSet->GoToNextRow();
    }

    if (count == 0 && itemCount > 0) {
        CM_FREE_PTR(itemArr);
    }
    *items = itemArr;
    *validCount = count;
    return CM_SUCCESS;
}

int32_t QueryAllConfig(struct CertManagerConfig *config)
{
    CM_LOG_D("enter QueryAllConfig");
    if (config == nullptr) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmConfigRdbDataManager == nullptr) {
        CM_LOG_E("cmConfigRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    auto absSharedResultSet = cmConfigRdbDataManager->QueryAllData();
    if (absSharedResultSet == nullptr) {
        CM_LOG_E("query all config failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t rowCount = 0;
    auto ret = absSharedResultSet->GetRowCount(rowCount);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        absSharedResultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    if (rowCount <= 0) {
        config->count = 0;
        config->configItems = nullptr;
        absSharedResultSet->Close();
        return CM_SUCCESS;
    }

    if (static_cast<uint32_t>(rowCount) > MAX_COUNT_CONFIG_ITEM) {
        CM_LOG_E("config item count %d exceeds max %u", rowCount, MAX_COUNT_CONFIG_ITEM);
        absSharedResultSet->Close();
        return CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t itemCount = static_cast<uint32_t>(rowCount);
    uint32_t validCount = 0;
    struct CmConfigItem *items = nullptr;
    int32_t readRet = ReadAllConfigRows(absSharedResultSet, itemCount, &items, &validCount);
    absSharedResultSet->Close();
    if (readRet != CM_SUCCESS) {
        return readRet;
    }
    config->count = validCount;
    config->configItems = items;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
