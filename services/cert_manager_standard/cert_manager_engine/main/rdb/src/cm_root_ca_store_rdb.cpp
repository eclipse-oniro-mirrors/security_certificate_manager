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

#include "cm_root_ca_store_rdb.h"

#include <cstdint>
#include <string>
#include <vector>

#include "securec.h"

#include "cm_log.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"

namespace OHOS {
namespace Security {
namespace CertManager {

static std::shared_ptr<CmRdbDataManager> rootCaStoreRdbDataManager = nullptr;

} // namespace CertManager
} // namespace Security
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Security::CertManager;

#ifdef __cplusplus
extern "C" {
#endif

/* engine uri blobs are sized strlen + 1 (see CreateCertFileList in
 * cert_manager_query.c): the row key must not inherit the trailing NUL,
 * or a lookup with the NUL-less spelling would never match the row */
static std::string UriToKey(const char *uri, uint32_t uriLen)
{
    std::string key(uri, uriLen);
    if (!key.empty() && key.back() == '\0') {
        key.pop_back();
    }
    return key;
}

int32_t CreateRootCaStoreRdb(void)
{
    CM_LOG_D("enter CreateRootCaStoreRdb");
    /* the table shares cert_manager.db with cert_property and revocation_cache:
     * URI alone is the primary key (file names are unique across the two
     * system certificate directories) */
    RdbConfig storeConfig;
    storeConfig.dbName = CERT_MANAGER_RDB_NAME;
    storeConfig.tableName = ROOT_CA_STORE_TABLE_NAME;
    storeConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + ROOT_CA_STORE_TABLE_NAME +
        "(URI TEXT NOT NULL, ALG_TYPE INTEGER NOT NULL, ENABLE INTEGER NOT NULL, " +
        "CERT_PK_HASH TEXT NOT NULL, PRIMARY KEY(URI))");
    rootCaStoreRdbDataManager = std::make_shared<CmRdbDataManager>(storeConfig);
    if (!rootCaStoreRdbDataManager->CreateTable()) {
        CM_LOG_E("Failed to create root_ca_cert_store table");
        rootCaStoreRdbDataManager = nullptr;
        return CMR_ERROR_CREATE_RDB_TABLE_FAIL;
    }
    return CM_SUCCESS;
}

int32_t UpsertRootCaStore(const char *uri, uint32_t uriLen, uint32_t algType,
    uint32_t enable, const char *certPkHash)
{
    CM_LOG_D("enter UpsertRootCaStore");
    if (uri == nullptr || certPkHash == nullptr || uriLen == 0) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (rootCaStoreRdbDataManager == nullptr) {
        CM_LOG_E("rootCaStoreRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    /* one uri is one row: a re-enable (or re-disable) rewrites the whole row */
    std::string sql = std::string("INSERT INTO ") + ROOT_CA_STORE_TABLE_NAME + "(" + COLUMN_URI + ", " +
        COLUMN_ALG_TYPE + ", " + COLUMN_ENABLE + ", " + COLUMN_CERT_PK_HASH + ") VALUES(?, ?, ?, ?) " +
        "ON CONFLICT(" + COLUMN_URI + ") DO UPDATE SET " + COLUMN_ALG_TYPE + " = excluded." + COLUMN_ALG_TYPE +
        ", " + COLUMN_ENABLE + " = excluded." + COLUMN_ENABLE + ", " + COLUMN_CERT_PK_HASH + " = excluded." +
        COLUMN_CERT_PK_HASH;
    std::vector<NativeRdb::ValueObject> args;
    args.emplace_back(UriToKey(uri, uriLen));
    args.emplace_back(static_cast<int64_t>(algType));
    args.emplace_back(static_cast<int64_t>(enable));
    args.emplace_back(std::string(certPkHash));
    if (!rootCaStoreRdbDataManager->ExecuteSql(sql, args)) {
        CM_LOG_E("Failed to upsert root ca store record");
        return CMR_ERROR_INSERT_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

/* fetch one TEXT column into value; logs the column name on failure */
static int32_t ReadStringColumn(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    const std::string &column, std::string &value)
{
    int index = 0;
    if (resultSet->GetColumnIndex(column, index) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for %s failed", column.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (resultSet->GetString(index, value) != NativeRdb::E_OK) {
        CM_LOG_E("GetString for %s failed", column.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

/* fetch one INTEGER column into value; logs the column name on failure */
static int32_t ReadLongColumn(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    const std::string &column, int64_t &value)
{
    int index = 0;
    if (resultSet->GetColumnIndex(column, index) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for %s failed", column.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (resultSet->GetLong(index, value) != NativeRdb::E_OK) {
        CM_LOG_E("GetLong for %s failed", column.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

static int32_t ReadRecordFromResultSet(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, struct RootCaStoreRecord *record)
{
    std::string uri;
    if (ReadStringColumn(resultSet, COLUMN_URI, uri) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t algType = 0;
    if (ReadLongColumn(resultSet, COLUMN_ALG_TYPE, algType) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t enable = 0;
    if (ReadLongColumn(resultSet, COLUMN_ENABLE, enable) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string certPkHash;
    if (ReadStringColumn(resultSet, COLUMN_CERT_PK_HASH, certPkHash) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    record->algType = algType < 0 ? CM_ROOT_CA_ALG_TYPE_INTERNATIONAL : static_cast<uint32_t>(algType);
    record->enable = enable > 0 ? 1 : 0;
    if (memcpy_s(record->uri, sizeof(record->uri), uri.c_str(), uri.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s uri failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(record->certPkHash, sizeof(record->certPkHash), certPkHash.c_str(), certPkHash.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s certPkHash failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

int32_t QueryDisabledRootCa(struct RootCaStoreRecord *records, uint32_t maxCount, uint32_t *count)
{
    CM_LOG_D("enter QueryDisabledRootCa");
    if (records == nullptr || count == nullptr) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (rootCaStoreRdbDataManager == nullptr) {
        CM_LOG_E("rootCaStoreRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    *count = 0;

    /* disabled rows only, ordered by uri: the caller regenerates the whole
     * policy file from this list and the order keeps its content stable */
    std::string sql = std::string("SELECT ") + COLUMN_URI + ", " + COLUMN_ALG_TYPE + ", " + COLUMN_ENABLE + ", " +
        COLUMN_CERT_PK_HASH + " FROM " + ROOT_CA_STORE_TABLE_NAME + " WHERE " + COLUMN_ENABLE + " = 0 ORDER BY " +
        COLUMN_URI;
    auto resultSet = rootCaStoreRdbDataManager->QueryBySql(sql, std::vector<NativeRdb::ValueObject>());
    if (resultSet == nullptr) {
        CM_LOG_E("query disabled root ca failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (rowCount < 0 || static_cast<uint32_t>(rowCount) > maxCount) {
        CM_LOG_E("disabled root ca count %d exceeds capacity %u", rowCount, maxCount);
        resultSet->Close();
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    int32_t ret = CM_SUCCESS;
    int32_t goRow = resultSet->GoToFirstRow();
    while (goRow == NativeRdb::E_OK && *count < static_cast<uint32_t>(rowCount)) {
        ret = ReadRecordFromResultSet(resultSet, &records[*count]);
        if (ret != CM_SUCCESS) {
            break;
        }
        (*count)++;
        goRow = resultSet->GoToNextRow();
    }
    resultSet->Close();
    if (ret != CM_SUCCESS) {
        *count = 0;
        return ret;
    }
    return CM_SUCCESS;
}

int32_t QueryRootCaEnable(const char *uri, uint32_t uriLen, uint32_t *enable)
{
    CM_LOG_D("enter QueryRootCaEnable");
    if (uri == nullptr || enable == nullptr || uriLen == 0) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (rootCaStoreRdbDataManager == nullptr) {
        CM_LOG_E("rootCaStoreRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    /* no row counts as enabled: only explicitly disabled certificates deviate */
    *enable = 1;

    std::string sql = std::string("SELECT ") + COLUMN_ENABLE + " FROM " + ROOT_CA_STORE_TABLE_NAME + " WHERE " +
        COLUMN_URI + " = ?";
    std::vector<NativeRdb::ValueObject> args;
    args.emplace_back(UriToKey(uri, uriLen));
    auto resultSet = rootCaStoreRdbDataManager->QueryBySql(sql, args);
    if (resultSet == nullptr) {
        CM_LOG_E("query root ca enable failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (rowCount <= 0) {
        resultSet->Close();
        return CM_SUCCESS;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        CM_LOG_E("GoToFirstRow failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int64_t value = 0;
    int32_t ret = ReadLongColumn(resultSet, COLUMN_ENABLE, value);
    resultSet->Close();
    if (ret != CM_SUCCESS) {
        return ret;
    }
    *enable = value > 0 ? 1 : 0;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
