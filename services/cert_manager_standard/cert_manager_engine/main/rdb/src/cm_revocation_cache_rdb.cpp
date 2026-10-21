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

#include "cm_revocation_cache_rdb.h"

#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#include "securec.h"

#include "cm_config_rdb.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"

namespace OHOS {
namespace Security {
namespace CertManager {

static std::shared_ptr<CmRdbDataManager> revocationCacheRdbDataManager = nullptr;

} // namespace CertManager
} // namespace Security
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Security::CertManager;

static const char *REVOCATION_CACHE_SELECT_COLUMNS =
    "SELECT KEY, TYPE, EXPIRE_TIME_UTC, FILE_PATH, DATA_SIZE FROM ";

/* the cleanup meta row lives in cert_manager_config: the int64 timestamp is
 * stored as a decimal string; 32 bytes cover int64 (20 digits + sign + NUL) */
constexpr uint32_t REVOCATION_CACHE_META_VALUE_STR_LEN = 32;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateRevocationCacheRdb(void)
{
    CM_LOG_D("enter CreateRevocationCacheRdb");
    /* (KEY, TYPE) is the logical identity of one cached entry: a rewrite of the
     * same key and type replaces the whole row (ON_CONFLICT_REPLACE), so
     * FILE_PATH stays plain derived data instead of being the primary key */
    RdbConfig cacheConfig;
    cacheConfig.dbName = CERT_MANAGER_RDB_NAME;
    cacheConfig.tableName = REVOCATION_CACHE_TABLE_NAME;
    cacheConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + REVOCATION_CACHE_TABLE_NAME +
        "(KEY TEXT NOT NULL, TYPE TEXT NOT NULL, EXPIRE_TIME_UTC INTEGER NOT NULL, WRITE_TIME_UTC INTEGER NOT NULL, " +
        "FILE_PATH TEXT NOT NULL, DATA_SIZE INTEGER NOT NULL, PRIMARY KEY (KEY, TYPE))");
    revocationCacheRdbDataManager = std::make_shared<CmRdbDataManager>(cacheConfig);
    if (!revocationCacheRdbDataManager->CreateTable()) {
        CM_LOG_E("Failed to create revocation_cache table");
        revocationCacheRdbDataManager = nullptr;
        return CMR_ERROR_CREATE_RDB_TABLE_FAIL;
    }
    return CM_SUCCESS;
}

int32_t InsertRevocationCacheRecord(const struct RevocationCacheRecord *record)
{
    CM_LOG_D("enter InsertRevocationCacheRecord");
    if (record == nullptr) {
        CM_LOG_E("record is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (revocationCacheRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(COLUMN_KEY, std::string(record->key));
    valuesBucket.PutString(COLUMN_TYPE, std::string(record->type));
    valuesBucket.PutLong(COLUMN_EXPIRE_TIME_UTC, record->expireTimeUtc);
    valuesBucket.PutLong(COLUMN_WRITE_TIME_UTC, static_cast<int64_t>(std::time(nullptr)));
    valuesBucket.PutString(COLUMN_FILE_PATH, std::string(record->filePath));
    valuesBucket.PutLong(COLUMN_DATA_SIZE, static_cast<int64_t>(record->dataSize));
    if (!revocationCacheRdbDataManager->InsertData(valuesBucket)) {
        CM_LOG_E("Failed to insert revocation cache record:%s", record->filePath);
        return CMR_ERROR_INSERT_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

int32_t DeleteRevocationCacheRecord(const char *filePath)
{
    CM_LOG_D("enter DeleteRevocationCacheRecord");
    if (filePath == nullptr) {
        CM_LOG_E("filePath is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (revocationCacheRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    if (!revocationCacheRdbDataManager->DeleteData(std::string(filePath), COLUMN_FILE_PATH)) {
        CM_LOG_E("Failed to delete revocation cache record:%s", filePath);
        return CMR_ERROR_DELETE_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

int32_t QueryRevocationCacheSumSize(uint64_t *totalSize)
{
    CM_LOG_D("enter QueryRevocationCacheSumSize");
    if (totalSize == nullptr) {
        CM_LOG_E("totalSize is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (revocationCacheRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    *totalSize = 0;

    std::string sql = std::string("SELECT SUM(") + COLUMN_DATA_SIZE + ") AS total_size FROM " +
        REVOCATION_CACHE_TABLE_NAME;
    auto resultSet = revocationCacheRdbDataManager->QueryBySql(sql, std::vector<NativeRdb::ValueObject>());
    if (resultSet == nullptr) {
        CM_LOG_E("query sum size failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (rowCount <= 0 || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        resultSet->Close();
        return CM_SUCCESS;
    }

    bool isNull = false;
    int64_t sum = 0;
    if (resultSet->IsColumnNull(0, isNull) == NativeRdb::E_OK && !isNull) {
        if (resultSet->GetLong(0, sum) != NativeRdb::E_OK) {
            CM_LOG_E("GetLong for sum failed");
            resultSet->Close();
            return CMR_ERROR_QUERY_RDB_DATA_FAIL;
        }
    }
    resultSet->Close();
    *totalSize = sum < 0 ? 0 : static_cast<uint64_t>(sum);
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
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, struct RevocationCacheRecord *record)
{
    std::string key;
    if (ReadStringColumn(resultSet, COLUMN_KEY, key) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string type;
    if (ReadStringColumn(resultSet, COLUMN_TYPE, type) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t expire = 0;
    if (ReadLongColumn(resultSet, COLUMN_EXPIRE_TIME_UTC, expire) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string path;
    if (ReadStringColumn(resultSet, COLUMN_FILE_PATH, path) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t size = 0;
    if (ReadLongColumn(resultSet, COLUMN_DATA_SIZE, size) != CM_SUCCESS) {
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    record->expireTimeUtc = expire;
    record->dataSize = size < 0 ? 0 : static_cast<uint64_t>(size);
    if (memcpy_s(record->key, sizeof(record->key), key.c_str(), key.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s key failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(record->type, sizeof(record->type), type.c_str(), type.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s type failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(record->filePath, sizeof(record->filePath), path.c_str(), path.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s filePath failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

static int32_t QuerySingleRecord(const std::string &sql, const std::vector<NativeRdb::ValueObject> &args,
    struct RevocationCacheRecord *record)
{
    if (record == nullptr) {
        CM_LOG_E("record is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (revocationCacheRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    auto resultSet = revocationCacheRdbDataManager->QueryBySql(sql, args);
    if (resultSet == nullptr) {
        CM_LOG_E("query revocation cache record failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (rowCount <= 0) {
        CM_LOG_D("revocation cache record not found");
        resultSet->Close();
        return CMR_ERROR_NOT_FOUND;
    }
    if (resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        CM_LOG_E("GoToFirstRow failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t ret = ReadRecordFromResultSet(resultSet, record);
    resultSet->Close();
    return ret;
}

int32_t QueryRevocationCacheRecordByExpireAsc(struct RevocationCacheRecord *record)
{
    CM_LOG_D("enter QueryRevocationCacheRecordByExpireAsc");
    std::string sql = std::string(REVOCATION_CACHE_SELECT_COLUMNS) + REVOCATION_CACHE_TABLE_NAME +
        " ORDER BY " + COLUMN_EXPIRE_TIME_UTC + " ASC, " + COLUMN_WRITE_TIME_UTC + " ASC LIMIT 1";
    return QuerySingleRecord(sql, std::vector<NativeRdb::ValueObject>(), record);
}

int32_t QueryExpiredRevocationCacheRecord(int64_t nowUtc, struct RevocationCacheRecord *record)
{
    CM_LOG_D("enter QueryExpiredRevocationCacheRecord");
    std::string sql = std::string(REVOCATION_CACHE_SELECT_COLUMNS) + REVOCATION_CACHE_TABLE_NAME +
        " WHERE " + COLUMN_EXPIRE_TIME_UTC + " < ? ORDER BY " + COLUMN_EXPIRE_TIME_UTC + " ASC LIMIT 1";
    std::vector<NativeRdb::ValueObject> args;
    args.emplace_back(nowUtc);
    return QuerySingleRecord(sql, args, record);
}

static int32_t AppendCurrentRowPath(NativeRdb::AbsSharedResultSet *resultSet, char **pathArray, uint32_t *validCount)
{
    int pathIndex = 0;
    if (resultSet->GetColumnIndex(COLUMN_FILE_PATH, pathIndex) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for path failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string path;
    if (resultSet->GetString(pathIndex, path) != NativeRdb::E_OK) {
        CM_LOG_E("GetString for path failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    char *pathStr = static_cast<char *>(CmMalloc(path.size() + 1));
    if (pathStr == nullptr) {
        CM_LOG_E("malloc path string failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(pathStr, path.size() + 1, path.c_str(), path.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s path failed");
        CmFree(pathStr);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    pathArray[*validCount] = pathStr;
    (*validCount)++;
    return CM_SUCCESS;
}

static int32_t CollectFilePaths(NativeRdb::AbsSharedResultSet *resultSet, uint32_t capacity,
    char ***paths, uint32_t *count)
{
    char **pathArray = static_cast<char **>(CmMalloc(sizeof(char *) * capacity));
    if (pathArray == nullptr) {
        CM_LOG_E("malloc path array failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(pathArray, sizeof(char *) * capacity, 0, sizeof(char *) * capacity);

    uint32_t validCount = 0;
    int32_t ret = resultSet->GoToFirstRow();
    while (ret == NativeRdb::E_OK && validCount < capacity) {
        int32_t appendRet = AppendCurrentRowPath(resultSet, pathArray, &validCount);
        if (appendRet != CM_SUCCESS) {
            FreeRevocationCacheFilePaths(pathArray, validCount);
            return appendRet;
        }
        ret = resultSet->GoToNextRow();
    }
    *paths = pathArray;
    *count = validCount;
    return CM_SUCCESS;
}

int32_t QueryAllRevocationCacheFilePaths(char ***paths, uint32_t *count)
{
    CM_LOG_D("enter QueryAllRevocationCacheFilePaths");
    if (paths == nullptr || count == nullptr) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    *paths = nullptr;
    *count = 0;
    if (revocationCacheRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    std::string sql = std::string("SELECT ") + COLUMN_FILE_PATH + " FROM " + REVOCATION_CACHE_TABLE_NAME;
    auto resultSet = revocationCacheRdbDataManager->QueryBySql(sql, std::vector<NativeRdb::ValueObject>());
    if (resultSet == nullptr) {
        CM_LOG_E("query all file paths failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t ret = CM_SUCCESS;
    int32_t rowCount = 0;
    if (resultSet->GetRowCount(rowCount) != NativeRdb::E_OK) {
        CM_LOG_E("GetRowCount failed");
        ret = CMR_ERROR_QUERY_RDB_DATA_FAIL;
    } else if (rowCount > 0) {
        ret = CollectFilePaths(resultSet.get(), static_cast<uint32_t>(rowCount), paths, count);
    }
    resultSet->Close();
    return ret;
}

void FreeRevocationCacheFilePaths(char **paths, uint32_t count)
{
    if (paths == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        CmFree(paths[i]);
        paths[i] = nullptr;
    }
    CmFree(paths);
}

int32_t GetRevocationCacheMeta(int64_t *value)
{
    CM_LOG_D("enter GetRevocationCacheMeta");
    if (value == nullptr) {
        CM_LOG_E("value is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char valueStr[REVOCATION_CACHE_META_VALUE_STR_LEN] = { 0 };
    int32_t ret = QueryConfigByKey(REVOCATION_CACHE_LAST_CLEANUP_KEY.c_str(), valueStr, sizeof(valueStr));
    if (ret != CM_SUCCESS) {
        return ret; /* CMR_ERROR_NOT_FOUND propagates to the caller */
    }

    constexpr int decimalBase = 10;
    *value = std::strtoll(valueStr, nullptr, decimalBase);
    return CM_SUCCESS;
}

int32_t SetRevocationCacheMeta(int64_t value)
{
    CM_LOG_D("enter SetRevocationCacheMeta");
    std::string valueStr = std::to_string(value);
    return InsertOrUpdateConfig(REVOCATION_CACHE_LAST_CLEANUP_KEY.c_str(), valueStr.c_str());
}

int32_t DeleteRevocationCacheMeta(void)
{
    CM_LOG_D("enter DeleteRevocationCacheMeta");
    return DeleteConfigByKey(REVOCATION_CACHE_LAST_CLEANUP_KEY.c_str());
}

#ifdef __cplusplus
}
#endif
