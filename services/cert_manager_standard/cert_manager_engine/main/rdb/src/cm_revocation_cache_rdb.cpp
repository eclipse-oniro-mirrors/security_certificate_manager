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

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"

namespace OHOS {
namespace Security {
namespace CertManager {

static std::shared_ptr<CmRdbDataManager> revocationCacheRdbDataManager = nullptr;
static std::shared_ptr<CmRdbDataManager> revocationCacheMetaRdbDataManager = nullptr;

} // namespace CertManager
} // namespace Security
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Security::CertManager;

static const char *REVOCATION_CACHE_SELECT_COLUMNS =
    "SELECT EXPIRE_TIME_UTC, FILE_PATH, DATA_SIZE FROM ";

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateRevocationCacheRdb(void)
{
    CM_LOG_D("enter CreateRevocationCacheRdb");
    RdbConfig cacheConfig;
    cacheConfig.dbName = CERT_MANAGER_RDB_NAME;
    cacheConfig.tableName = REVOCATION_CACHE_TABLE_NAME;
    cacheConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + REVOCATION_CACHE_TABLE_NAME +
        "(KEY_HASH TEXT NOT NULL, TYPE TEXT NOT NULL, EXPIRE_TIME_UTC INTEGER NOT NULL, " +
        "WRITE_TIME_UTC INTEGER NOT NULL, FILE_PATH TEXT PRIMARY KEY, DATA_SIZE INTEGER NOT NULL)");
    revocationCacheRdbDataManager = std::make_shared<CmRdbDataManager>(cacheConfig);
    if (!revocationCacheRdbDataManager->CreateTable()) {
        CM_LOG_E("Failed to create revocation_cache table");
        revocationCacheRdbDataManager = nullptr;
        return CMR_ERROR_CREATE_RDB_TABLE_FAIL;
    }

    RdbConfig metaConfig;
    metaConfig.dbName = CERT_MANAGER_RDB_NAME;
    metaConfig.tableName = REVOCATION_CACHE_META_TABLE_NAME;
    metaConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + REVOCATION_CACHE_META_TABLE_NAME +
        "(CONFIG_KEY TEXT PRIMARY KEY, CONFIG_VALUE TEXT NOT NULL)");
    revocationCacheMetaRdbDataManager = std::make_shared<CmRdbDataManager>(metaConfig);
    if (!revocationCacheMetaRdbDataManager->CreateTable()) {
        CM_LOG_E("Failed to create revocation_cache_meta table");
        revocationCacheMetaRdbDataManager = nullptr;
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
    valuesBucket.PutString(COLUMN_KEY_HASH, std::string(""));
    valuesBucket.PutString(COLUMN_REVOCATION_TYPE, std::string(""));
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

static int32_t ReadRecordFromResultSet(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, struct RevocationCacheRecord *record)
{
    int expireIndex = 0;
    if (resultSet->GetColumnIndex(COLUMN_EXPIRE_TIME_UTC, expireIndex) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for expire failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t expire = 0;
    if (resultSet->GetLong(expireIndex, expire) != NativeRdb::E_OK) {
        CM_LOG_E("GetLong for expire failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

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

    int sizeIndex = 0;
    if (resultSet->GetColumnIndex(COLUMN_DATA_SIZE, sizeIndex) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for size failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    int64_t size = 0;
    if (resultSet->GetLong(sizeIndex, size) != NativeRdb::E_OK) {
        CM_LOG_E("GetLong for size failed");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    record->expireTimeUtc = expire;
    record->dataSize = size < 0 ? 0 : static_cast<uint64_t>(size);
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

int32_t QueryOldestRevocationCacheRecord(struct RevocationCacheRecord *record)
{
    CM_LOG_D("enter QueryOldestRevocationCacheRecord");
    std::string sql = std::string(REVOCATION_CACHE_SELECT_COLUMNS) + REVOCATION_CACHE_TABLE_NAME +
        " ORDER BY " + COLUMN_WRITE_TIME_UTC + " ASC, " + COLUMN_FILE_PATH + " ASC LIMIT 1";
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

    uint32_t capacity = static_cast<uint32_t>(rowCount);
    char **pathArray = static_cast<char **>(CmMalloc(sizeof(char *) * capacity));
    if (pathArray == nullptr) {
        CM_LOG_E("malloc path array failed");
        resultSet->Close();
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(pathArray, sizeof(char *) * capacity, 0, sizeof(char *) * capacity);

    uint32_t validCount = 0;
    int32_t ret = resultSet->GoToFirstRow();
    while (ret == NativeRdb::E_OK && validCount < capacity) {
        int pathIndex = 0;
        if (resultSet->GetColumnIndex(COLUMN_FILE_PATH, pathIndex) != NativeRdb::E_OK) {
            CM_LOG_E("GetColumnIndex for path failed");
            FreeRevocationCacheFilePaths(pathArray, validCount);
            resultSet->Close();
            return CMR_ERROR_QUERY_RDB_DATA_FAIL;
        }
        std::string path;
        if (resultSet->GetString(pathIndex, path) != NativeRdb::E_OK) {
            CM_LOG_E("GetString for path failed");
            FreeRevocationCacheFilePaths(pathArray, validCount);
            resultSet->Close();
            return CMR_ERROR_QUERY_RDB_DATA_FAIL;
        }
        char *pathStr = static_cast<char *>(CmMalloc(path.size() + 1));
        if (pathStr == nullptr) {
            CM_LOG_E("malloc path string failed");
            FreeRevocationCacheFilePaths(pathArray, validCount);
            resultSet->Close();
            return CMR_ERROR_MALLOC_FAIL;
        }
        if (memcpy_s(pathStr, path.size() + 1, path.c_str(), path.size() + 1) != EOK) {
            CM_LOG_E("memcpy_s path failed");
            CmFree(pathStr);
            FreeRevocationCacheFilePaths(pathArray, validCount);
            resultSet->Close();
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
        pathArray[validCount] = pathStr;
        validCount++;
        ret = resultSet->GoToNextRow();
    }
    resultSet->Close();

    *paths = pathArray;
    *count = validCount;
    return CM_SUCCESS;
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
    if (revocationCacheMetaRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheMetaRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    std::string sql = std::string("SELECT ") + COLUMN_CONFIG_VALUE + " FROM " +
        REVOCATION_CACHE_META_TABLE_NAME + " WHERE " + COLUMN_CONFIG_KEY + " = ?";
    std::vector<NativeRdb::ValueObject> args;
    args.emplace_back(std::string(REVOCATION_CACHE_LAST_CLEANUP_KEY));
    auto resultSet = revocationCacheMetaRdbDataManager->QueryBySql(sql, args);
    if (resultSet == nullptr) {
        CM_LOG_E("query meta failed");
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
        return CMR_ERROR_NOT_FOUND;
    }

    int valueIndex = 0;
    if (resultSet->GetColumnIndex(COLUMN_CONFIG_VALUE, valueIndex) != NativeRdb::E_OK) {
        CM_LOG_E("GetColumnIndex for value failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    std::string strValue;
    if (resultSet->GetString(valueIndex, strValue) != NativeRdb::E_OK) {
        CM_LOG_E("GetString for value failed");
        resultSet->Close();
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    resultSet->Close();

    *value = std::strtoll(strValue.c_str(), nullptr, 10);
    return CM_SUCCESS;
}

int32_t SetRevocationCacheMeta(int64_t value)
{
    CM_LOG_D("enter SetRevocationCacheMeta");
    if (revocationCacheMetaRdbDataManager == nullptr) {
        CM_LOG_E("revocationCacheMetaRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(COLUMN_CONFIG_KEY, REVOCATION_CACHE_LAST_CLEANUP_KEY);
    valuesBucket.PutString(COLUMN_CONFIG_VALUE, std::to_string(value));
    if (!revocationCacheMetaRdbDataManager->InsertData(valuesBucket)) {
        CM_LOG_E("Failed to set revocation cache meta");
        return CMR_ERROR_INSERT_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
