/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CM_RDB_CONFIG_H
#define CM_RDB_CONFIG_H

#include <string>
#include <vector>

const int32_t RDB_VERSION_FIRST = 1;
const int32_t RDB_VERSION_CURRENT = 2;

const std::string CERT_MANAGER_RDB_NAME = "/cert_manager.db";
const std::string CERT_PROPERTY_TABLE_NAME = "cert_property";
const std::string COLUMN_URI = "URI";
const std::string COLUMN_ALIAS = "ALIAS";
const std::string COLUMN_SUBJECT_NAME = "SUBJECT_NAME";
const std::string COLUMN_CERT_TYPE = "CERT_TYPE";
const std::string COLUMN_CERT_STORE = "CERT_STORE";
const std::string COLUMN_USERID = "USERID";
const std::string COLUMN_UID = "UID";
const std::string COLUMN_AUTH_STORAGE_LEVEL = "AUTH_STORAGE_LEVEL";

const std::string CERT_MANAGER_CONFIG_TABLE_NAME = "cert_manager_config";
const std::string COLUMN_CONFIG_KEY = "CONFIG_KEY";
const std::string COLUMN_CONFIG_VALUE = "CONFIG_VALUE";

const std::string REVOCATION_CACHE_TABLE_NAME = "revocation_cache";
const std::string COLUMN_EXPIRE_TIME_UTC = "EXPIRE_TIME_UTC";
const std::string COLUMN_WRITE_TIME_UTC = "WRITE_TIME_UTC";
const std::string COLUMN_FILE_PATH = "FILE_PATH";
const std::string COLUMN_DATA_SIZE = "DATA_SIZE";
const std::string REVOCATION_CACHE_META_TABLE_NAME = "revocation_cache_meta";
const std::string REVOCATION_CACHE_LAST_CLEANUP_KEY = "last_cleanup_utc";

namespace OHOS {
namespace Security {
namespace CertManager {
struct RdbConfig {
    int32_t version = RDB_VERSION_CURRENT;
    std::string dbPath = "/data/service/el1/public/cert_manager_service/rdb";
    std::string dbName;
    std::string tableName;
    std::string createTableSql;
};
} // namespace CertManager
} // namespace Security
} // namespace OHOS

#endif // CM_RDB_CONFIG_H