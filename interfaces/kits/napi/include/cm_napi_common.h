/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CM_NAPI_COMMON_H
#define CM_NAPI_COMMON_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "cm_mem.h"
#include "cm_type.h"

#define DATA_SIZE_64KB  (1024 * 64)
#define NAPI_ASSERT_FUNC(f) if (CM_SUCCESS != (f)) { CM_LOG_W("Failed: %s\n", #f); return; }

namespace CMNapi {
static const std::string CM_CONTEXT_PROPERTY_USERID = "userId";
static const std::string CM_CONTEXT_PROPERTY_UID = "uid";
static const std::string CM_CONTEXT_PROPERTY_PACKAGENAME = "packageName";

static const std::string CM_CERT_PROPERTY_URI = "uri";
static const std::string CM_CERT_PROPERTY_TYPE = "type";
static const std::string CM_CERT_PROPERTY_CREDENTIAL_ALIAS = "alias";
static const std::string CM_CERT_PROPERTY_KEY_URI = "keyUri";
static const std::string CM_CERT_PROPERTY_KEY_NUM = "keyNum";
static const std::string CM_CERT_PROPERTY_CERT_NUM = "certNum";
static const std::string CM_CERT_PROPERTY_CREDENTIAL_DATA = "credData";

static const std::string CM_CERT_PROPERTY_CERTALIAS = "certAlias";
static const std::string CM_CERT_PROPERTY_ISSUERNAME = "issuerName";
static const std::string CM_CERT_PROPERTY_SUBJECTNAME = "subjectName";
static const std::string CM_CERT_PROPERTY_SERIAL = "serial";
static const std::string CM_CERT_PROPERTY_BEFORE = "notBefore";
static const std::string CM_CERT_PROPERTY_AFTER = "notAfter";
static const std::string CM_CERT_PROPERTY_FINGERSHA1 = "fingerprintSha1";
static const std::string CM_CERT_PROPERTY_FINGERSHA256 = "fingerprintSha256";
static const std::string CM_CERT_PROPERTY_CERTINFO = "certInfo";
static const std::string CM_CERT_PROPERTY_STATUS = "status";

static const std::string BUSINESS_ERROR_PROPERTY_CODE = "code";
static const std::string BUSINESS_ERROR_PROPERTY_MESSAGE = "message";

static const size_t CM_HANDLE_OFFSET32 = 32;
static const std::string CM_OPTIONS_PROPERTY_PROPERTIES = "properties";
static const std::string CM_OPTIONS_PROPERTY_INDATA = "inData";

static const std::string CM_PARAM_PROPERTY_TAG = "tag";
static const std::string CM_PARAM_PROPERTY_VALUE = "value";

static const std::string CM_RESULT_PRPPERTY_CERTLIST = "certList";
static const std::string CM_RESULT_PRPPERTY_CERTINFO = "certInfo";
static const std::string CM_RESULT_PRPPERTY_CREDENTIAL_LIST = "credentialList";
static const std::string CM_RESULT_PRPPERTY_CREDENTIAL = "credential";

static const std::string CM_HANDLE_PROPERTY_HANDLE = "handle";

static const int32_t CERT_MANAGER_SYS_CAP = 17500000;
static const int32_t RESULT_NUMBER = 2;
static const uint32_t APPLICATION_CERTIFICATE_STORE = 0;
static const uint32_t SYSTEM_CERTIFICATE_STORE = 1;
static const std::string PARAM_TYPE_ERROR_NUMBER = "401";


napi_value ParseCmContext(napi_env env, napi_value object, CmContext *&cmContext);
napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store);
napi_value ParseBoolean(napi_env env, napi_value object, bool &status);
napi_value ParseString(napi_env env, napi_value object, CmBlob *&certUri);
napi_value GetUint8Array(napi_env env, napi_value object, CmBlob &arrayBlob);

napi_ref GetCallback(napi_env env, napi_value object);

napi_value GenerateCertAbstractArray(
    napi_env env, const struct CertAbstract *certAbstract, const uint32_t certCount);

napi_value GenerateCredentialAbstractArray(napi_env env,
    const struct CredentialAbstract *credentialAbstract, const uint32_t credentialCount);

napi_value GenerateCertInfo(napi_env env, const struct CertInfo *certInfo);
napi_value GenerateAppCertInfo(napi_env env, const struct Credential *credential);
napi_value GenerateBusinessError(napi_env env, int32_t errorCode, const char *errorMessage);

void DeleteNapiContext(napi_env env, napi_async_work &asyncWork, napi_ref &callback);

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t arrLength);
void GenerateCallback(napi_env env, napi_ref callback, napi_value *result, int32_t arrLength);
void GenerateNapiPromise(napi_env env, napi_ref callback, napi_deferred *deferred, napi_value *promise);

inline napi_value GetNull(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

inline napi_value GetInt32(napi_env env, int32_t value)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &result));
    return result;
}

inline void FreeCmBlob(CmBlob *&blob)
{
    if (blob == nullptr) {
        return;
    }

    if (blob->data != nullptr) {
        CmFree(blob->data);
        blob->data = nullptr;
    }
    blob->size = 0;

    CmFree(blob);
    blob = nullptr;
}

void FreeCmContext(CmContext *&context);

inline void FreeCertAbstract(CertAbstract *&certAbstract)
{
    if (certAbstract == nullptr) {
        return;
    }

    certAbstract->status = false;

    CmFree(certAbstract);
    certAbstract = nullptr;
}

inline void FreeCredentialAbstract(CredentialAbstract *&CredentialAbstract)
{
    if (CredentialAbstract == nullptr) {
        return;
    }

    CmFree(CredentialAbstract);
    CredentialAbstract = nullptr;
}

void FreeCertList(CertList *&certList);
void FreeCredentialList(CredentialList *&credentialList);
void FreeCertInfo(CertInfo *&certInfo);
void FreeCredential(Credential *&credential);

enum CmErrorCode {
    CM_SUCCESS = 0,
    CM_FAILURE = 17500001,

    CMR_NOT_PERMITTED = 17500002,
    CMR_NOT_SUPPORTED = 17500003,
    CMR_INVALID_ARGUMENT = 17500004,
    CMR_BUFFER_TOO_SMALL = 17500006,
    CMR_MEM_ERROR = 17500007,
    CMR_STORAGE_ERROR = 17500008,
    CMR_NOT_FOUND = 17500009,
    CMR_FILE_READ_ERROR = 17500010,
    CMR_FILE_WRITE_ERROR = 17500011,
    CMR_NULL_POINTER_ERROR = 17500012,
    CMR_INSUFFICIENT_DATA = 17500013,
    CMR_ERROR_MAKE_DIR_FAIL = 17500014,
    CMR_ERROR_INTERNAL_ERROR = 17500015,
    CMR_ERROR_REMOVE_FILE_FAIL = 17500016,
    CMR_ERROR_INVALID_ARGUMENT = 17500017,
    CMR_ERROR_WRITE_FILE_FAIL = 17500018,
    CMR_ERROR_OPEN_FILE_FAIL = 17500019,
    CMR_ERROR_CLOSE_FILE_FAIL = 17500020,
    CMR_ERROR_BAD_STATE = 17500021,
    CMR_ERROR_INVALID_KEY_FILE = 17500022,
    CMR_ERROR_MALLOC_FAIL = 17500023,
    CMR_ERROR_NOT_EXIST   = 17500024,
    CMR_ERROR_NULL_POINTER = 17500025,
    CMR_ERROR_ALREADY_EXISTS = 17500026,

    CMR_ERROR_NOT_SUPPORTED = 17500027,
    CMR_ERROR_INSUFFICIENT_DATA = 17500028,
    CMR_ERROR_BUFFER_TOO_SMALL = 17500029,
    CMR_ERROR_INSUFFICIENT_MEMORY = 17500030,
    CMR_ERROR_INVALID_CERT_FORMAT = 17500031,
    CMR_ERROR_NOT_FOUND = 17500032,

    CMR_ERROR_KEY_ERROR = 17500033,
    CMR_ERROR_PARAM_NOT_EXIST = 17500034,
    CMR_ERROR_INVALID_OPERATION = 17500035,
};
}  // namespace CertManagerNapi

#endif
