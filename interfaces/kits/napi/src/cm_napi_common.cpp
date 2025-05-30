/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_common.h"

#include <unordered_map>
#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"

namespace CMNapi {
namespace {
constexpr int CM_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M

static const std::string NO_PERMISSION_MSG = "the caller has no permission";
static const std::string NOT_SYSTEM_APP_MSG = "the caller is not a system application";
static const std::string INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string NO_FOUND_MSG = "the certificate do not exist";
static const std::string INCORRECT_FORMAT_MSG = "the input cert data is invalid";
static const std::string MAX_CERT_COUNT_REACHED_MSG = "the count of certificates or credentials reach the max";
static const std::string NO_AUTHORIZATION_MSG = "the application is not authorized by user";
static const std::string ALIAS_LENGTH_REACHED_LIMIT_MSG = "the input alias length reaches the max";
static const std::string DEVICE_ENTER_ADVSECMODE_MSG = "the device enters advanced security mode";
static const std::string PASSWORD_IS_ERROR_MSG = "the input password is error";

static const std::unordered_map<int32_t, int32_t> NATIVE_CODE_TO_JS_CODE_MAP = {
    // invalid params
    { CMR_ERROR_INVALID_ARGUMENT, PARAM_ERROR },

    // no permission
    { CMR_ERROR_PERMISSION_DENIED, HAS_NO_PERMISSION },
    { CMR_ERROR_NOT_SYSTEMP_APP, NOT_SYSTEM_APP },

    { CMR_ERROR_INVALID_CERT_FORMAT, INVALID_CERT_FORMAT },
    { CMR_ERROR_INSUFFICIENT_DATA, INVALID_CERT_FORMAT },
    { CMR_ERROR_NOT_FOUND, NOT_FOUND },
    { CMR_ERROR_NOT_EXIST, NOT_FOUND },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, MAX_CERT_COUNT_REACHED },
    { CMR_ERROR_AUTH_CHECK_FAILED, NO_AUTHORIZATION },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, ALIAS_LENGTH_REACHED_LIMIT },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, DEVICE_ENTER_ADVSECMODE },
    { CMR_ERROR_PASSWORD_IS_ERR, PASSWORD_IS_ERROR },
};

static const std::unordered_map<int32_t, std::string> NATIVE_CODE_TO_MSG_MAP = {
    { CMR_ERROR_PERMISSION_DENIED, NO_PERMISSION_MSG },
    { CMR_ERROR_NOT_SYSTEMP_APP, NOT_SYSTEM_APP_MSG },
    { CMR_ERROR_INVALID_ARGUMENT, INVALID_PARAMS_MSG },
    { CMR_ERROR_NOT_FOUND, NO_FOUND_MSG },
    { CMR_ERROR_NOT_EXIST, NO_FOUND_MSG },
    { CMR_ERROR_INVALID_CERT_FORMAT, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_INSUFFICIENT_DATA, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, MAX_CERT_COUNT_REACHED_MSG },
    { CMR_ERROR_AUTH_CHECK_FAILED, NO_AUTHORIZATION_MSG },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, ALIAS_LENGTH_REACHED_LIMIT_MSG },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, DEVICE_ENTER_ADVSECMODE_MSG },
    { CMR_ERROR_PASSWORD_IS_ERR, PASSWORD_IS_ERROR_MSG },
};
}  // namespace

napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_number) {
        CM_LOG_E("param type is not number");
        return nullptr;
    }
    uint32_t temp = 0;
    napi_get_value_uint32(env, object, &temp);
    store = temp;
    return GetInt32(env, 0);
}

napi_value ParseBoolean(napi_env env, napi_value object, bool &status)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_boolean) {
        CM_LOG_E("param type is not bool");
        return nullptr;
    }
    bool temp = false;
    napi_get_value_bool(env, object, &temp);
    status = temp;
    return GetInt32(env, 0);
}

napi_value ParseCertAlias(napi_env env, napi_value napiObj, CmBlob *&certAlias)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, napiObj, &valueType));
    if (valueType != napi_string) {
        CM_LOG_E("the type of napiObj is not string");
        return nullptr;
    }
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, napiObj, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("Failed to get string length");
        return nullptr;
    }
    if (length > CM_MAX_DATA_LEN) { /* alias can be empty */
        CM_LOG_E("input alias length is too large, length: %d", length);
        return nullptr;
    }

    char *value = static_cast<char *>(CmMalloc(length + 1));
    if (value == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(value, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, napiObj, value, length + 1, &result);
    if (status != napi_ok) {
        CmFree(value);
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    certAlias = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (certAlias == nullptr) {
        CmFree(value);
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    certAlias->data = reinterpret_cast<uint8_t *>(value);
    certAlias->size = static_cast<uint32_t>((length + 1) & UINT32_MAX);
    return GetInt32(env, 0);
}

static napi_value ParseStringCommon(napi_env env, napi_value object, CmBlob *&stringBlob, bool canBeEmpty)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    if (valueType != napi_string) {
        CM_LOG_E("the type of param is not string");
        return nullptr;
    }
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string length");
        return nullptr;
    }

    // add max length check
    if (length > CM_MAX_DATA_LEN) {
        CM_LOG_E("input string length is too large, length: %d", length);
        return nullptr;
    }
    // add 0 length check
    if (!canBeEmpty && length == 0) {
        CM_LOG_E("input string length is 0");
        return nullptr;
    }

    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (data == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, data, length + 1, &result);
    if (status != napi_ok) {
        CmFree(data);
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    stringBlob = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (stringBlob == nullptr) {
        CmFree(data);
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    stringBlob->data = reinterpret_cast<uint8_t *>(data);
    stringBlob->size = static_cast<uint32_t>((length + 1) & UINT32_MAX);

    return GetInt32(env, 0);
}

napi_value ParseString(napi_env env, napi_value object, CmBlob *&stringBlob)
{
    return ParseStringCommon(env, object, stringBlob, false);
}

napi_value ParsePasswd(napi_env env, napi_value object, CmBlob *&stringBlob)
{
    return ParseStringCommon(env, object, stringBlob, true);
}

napi_value GetUint8Array(napi_env env, napi_value object, CmBlob &arrayBlob)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(
        env, object, &arrayType, &length, static_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        CM_LOG_E("the type of param is not uint8_array");
        return nullptr;
    }
    if (length > CM_MAX_DATA_LEN) {
        CM_LOG_E("Data is too large, length = %x", length);
        return nullptr;
    }
    if (length == 0) {
        CM_LOG_D("The memory length created is only 1 Byte");
        // The memory length created is only 1 Byte
        arrayBlob.data = static_cast<uint8_t *>(CmMalloc(1));
    } else {
        arrayBlob.data = static_cast<uint8_t *>(CmMalloc(length));
    }
    if (arrayBlob.data == nullptr) {
        CM_LOG_E("Malloc failed");
        return nullptr;
    }
    (void)memset_s(arrayBlob.data, length, 0, length);
    if (memcpy_s(arrayBlob.data, length, rawData, length) != EOK) {
        CM_LOG_E("memcpy_s fail, length = %x", length);
        return nullptr;
    }
    arrayBlob.size = static_cast<uint32_t>(length);

    return GetInt32(env, 0);
}

napi_ref GetCallback(napi_env env, napi_value object)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("could not get object type");
        return nullptr;
    }

    if (valueType != napi_function) {
        CM_LOG_E("invalid type");
        return nullptr;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, object, 1, &ref);
    if (status != napi_ok) {
        CM_LOG_E("could not create reference");
        return nullptr;
    }
    return ref;
}

int32_t GetCallback(napi_env env, napi_value object, napi_ref &callback)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("could not get object type");
        return CM_FAILURE;
    }

    if (valueType == napi_null || valueType == napi_undefined) {
        CM_LOG_D("callback is null or undefined, treat as promise");
        return CM_SUCCESS;
    }

    if (valueType != napi_function) {
        CM_LOG_E("invalid type, not function");
        return CM_FAILURE;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, object, 1, &ref);
    if (status != napi_ok) {
        CM_LOG_E("could not create reference");
        return CM_FAILURE;
    }
    callback = ref;
    return CM_SUCCESS;
}

static napi_value GenerateAarrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *buffer = static_cast<uint8_t *>(CmMalloc(size));
    if (buffer == nullptr) {
        return nullptr;
    }
    (void)memcpy_s(buffer, size, data, size);

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, size, [](napi_env env, void *data, void *hint) { CmFree(data); }, nullptr, &outBuffer);
    if (status == napi_ok) {
        // free by finalize callback
        buffer = nullptr;
    } else {
        CmFree(buffer);
        GET_AND_THROW_LAST_ERROR((env));
    }

    return outBuffer;
}

napi_value GenerateCertAbstractArray(napi_env env, const struct CertAbstract *certAbstract, const uint32_t certCount)
{
    if (certCount == 0 || certAbstract == nullptr) {
        return nullptr;
    }
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array(env, &array));
    for (uint32_t i = 0; i < certCount; i++) {
        napi_value uri = nullptr;
        napi_value certAlias = nullptr;
        napi_value subjectName = nullptr;
        napi_value status = nullptr;

        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].uri), NAPI_AUTO_LENGTH, &uri);
        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].certAlias),
            NAPI_AUTO_LENGTH, &certAlias);
        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].subjectName),
            NAPI_AUTO_LENGTH, &subjectName);
        napi_get_boolean(env, certAbstract[i].status, &status);

        napi_value element = nullptr;
        napi_create_object(env, &element);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_URI.c_str(), uri);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_CERTALIAS.c_str(), certAlias);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_STATUS.c_str(), status);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_STATE.c_str(), status);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_SUBJECTNAME.c_str(), subjectName);

        napi_set_element(env, array, i, element);
    }
    return array;
}

napi_value GenerateCredentialAbstractArray(napi_env env,
    const struct CredentialAbstract *credentialAbstract, const uint32_t credentialCount)
{
    if (credentialCount == 0 || credentialAbstract == nullptr) {
        return nullptr;
    }
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array(env, &array));
    for (uint32_t i = 0; i < credentialCount; i++) {
        napi_value type = nullptr;
        napi_value alias = nullptr;
        napi_value keyUri = nullptr;
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].type),
            NAPI_AUTO_LENGTH, &type);
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].alias),
            NAPI_AUTO_LENGTH, &alias);
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].keyUri),
            NAPI_AUTO_LENGTH, &keyUri);

        napi_value element = nullptr;
        napi_create_object(env, &element);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_TYPE.c_str(), type);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_CREDENTIAL_ALIAS.c_str(), alias);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_KEY_URI.c_str(), keyUri);

        napi_set_element(env, array, i, element);
    }
    return array;
}

napi_value GenerateCertInfo(napi_env env, const struct CertInfo *certInfo)
{
    if (certInfo == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    struct CertInfoValue cInfVal = { nullptr };
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->uri),
        NAPI_AUTO_LENGTH, &cInfVal.uri));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->certAlias),
        NAPI_AUTO_LENGTH, &cInfVal.certAlias));
    NAPI_CALL(env, napi_get_boolean(env, certInfo->status, &cInfVal.status));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->issuerName),
        NAPI_AUTO_LENGTH, &cInfVal.issuerName));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->subjectName),
        NAPI_AUTO_LENGTH, &cInfVal.subjectName));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->serial),
        NAPI_AUTO_LENGTH, &cInfVal.serial));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->notBefore),
        NAPI_AUTO_LENGTH, &cInfVal.notBefore));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->notAfter),
        NAPI_AUTO_LENGTH, &cInfVal.notAfter));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->fingerprintSha256),
        NAPI_AUTO_LENGTH, &cInfVal.fingerprintSha256));

    napi_value certBuffer = GenerateAarrayBuffer(env, certInfo->certInfo.data, certInfo->certInfo.size);
    if (certBuffer != nullptr) {
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, certInfo->certInfo.size,
            certBuffer, 0, &cInfVal.certInfoBlob));
    }

    napi_value elem = nullptr;
    NAPI_CALL(env, napi_create_object(env, &elem));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_URI.c_str(), cInfVal.uri));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_CERTALIAS.c_str(), cInfVal.certAlias));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_STATUS.c_str(), cInfVal.status));
    NAPI_CALL(env, napi_set_named_property (env, elem, CM_CERT_PROPERTY_STATE.c_str(), cInfVal.status));

    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_ISSUERNAME.c_str(), cInfVal.issuerName));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_SUBJECTNAME.c_str(), cInfVal.subjectName));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_SERIAL.c_str(), cInfVal.serial));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_BEFORE.c_str(), cInfVal.notBefore));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_AFTER.c_str(), cInfVal.notAfter));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_FINGERSHA256.c_str(),
        cInfVal.fingerprintSha256));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_CERT_DATA.c_str(), cInfVal.certInfoBlob));

    return elem;
}

static const char *GetJsErrorMsg(int32_t errCode)
{
    auto iter = NATIVE_CODE_TO_MSG_MAP.find(errCode);
    if (iter != NATIVE_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return GENERIC_MSG.c_str();
}

int32_t TranformErrorCode(int32_t errorCode)
{
    auto iter = NATIVE_CODE_TO_JS_CODE_MAP.find(errorCode);
    if (iter != NATIVE_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return INNER_FAILURE;
}

napi_value GenerateBusinessError(napi_env env, int32_t errorCode)
{
    const char *errorMsg = GetJsErrorMsg(errorCode);
    if (errorMsg == nullptr) {
        return nullptr;
    }

    napi_value code = nullptr;
    int32_t outCode = TranformErrorCode(errorCode);
    NAPI_CALL(env, napi_create_int32(env, outCode, &code));

    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMsg, NAPI_AUTO_LENGTH, &message));

    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, message, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    return businessError;
}

void ThrowError(napi_env env, int32_t errorCode, std::string errMsg)
{
    napi_value paramsError = nullptr;
    napi_value code = nullptr;
    napi_value message = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, errorCode, &code));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message));
    NAPI_CALL_RETURN_VOID(env, napi_create_error(env, nullptr, message, &paramsError));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, paramsError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, paramsError));
}

napi_value GenerateAppCertInfo(napi_env env, const struct Credential *credential)
{
    if (credential == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value type = nullptr;
    napi_value alias = nullptr;
    napi_value keyUri = nullptr;
    napi_value certNum = nullptr;
    napi_value keyNum = nullptr;
    napi_value credData = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->type),
        NAPI_AUTO_LENGTH, &type));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->alias),
        NAPI_AUTO_LENGTH, &alias));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->keyUri),
        NAPI_AUTO_LENGTH, &keyUri));

    NAPI_CALL(env, napi_create_int32(env, credential->certNum, &certNum));
    NAPI_CALL(env, napi_create_int32(env, credential->keyNum, &keyNum));

    napi_value crendentialBuffer = GenerateAarrayBuffer(env, credential->credData.data, credential->credData.size);
    if (crendentialBuffer != nullptr) {
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, credential->credData.size,
            crendentialBuffer, 0, &credData));
    }

    napi_value element = nullptr;
    NAPI_CALL(env, napi_create_object(env, &element));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_TYPE.c_str(), type));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CREDENTIAL_ALIAS.c_str(), alias));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_KEY_URI.c_str(), keyUri));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CERT_NUM.c_str(), certNum));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_KEY_NUM.c_str(), keyNum));

    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CREDENTIAL_DATA.c_str(), credData));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CREDENTIAL_DATA_NEW.c_str(), credData));
    return element;
}

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t arrLength)
{
    if (arrLength < RESULT_NUMBER) {
        return;
    }
    if (resultCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, result[0]));
    }
}

void GenerateCallback(napi_env env, napi_ref callback, napi_value *result, int32_t arrLength, int32_t ret)
{
    napi_value func = nullptr;
    napi_value returnVal = nullptr;
    if (arrLength < RESULT_NUMBER) {
        return;
    }
    napi_value businessError = (ret == CM_SUCCESS) ? nullptr : result[0];
    napi_value params[RESULT_NUMBER] = { businessError, result[1] };
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callback, &func));

    napi_value recv = nullptr;
    napi_get_undefined(env, &recv);
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, recv, func, RESULT_NUMBER, params, &returnVal));
}

void GenerateNapiPromise(napi_env env, napi_ref callback, napi_deferred *deferred, napi_value *promise)
{
    if (callback == nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, deferred, promise));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, promise));
    }
}

void DeleteNapiContext(napi_env env, napi_async_work &asyncWork, napi_ref &callback)
{
    if (asyncWork != nullptr) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }

    if (callback != nullptr) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
}

void FreeCmContext(CmContext *&context)
{
    if (context == nullptr) {
        return;
    }

    context->userId = 0;
    context->uid = 0;

    CmFree(context);
    context = nullptr;
}

void FreeCertList(CertList *&certList)
{
    if (certList == nullptr || certList->certAbstract == nullptr) {
        return;
    }

    FreeCertAbstract(certList->certAbstract);
    certList->certAbstract = nullptr;

    CmFree(certList);
    certList = nullptr;
}

void FreeCredentialList(CredentialList *&credentialList)
{
    if (credentialList == nullptr || credentialList->credentialAbstract == nullptr) {
        return;
    }

    FreeCredentialAbstract(credentialList->credentialAbstract);
    credentialList->credentialAbstract = nullptr;

    CmFree(credentialList);
    credentialList = nullptr;
}

void FreeCertInfo(CertInfo *&certInfo)
{
    if (certInfo == nullptr) {
        return;
    }

    certInfo->status = false;

    if (certInfo->certInfo.data != nullptr) {
        CmFree(certInfo->certInfo.data);
    }

    CmFree(certInfo);
    certInfo = nullptr;
}

void FreeCredential(Credential *&credential)
{
    if (credential == nullptr) {
        return;
    }

    if (credential->credData.data != nullptr) {
        CmFree(credential->credData.data);
    }

    CmFree(credential);
    credential = nullptr;
}

bool IsValidCertType(const uint32_t certType)
{
    switch (static_cast<CmCertType>(certType)) {
        case CM_CA_CERT_SYSTEM:
        case CM_CA_CERT_USER:
            return true;
        default:
            return false;
    }
}

bool IsValidCertScope(const uint32_t scope)
{
    switch (static_cast<CmCertScope>(scope)) {
        case CM_CURRENT_USER:
        case CM_GLOBAL_USER:
            return true;
        default:
            return false;
    }
}

bool IsValidCertAlg(const uint32_t certAlg)
{
    switch (static_cast<CmCertAlg>(certAlg)) {
        case CM_ALG_INTERNATIONAL:
        case CM_ALG_SM:
            return true;
        default:
            return false;
    }
}
}  // namespace CertManagerNapi
