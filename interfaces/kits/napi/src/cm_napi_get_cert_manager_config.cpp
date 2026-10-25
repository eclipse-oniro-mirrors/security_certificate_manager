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

#include "cm_napi_get_cert_manager_config.h"

#include "securec.h"

#include <memory>
#include <string>
#include <vector>

#include "cert_manager_api.h"
#include "cm_config_type.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_metrics.h"
#include "cm_napi_common.h"
#include "cm_type.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_CONFIG_ARGS = 1;
constexpr uint32_t MAX_KEY_COUNT = 16;
}

struct GetCertManagerConfigAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *keysBlob = nullptr;
    struct CertManagerConfig config = { 0, nullptr };
    std::shared_ptr<OHOS::Security::CertManager::CmMetricsReport> metricsReport = nullptr;
};
using GetCertManagerConfigAsyncContext = GetCertManagerConfigAsyncContextT *;

static GetCertManagerConfigAsyncContext CreateGetConfigAsyncContext()
{
    GetCertManagerConfigAsyncContext context =
        static_cast<GetCertManagerConfigAsyncContext>(CmMalloc(sizeof(GetCertManagerConfigAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(GetCertManagerConfigAsyncContextT), 0, sizeof(GetCertManagerConfigAsyncContextT));
    }
    return context;
}

static void DeleteGetConfigAsyncContext(napi_env env, GetCertManagerConfigAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keysBlob != nullptr) {
        CM_FREE_PTR(context->keysBlob->data);
        CmFree(context->keysBlob);
        context->keysBlob = nullptr;
    }

    CmFreeCertManagerConfig(&context->config);

    CmFree(context);
    context = nullptr;
}

static int32_t ParseKeysArray(napi_env env, napi_value arrayValue, GetCertManagerConfigAsyncContext context)
{
    bool isArray = false;
    napi_status status = napi_is_array(env, arrayValue, &isArray);
    if (status != napi_ok || !isArray) {
        CM_LOG_E("configNames param is not an array");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t arrayLen = 0;
    status = napi_get_array_length(env, arrayValue, &arrayLen);
    if (status != napi_ok) {
        CM_LOG_E("get array length failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (arrayLen == 0) {
        CM_LOG_E("configNames array is empty");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (arrayLen > MAX_KEY_COUNT) {
        CM_LOG_E("configNames array length %u exceeds max %u", arrayLen, MAX_KEY_COUNT);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    std::vector<std::string> keys;
    keys.reserve(arrayLen);
    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element = nullptr;
        status = napi_get_element(env, arrayValue, i, &element);
        if (status != napi_ok || element == nullptr) {
            CM_LOG_E("get array element %u failed", i);
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        size_t strLen = 0;
        status = napi_get_value_string_utf8(env, element, nullptr, 0, &strLen);
        if (status != napi_ok || strLen == 0 || strLen >= MAX_LEN_CONFIG_KEY) {
            CM_LOG_E("invalid configName string at index %u, len = %zu", i, strLen);
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        std::string key(strLen + 1, '\0');
        status = napi_get_value_string_utf8(env, element, &key[0], strLen + 1, &strLen);
        if (status != napi_ok) {
            CM_LOG_E("get configName string value failed at index %u", i);
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        key.resize(strLen);
        keys.push_back(std::move(key));
    }

    /* pack keys into a CmBlob: "keyA\0keyB\0\0" (each key null-terminated, block ends with extra \0) */
    uint32_t totalSize = 1; /* trailing \0 */
    for (const auto &k : keys) {
        totalSize += static_cast<uint32_t>(k.size()) + 1; /* key + \0 */
    }

    uint8_t *buf = static_cast<uint8_t *>(CmMalloc(totalSize));
    if (buf == nullptr) {
        CM_LOG_E("malloc keys blob failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(buf, totalSize, 0, totalSize);

    uint32_t offset = 0;
    for (const auto &k : keys) {
        if (memcpy_s(buf + offset, totalSize - offset, k.c_str(), k.size() + 1) != EOK) {
            CM_FREE_PTR(buf);
            CM_LOG_E("memcpy_s key failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
        offset += static_cast<uint32_t>(k.size()) + 1;
    }
    /* buf is already zero-terminated at the end by memset_s */

    context->keysBlob = static_cast<struct CmBlob *>(CmMalloc(sizeof(struct CmBlob)));
    if (context->keysBlob == nullptr) {
        CM_FREE_PTR(buf);
        CM_LOG_E("malloc keysBlob struct failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    context->keysBlob->data = buf;
    context->keysBlob->size = totalSize;
    return CM_SUCCESS;
}

static napi_value GetConfigParseParams(
    napi_env env, napi_callback_info info, GetCertManagerConfigAsyncContext context)
{
    size_t argc = CM_NAPI_GET_CONFIG_ARGS;
    napi_value argv[CM_NAPI_GET_CONFIG_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_GET_CONFIG_ARGS) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "arguments count invalid, should be 1.",
            context->metricsReport.get());
        CM_LOG_E("arguments count invalid. argc = %zu", argc);
        return nullptr;
    }

    int32_t ret = ParseKeysArray(env, argv[0], context);
    if (ret != CM_SUCCESS) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "parse configNames array failed",
            context->metricsReport.get());
        CM_LOG_E("parse configNames array failed, ret = %d", ret);
        return nullptr;
    }

    return GetInt32(env, 0);
}

static void GetConfigExecute(napi_env env, void *data)
{
    GetCertManagerConfigAsyncContext context = static_cast<GetCertManagerConfigAsyncContext>(data);
    context->result = CmGetCertManagerConfig(context->keysBlob, &context->config);
}

static napi_value GenerateConfigResult(napi_env env, const struct CertManagerConfig *config)
{
    napi_value resultArray = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, config->count, &resultArray));

    for (uint32_t i = 0; i < config->count; i++) {
        napi_value item = nullptr;
        napi_value key = nullptr;
        napi_value value = nullptr;

        NAPI_CALL(env, napi_create_string_utf8(env, config->configItems[i].key, NAPI_AUTO_LENGTH, &key));
        NAPI_CALL(env, napi_create_string_utf8(env, config->configItems[i].value, NAPI_AUTO_LENGTH, &value));
        NAPI_CALL(env, napi_create_object(env, &item));
        NAPI_CALL(env, napi_set_named_property(env, item, "name", key));
        NAPI_CALL(env, napi_set_named_property(env, item, "value", value));
        NAPI_CALL(env, napi_set_element(env, resultArray, i, item));
    }

    return resultArray;
}

static void GetConfigResolve(napi_env env, GetCertManagerConfigAsyncContext context)
{
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GenerateConfigResult(env, &context->config);
        if (result[1] == nullptr) {
            CM_LOG_E("generate config result failed");
            result[1] = GetNull(env);
        }
        if (context->metricsReport != nullptr) {
            context->metricsReport->Finish(CM_SUCCESS);
        }
    } else {
        result[0] = GenerateBusinessError(env, context->result, context->metricsReport.get());
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
}

static void GetConfigComplete(napi_env env, napi_status status, void *data)
{
    GetCertManagerConfigAsyncContext context = static_cast<GetCertManagerConfigAsyncContext>(data);
    GetConfigResolve(env, context);
    DeleteGetConfigAsyncContext(env, context);
}

static napi_value GetConfigAsyncWork(napi_env env, GetCertManagerConfigAsyncContext &context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetCertManagerConfigAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetConfigExecute,
        GetConfigComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not queue async work");
        DeferredResolveUndefined(env, context->deferred);
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetCertManagerConfig(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get cert manager config enter");
    OHOS::Security::CertManager::CmMetricsReport report("getCertManagerConfig");
    report.Start();

    GetCertManagerConfigAsyncContext context = CreateGetConfigAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        report.Finish(INNER_FAILURE);
        return nullptr;
    }
    auto reportHolder = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));
    context->metricsReport = reportHolder;

    napi_value result = GetConfigParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetConfigAsyncContext(env, context);
        return nullptr;
    }
    result = GetConfigAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        reportHolder->Finish(INNER_FAILURE);
        DeleteGetConfigAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get cert manager config end");
    return result;
}
}  // namespace CMNapi
