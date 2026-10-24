/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "cm_napi_open_install_dialog.h"

#include <memory>

#include "cm_log.h"
#include "cm_metrics.h"
#include "cm_napi_dialog_common.h"
#include "cm_napi_dialog_callback_string.h"

#include "securec.h"
#include "syspara/parameters.h"
#include "want.h"
#include "want_params_wrapper.h"

namespace CMNapi {
/* same bound as CM_MAX_DATA_LEN elsewhere and the ets MAX_DATA_LEN */
constexpr int CM_MAX_DATA_LEN = 0x6400000;

static bool IsCmCertificateScopeEnum(const uint32_t value)
{
    return value >= NOT_SPECIFIED && value <= GLOBAL_USER;
}

static bool IsCmCertificateTypeAndConvert(const uint32_t value, uint32_t &pageType)
{
    switch (static_cast<CmCertificateType>(value)) {
        case CmCertificateType::CA_CERT:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        case CmCertificateType::CREDENTIAL_USER:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        case CmCertificateType::CREDENTIAL_SYSTEM:
            pageType = CmDialogPageType::PAGE_INSTALL_CA_GUIDE;
            return true;
        default:
            return false;
    }
}

static napi_value CMCheckArgvAndInitContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], size_t length)
{
    if (length != PARAM_SIZE_FOUR) {
        CM_LOG_E("params number vaild failed");
        return nullptr;
    }
    // Parse first argument for context.
    if (!ParseCmUIAbilityContextReq(asyncContext->env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return nullptr;
    }

    if (!IsCmCertificateTypeAndConvert(asyncContext->certificateType, asyncContext->pageType)) {
        CM_LOG_E("certificateType invalid");
        return nullptr;
    }

    // Parse third argument for certificateScope.
    if (ParseUint32(asyncContext->env, argv[PARAM2], asyncContext->certificateScope) == nullptr) {
        CM_LOG_E("parse type failed");
        return nullptr;
    }
    if (!IsCmCertificateScopeEnum(asyncContext->certificateScope)) {
        CM_LOG_E("certificateScope invalid");
        return nullptr;
    }

    // Parse fourth argument for cert.
    if (GetUint8ArrayToBase64Str(asyncContext->env, argv[PARAM3], asyncContext->certStr) == nullptr) {
        CM_LOG_E("cert is not a uint8Array or the length is 0 or too long.");
        return nullptr;
    }
    return GetInt32(asyncContext->env, 0);
}

/* Throws errorCode with errMsg and returns it, so the request parsers below
 * can fail with `return ThrowParamError(...)`. */
static int32_t ThrowParamError(napi_env env, int32_t errorCode, const std::string &errMsg,
    OHOS::Security::CertManager::CmMetricsReport *report)
{
    ThrowError(env, errorCode, errMsg, report);
    return errorCode;
}

/* Optional keystorePwd of InstallCertificateRequest (since 26.2.0): absent, undefined
 * or null means "not provided" (the dialog asks the user for the password); any string
 * value, including an empty one, is a provided password (an empty P12 password is valid).
 * A non-string type throws PARAM_ERROR (401) and a UTF-8 length beyond
 * KEYSTORE_PWD_MAX_LEN bytes throws DIALOG_ERROR_PARAMETER_VALIDATION_FAILED
 * (29700006); returns CM_SUCCESS or the thrown JS error code. */
static int32_t ParseKeystorePwd(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value request,
    OHOS::Security::CertManager::CmMetricsReport *report)
{
    napi_env env = asyncContext->env;
    napi_value value = nullptr;
    if (napi_get_named_property(env, request, "keystorePwd", &value) != napi_ok) {
        CM_LOG_E("get keystorePwd failed");
        return ThrowParamError(env, PARAM_ERROR, "get keystorePwd failed", report);
    }
    napi_valuetype valueType = napi_undefined;
    bool typeOk = napi_typeof(env, value, &valueType) == napi_ok &&
        (valueType == napi_undefined || valueType == napi_null || valueType == napi_string);
    if (!typeOk) {
        CM_LOG_E("keystorePwd type is invalid");
        return ThrowParamError(env, PARAM_ERROR, "keystorePwd is not a string", report);
    }
    if (valueType == napi_undefined || valueType == napi_null) {
        return CM_SUCCESS; /* not provided */
    }
    /* parse locally: the shared ParseString rejects empty strings */
    size_t length = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok) {
        CM_LOG_E("get keystorePwd length failed");
        return ThrowParamError(env, DIALOG_ERROR_GENERIC, "get keystorePwd length failed", report);
    }
    if (length > static_cast<size_t>(KEYSTORE_PWD_MAX_LEN)) {
        CM_LOG_E("keystorePwd is too long");
        return ThrowParamError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "keystorePwd is too long", report);
    }
    CmBlob *blob = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (blob == nullptr || data == nullptr) {
        CM_LOG_E("alloc keystorePwd failed");
        CM_FREE_PTR(blob);
        CM_FREE_PTR(data);
        return ThrowParamError(env, DIALOG_ERROR_GENERIC, "alloc keystorePwd failed", report);
    }
    (void)memset_s(data, length + 1, 0, length + 1);
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, value, data, length + 1, &copied) != napi_ok) {
        CM_LOG_E("copy keystorePwd failed");
        CM_FREE_PTR(data);
        CM_FREE_PTR(blob);
        return ThrowParamError(env, DIALOG_ERROR_GENERIC, "copy keystorePwd failed", report);
    }
    blob->data = reinterpret_cast<uint8_t *>(data);
    blob->size = static_cast<uint32_t>(length + 1);
    asyncContext->keystorePwd = blob;
    return CM_SUCCESS;
}

/* cert of InstallCertificateRequest must be a Uint8Array (a wrong type throws
 * PARAM_ERROR, 401) holding 1..CM_MAX_DATA_LEN bytes (an invalid length throws
 * DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, 29700006). Returns CM_SUCCESS or
 * the thrown JS error code. */
static int32_t CheckAndGetCertData(std::shared_ptr<CmUIExtensionRequestContext> asyncContext, napi_value request,
    OHOS::Security::CertManager::CmMetricsReport *report)
{
    napi_env env = asyncContext->env;
    napi_value value = nullptr;
    if (napi_get_named_property(env, request, "cert", &value) != napi_ok) {
        CM_LOG_E("get cert failed");
        return ThrowParamError(env, PARAM_ERROR, "get cert failed", report);
    }
    bool isTypedArray = false;
    napi_typedarray_type arrayType = napi_uint8_array;
    size_t length = 0;
    if (napi_is_typedarray(env, value, &isTypedArray) != napi_ok || !isTypedArray ||
        napi_get_typedarray_info(env, value, &arrayType, &length, nullptr, nullptr, nullptr) != napi_ok ||
        arrayType != napi_uint8_array) {
        CM_LOG_E("cert is not a uint8Array");
        return ThrowParamError(env, PARAM_ERROR, "cert is not a Uint8Array", report);
    }
    if (length < 1 || length > CM_MAX_DATA_LEN) {
        CM_LOG_E("cert length is invalid, length = %zu", length);
        return ThrowParamError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "the cert length is invalid", report);
    }
    if (GetUint8ArrayToBase64Str(env, value, asyncContext->certStr) == nullptr) {
        /* the type and length were validated above; only an internal failure remains */
        CM_LOG_E("encode cert failed");
        return ThrowParamError(env, DIALOG_ERROR_GENERIC, "encode cert failed", report);
    }
    return CM_SUCCESS;
}

/* Parse the InstallCertificateRequest overload (since 26.2.0):
 * (context, { certType, certScope, cert, keystorePwd? }). Wrong parameter types
 * throw PARAM_ERROR (401); value range or length violations throw
 * DIALOG_ERROR_PARAMETER_VALIDATION_FAILED (29700006). Returns CM_SUCCESS or
 * the thrown JS error code. */
static int32_t ParseInstallCertificateRequest(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], OHOS::Security::CertManager::CmMetricsReport *report)
{
    napi_env env = asyncContext->env;
    // Parse first argument for context.
    if (!ParseCmUIAbilityContextReq(env, argv[PARAM0], asyncContext->context)) {
        CM_LOG_E("ParseUIAbilityContextReq failed");
        return ThrowParamError(env, PARAM_ERROR, "parse context failed", report);
    }

    napi_valuetype reqType = napi_undefined;
    if (napi_typeof(env, argv[PARAM1], &reqType) != napi_ok || reqType != napi_object) {
        CM_LOG_E("request is not an object");
        return ThrowParamError(env, PARAM_ERROR, "InstallCertificateRequest is not an object", report);
    }

    napi_value value = nullptr;
    if (napi_get_named_property(env, argv[PARAM1], "certType", &value) != napi_ok ||
        ParseUint32(env, value, asyncContext->certificateType) == nullptr) {
        CM_LOG_E("parse certType failed");
        return ThrowParamError(env, PARAM_ERROR, "parse certType failed", report);
    }
    if (!IsCmCertificateTypeAndConvert(asyncContext->certificateType, asyncContext->pageType)) {
        CM_LOG_E("certificateType invalid");
        return ThrowParamError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "certType is not supported",
            report);
    }

    if (napi_get_named_property(env, argv[PARAM1], "certScope", &value) != napi_ok ||
        ParseUint32(env, value, asyncContext->certificateScope) == nullptr) {
        CM_LOG_E("parse certificateScope failed");
        return ThrowParamError(env, PARAM_ERROR, "parse certScope failed", report);
    }
    if (!IsCmCertificateScopeEnum(asyncContext->certificateScope)) {
        CM_LOG_E("certificateScope invalid");
        return ThrowParamError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "certScope is invalid", report);
    }

    int32_t ret = CheckAndGetCertData(asyncContext, argv[PARAM1], report);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return ParseKeystorePwd(asyncContext, argv[PARAM1], report);
}

static OHOS::AAFwk::Want CMGetInstallCertWant(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(asyncContext->pageType));
    want.SetParam(CERT_MANAGER_CERT_TYPE, static_cast<int32_t>(asyncContext->certificateType));
    want.SetParam(CERT_MANAGER_CERTIFICATE_DATA, asyncContext->certStr);
    want.SetParam(CERT_MANAGER_CERTSCOPE_TYPE, static_cast<int32_t>(asyncContext->certificateScope));
    want.SetParam(CERT_MANAGER_CALLER_BUNDLENAME, asyncContext->labelName);
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_OPERATION_TYPE, asyncContext->opType);
    if (asyncContext->keystorePwd != nullptr && asyncContext->keystorePwd->data != nullptr) {
        /* delivered to CertPickerUIExtAbility when the caller provides the keystore
         * password; an empty string is a valid provided password */
        std::string keystorePwd(reinterpret_cast<char *>(asyncContext->keystorePwd->data),
            asyncContext->keystorePwd->size - 1);
        want.SetParam(CERT_MANAGER_KEYSTORE_PWD, keystorePwd);
        /* scrub the local copy; the context blob is scrubbed on destruction */
        if (!keystorePwd.empty()) {
            (void)memset_s(&keystorePwd[0], keystorePwd.size(), 0, keystorePwd.size());
        }
    }
    return want;
}

static uint32_t GetCertificateType(napi_env env, napi_value argv[], size_t length)
{
    if (length < PARAM_SIZE_TWO) {
        CM_LOG_E("check param size invalid");
        return CREDENTIAL_INVALID_TYPE;
    }
    uint32_t certificateType = CREDENTIAL_INVALID_TYPE;
    if (ParseUint32(env, argv[PARAM1], certificateType) == nullptr) {
        CM_LOG_E("parse cert type failed");
        return CREDENTIAL_INVALID_TYPE;
    }
    return certificateType;
}

/* Read certType from the InstallCertificateRequest object for the syscap check;
 * CREDENTIAL_INVALID_TYPE is returned when the object or the property is invalid. */
static uint32_t GetCertTypeFromRequest(napi_env env, napi_value request)
{
    napi_valuetype reqType = napi_undefined;
    if (napi_typeof(env, request, &reqType) != napi_ok || reqType != napi_object) {
        CM_LOG_E("request is not an object");
        return CREDENTIAL_INVALID_TYPE;
    }
    napi_value value = nullptr;
    uint32_t certificateType = CREDENTIAL_INVALID_TYPE;
    if (napi_get_named_property(env, request, "certType", &value) != napi_ok ||
        ParseUint32(env, value, certificateType) == nullptr) {
        CM_LOG_E("parse cert type failed");
        return CREDENTIAL_INVALID_TYPE;
    }
    return certificateType;
}

/* Dispatches the two supported call forms (legacy 4-arg and request object),
 * validates the parameters and fills asyncContext; throws the matching JS
 * error and returns false on failure. */
static bool InitInstallDialogContext(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    napi_value argv[], size_t argc, OHOS::Security::CertManager::CmMetricsReport &report)
{
    napi_env env = asyncContext->env;
    if (argc == PARAM_SIZE_FOUR) {
        asyncContext->certificateType = GetCertificateType(env, argv, argc);
    } else if (argc == PARAM_SIZE_TWO) {
        asyncContext->certificateType = GetCertTypeFromRequest(env, argv[PARAM1]);
    } else {
        CM_LOG_E("params number mismatch");
        std::string errMsg = "Parameter Error. Params number mismatch, need " + std::to_string(PARAM_SIZE_TWO)
            + " or " + std::to_string(PARAM_SIZE_FOUR) + ", given " + std::to_string(argc);
        ThrowError(env, PARAM_ERROR, errMsg, &report);
        return false;
    }

    if (asyncContext->certificateType == CA_CERT && !IsEnableCACertDialog()) {
        CM_LOG_E("check not support ca cert dialog");
        ThrowError(env, DIALOG_ERROR_NOT_SUPPORTED, "DeviceType Error. deviceType is not support.", &report);
        return false;
    }

    asyncContext->opType = static_cast<int32_t>(DIALOG_OPERATION_INSTALL);
    if (argc == PARAM_SIZE_FOUR) {
        if (CMCheckArgvAndInitContext(asyncContext, argv, argc) == nullptr) {
            CM_LOG_E("check argv vaild and init faild");
            ThrowError(env, PARAM_ERROR, "check argv vaild and init faild", &report);
            return false;
        }
        return true;
    }
    if (ParseInstallCertificateRequest(asyncContext, argv, &report) != CM_SUCCESS) {
        return false; /* the thrown JS error already carries the exact code */
    }
    return true;
}

napi_value CMNapiOpenInstallCertDialog(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert install dialog enter");
    OHOS::Security::CertManager::CmMetricsReport report("openInstallCertificateDialog",
        OHOS::Security::CertManager::CmMetricsKind::DIALOG);
    report.Start();
    if (CheckSyscapThrowError(env) != CM_SUCCESS) {
        report.Finish(OHOS::Security::CertManager::Dialog::DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED);
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));

    size_t argc = PARAM_SIZE_FIVE;
    napi_value argv[PARAM_SIZE_FIVE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    asyncContext->env = env;
    if (!InitInstallDialogContext(asyncContext, argv, argc, report)) {
        return nullptr;
    }

    if (GetCallerLabelName(asyncContext) != CM_SUCCESS) {
        CM_LOG_E("get caller labelName faild");
        ThrowError(env, DIALOG_ERROR_GENERIC, "get caller labelName faild", &report);
        return nullptr;
    }
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));

    auto reportHolder = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));
    asyncContext->metricsReport = reportHolder;
    auto uiExtCallback = std::make_shared<CmUIExtensionStringCallback>(asyncContext);
    auto want = CMGetInstallCertWant(asyncContext);
    StartUIExtensionAbility(asyncContext, want, uiExtCallback);
    CM_LOG_I("cert install dialog end");
    return result;
}
}  // namespace CMNapi

