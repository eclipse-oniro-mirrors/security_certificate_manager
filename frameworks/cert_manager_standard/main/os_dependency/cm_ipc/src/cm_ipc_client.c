/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_client_ipc.h"
#include "cm_ipc_check.h"

#include "cm_ipc_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_x509.h"
#include "cm_param.h"

#include "cm_request.h"

static int32_t CertificateInfoInitBlob(struct CmBlob *inBlob, struct CmBlob *outBlob,
    const struct CmContext *cmContext, struct CertInfo *CertificateInfo)
{
    uint32_t buffSize;
    int32_t ret = CM_SUCCESS;
    buffSize = sizeof(cmContext->userId) + sizeof(cmContext->uid) +
        sizeof(uint32_t) + sizeof(cmContext->packageName) + sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t);
    inBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (inBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    inBlob->size = buffSize;

    buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t);
    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    outBlob->size = buffSize;

    CertificateInfo->certInfo.data = (uint8_t *)CmMalloc(MAX_LEN_CERTIFICATE);
    if (CertificateInfo->certInfo.data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    CertificateInfo->certInfo.size = MAX_LEN_CERTIFICATE;
    return ret;
err:
    CM_FREE_BLOB(*inBlob);
    CM_FREE_BLOB(*outBlob);

    return ret;
}

static int32_t CertificateListInitBlob(struct CmBlob *inBlob, struct CmBlob *outBlob, const struct CmContext *cmContext,
    const uint32_t store, struct CertList *certificateList)
{
    uint32_t buffSize;
    int32_t ret = CM_SUCCESS;

    buffSize = sizeof(cmContext->userId) + sizeof(cmContext->uid) +
        sizeof(uint32_t) + sizeof(cmContext->packageName) + sizeof(uint32_t);
    inBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (inBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    inBlob->size = buffSize;

    buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) + sizeof(uint32_t) +
        MAX_LEN_URI + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    outBlob->size = buffSize;

    buffSize = (MAX_COUNT_CERTIFICATE * sizeof(struct CertAbstract));
    certificateList->certAbstract = (struct CertAbstract *)CmMalloc(buffSize);
    if (certificateList->certAbstract == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    certificateList->certsCount = MAX_COUNT_CERTIFICATE;

    if (memset_s(certificateList->certAbstract, buffSize, 0, buffSize) != EOK) {
        CM_LOG_E("init certAbstract failed");
        ret = CMR_ERROR_INVALID_OPERATION;
        goto err;
    }
    return ret;
err:
    CM_FREE_BLOB(*inBlob);
    CM_FREE_BLOB(*outBlob);
    CmFree(certificateList->certAbstract);

    return ret;
}

static int32_t GetCertificateList(enum CmMessage type, const struct CmContext *cmContext, const uint32_t store,
    struct CertList *certificateList)
{
    struct CmBlob inBlob = {0, NULL};
    struct CmBlob outBlob = {0, NULL};
    const struct CmContext context = {0};
    int32_t ret = CheckCertificateListPara(&inBlob, &outBlob, cmContext, store, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CheckCertificateListPara fail");
        return ret;
    }

    ret = CertificateListInitBlob(&inBlob, &outBlob, cmContext, store, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateListInitBlob fail");
        return ret;
    }

    do {
        ret = CmCertificateListPack(&inBlob, cmContext, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificateListPack fail");
            break;
        }
        ret = SendRequest(type, &inBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertificateList request fail");
            break;
        }

        ret = CmCertificateListUnpackFromService(&outBlob, false, &context, certificateList);
    } while (0);
    CM_FREE_BLOB(inBlob);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertList(const struct CmContext *cmContext, const uint32_t store,
    struct CertList *certificateList)
{
    return GetCertificateList(CM_MSG_GET_CERTIFICATE_LIST, cmContext, store, certificateList);
}

static int32_t GetCertificateInfo(enum CmMessage type, const struct CmContext *cmContext,
    const struct CmBlob *certUri, const uint32_t store, struct CertInfo *certificateInfo)
{
    struct CmBlob inBlob = {0, NULL};
    struct CmBlob outBlob = {0, NULL};
    const struct CmContext context = {0};

    int32_t ret = CheckCertificateInfoPara(&inBlob, &outBlob, cmContext, store, certificateInfo);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CheckCertificateInfoPara fail");
        return ret;
    }

    ret = CertificateInfoInitBlob(&inBlob, &outBlob, cmContext, certificateInfo);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CheckCertificateInfoPara fail");
        return ret;
    }

    do {
        ret = CmCertificateInfoPack(&inBlob, cmContext, certUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificateInfoPack fail");
            break;
        }

        ret = SendRequest(type, &inBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertificateInfo request fail");
            break;
        }

        ret = CmCertificateInfoUnpackFromService(&outBlob, &context, certificateInfo, certUri);
    } while (0);

    CM_FREE_BLOB(inBlob);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertInfo(const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store, struct CertInfo *certificateInfo)
{
    return GetCertificateInfo(CM_MSG_GET_CERTIFICATE_INFO, cmContext, certUri, store, certificateInfo);
}

static int32_t CertificateStatusInitBlob(struct CmBlob *inBlob, const struct CmContext *cmContext,
    const struct CmBlob *certUri, const uint32_t store, const uint32_t status)
{
    int32_t ret = CM_SUCCESS;
    uint32_t buffSize = sizeof(cmContext->userId) + sizeof(cmContext->uid) +
                        sizeof(uint32_t) + sizeof(cmContext->packageName) + sizeof(certUri->size) +
                        ALIGN_SIZE(certUri->size) + sizeof(store) + sizeof(status);
    inBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (inBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        goto err;
    }
    inBlob->size = buffSize;
    return ret;
err:
    CM_FREE_BLOB(*inBlob);
    return ret;
}

static int32_t SetCertificateStatus(enum CmMessage type, const struct CmContext *cmContext,
    const struct CmBlob *certUri, const uint32_t store, const uint32_t status)
{
    struct CmBlob inBlob = {0, NULL};
    int32_t ret = CM_SUCCESS;

    if ((cmContext == NULL) || certUri == NULL) {
        CM_LOG_E("SetCertificateStatus  invalid  agrument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = CertificateStatusInitBlob(&inBlob, cmContext, certUri, store, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateStatusInitBlob fail");
        return ret;
    }

    do {
        ret = CmCertificateStatusPack(&inBlob, cmContext, certUri, store, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificateStatusPack fail");
            break;
        }
        ret = SendRequest(type, &inBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificateStatusPack request fail");
            break;
        }
    } while (0);
    CM_FREE_BLOB(inBlob);
    return ret;
}

int32_t CmClientSetCertStatus(const struct CmContext *cmContext, const struct CmBlob *certUri, const uint32_t store,
                              const uint32_t status)
{
    return SetCertificateStatus(CM_MSG_SET_CERTIFICATE_STATUS, cmContext, certUri, store, status);
}

static int32_t CmInstallAppCertUnpackFromService(const struct CmBlob *outData, struct CmBlob *keyUri)
{
    uint32_t offset = 0;
    struct CmBlob blob = { 0, NULL };

    if ((outData == NULL) || (keyUri == NULL) || (outData->data == NULL) ||
        (keyUri->data == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmGetBlobFromBuffer(&blob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get keyUri failed");
        return ret;
    }

    if ((blob.size > keyUri->size) || memcpy_s(keyUri->data, keyUri->size, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy keyUri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

static int32_t InstallAppCertInitBlob(struct CmBlob *outBlob)
{
    int32_t ret = CM_SUCCESS;

    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_URI;
    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
    }
    outBlob->size = buffSize;

    return ret;
}

static int32_t InstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *appCert },
        { .tag = CM_TAG_PARAM1_BUFFER,
          .blob = *appCertPwd },
        { .tag = CM_TAG_PARAM2_BUFFER,
          .blob = *certAlias },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };
    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = InstallAppCertInitBlob(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("InstallAppCertInitBlob fail");
            break;
        }

        ret = SendRequest(CM_MSG_INSTALL_APP_CERTIFICATE, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParamSet send fail");
            break;
        }

        ret = CmInstallAppCertUnpackFromService(&outBlob, keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertListUnpackFromService fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    return InstallAppCert(appCert, appCertPwd, certAlias, store, keyUri);
}

static int32_t UninstallAppCert(enum CmMessage type, const struct CmBlob *keyUri, const uint32_t store)
{
    int32_t ret;
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *keyUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };

    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmParamSet send fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    return UninstallAppCert(CM_MSG_UNINSTALL_APP_CERTIFICATE, keyUri, store);
}

int32_t CmClientUninstallAllAppCert(enum CmMessage type)
{
    int32_t ret;
    char tempBuff[] = "uninstall all app cert";
    struct CmBlob parcelBlob = {
        .size = sizeof(tempBuff),
        .data = (uint8_t *)tempBuff
    };

    ret = SendRequest(type, &parcelBlob, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("UninstallAllAppCert request fail");
    }

    return ret;
}

static int32_t GetAppCertListInitBlob(struct CmBlob *outBlob)
{
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t CmAppCertListUnpackFromService(const struct CmBlob *outData,
    struct CredentialList *certificateList)
{
    uint32_t offset = 0;
    struct CmBlob blob = { 0, NULL };
    if ((outData == NULL) || (certificateList == NULL) ||
        (outData->data == NULL) || (certificateList->credentialAbstract == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = GetUint32FromBuffer(&(certificateList->credentialCount), outData, &offset);
    if (ret != CM_SUCCESS || certificateList->credentialCount == 0) {
        CM_LOG_E("certificateList->credentialCount ret:%d, cont:%d", ret, certificateList->credentialCount);
        return ret;
    }
    for (uint32_t i = 0; i < certificateList->credentialCount; i++) {
        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get type blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].type, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy type failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get keyUri blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].keyUri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy keyUri failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get alias blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].alias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy alias failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    return CM_SUCCESS;
}

static int32_t GetAppCertList(enum CmMessage type, const uint32_t store, struct CredentialList *certificateList)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = store },
    };

    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = GetAppCertListInitBlob(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertListInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList request fail");
            break;
        }

        ret = CmAppCertListUnpackFromService(&outBlob, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertListUnpackFromService fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetAppCertList(const uint32_t store, struct CredentialList *certificateList)
{
    return GetAppCertList(CM_MSG_GET_APP_CERTIFICATE_LIST, store, certificateList);
}

static int32_t GetAppCertInitBlob(struct CmBlob *outBlob)
{
    uint32_t buffSize = sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME +
        sizeof(uint32_t) + MAX_LEN_CERT_ALIAS + sizeof(uint32_t) + MAX_LEN_URI +
        sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_CERTIFICATE_CHAIN;

    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t CmGetAppCertFromBuffer(struct Credential *certificateInfo,
    const struct CmBlob *outData, uint32_t *offset)
{
    struct CmBlob blob;
    int32_t ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get type blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->type, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy type failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get keyUri blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->keyUri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy keyUri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get alias blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->alias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy alias failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return ret;
}

static int32_t CmAppCertInfoUnpackFromService(const struct CmBlob *outData, struct Credential *certificateInfo)
{
    uint32_t offset = 0;
    struct CmBlob blob = { 0, NULL };

    if ((outData == NULL) || (certificateInfo == NULL) || (outData->data == NULL) ||
        (certificateInfo->credData.data == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = GetUint32FromBuffer(&certificateInfo->isExist, outData, &offset);
    if (ret != CM_SUCCESS || certificateInfo->isExist == 0) {
        CM_LOG_E("Get certificateInfo->isExist failed ret:%s, is exist:%d", ret, certificateInfo->isExist);
        return ret;
    }

    ret = CmGetAppCertFromBuffer(certificateInfo, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get AppCert failed");
        return ret;
    }

    ret = GetUint32FromBuffer(&certificateInfo->certNum, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->certNum failed");
        return ret;
    }

    ret = GetUint32FromBuffer(&certificateInfo->keyNum, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->keyNum failed");
        return ret;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->credData failed");
        return ret;
    }

    if ((blob.size > certificateInfo->credData.size) || memcpy_s(certificateInfo->credData.data,
        certificateInfo->credData.size, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy credData failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

static int32_t GetAppCert(enum CmMessage type, const struct CmBlob *certUri, const uint32_t store,
    struct Credential *certificate)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };
    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCert CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = GetAppCertInitBlob(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCert request fail");
            break;
        }

        ret = CmAppCertInfoUnpackFromService(&outBlob, certificate);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertInfoUnpackFromService fail");
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct Credential *certificate)
{
    return GetAppCert(CM_MSG_GET_APP_CERTIFICATE, keyUri, store, certificate);
}

static int32_t ClientSerializationAndSend(enum CmMessage message, struct CmParam *params,
    uint32_t paramCount, struct CmBlob *outBlob)
{
    struct CmParamSet *sendParamSet = NULL;
    int32_t ret = CmParamsToParamSet(params, paramCount, &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("pack params failed, ret = %d", ret);
        return ret;
    }

    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, (uint8_t *)sendParamSet };
    ret = SendRequest(message, &parcelBlob, outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("send request failed, ret = %d", ret);
    }
    CmFreeParamSet(&sendParamSet);

    return ret;
}

static int32_t FormatAppUidList(const struct CmBlob *replyBlob, struct CmAppUidList *appUidList)
{
    if (replyBlob->size < sizeof(uint32_t)) { /* app uid count: 4 bytes */
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* get app uid count */
    uint32_t count = 0;
    (void)memcpy_s(&count, sizeof(uint32_t), replyBlob->data, sizeof(uint32_t));
    uint32_t offset = sizeof(uint32_t);

    /* check reply total len */
    if ((count > MAX_OUT_BLOB_SIZE) || (replyBlob->size < (sizeof(uint32_t) + count * sizeof(uint32_t)))) {
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount < count) {
        CM_LOG_E("input app list count[%u] too small", appUidList->appUidCount);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (count != 0) {
        if (appUidList->appUid == NULL) {
            CM_LOG_E("input appUid NULL");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        uint32_t uidListSize = count * sizeof(uint32_t);
        (void)memcpy_s(appUidList->appUid, uidListSize, replyBlob->data + offset, uidListSize);
    }
    appUidList->appUidCount = count;
    return CM_SUCCESS;
}

int32_t CmClientGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri or authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GRANT_APP_CERT, params, CM_ARRAY_SIZE(params), authUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("grant app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount > MAX_OUT_BLOB_SIZE) { /* ensure not out of bounds */
        CM_LOG_E("invalid app uid list count[%u]", appUidList->appUidCount);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t outLen = sizeof(uint32_t) + appUidList->appUidCount * sizeof(uint32_t);
    uint8_t *outData = CmMalloc(outLen);
    if (outData == NULL) {
        CM_LOG_E("malloc out data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(outData, outLen, 0, outLen);
    struct CmBlob outBlob = { outLen, outData };

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GET_AUTHED_LIST, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get authed list serialization and send failed, ret = %d", ret);
        CmFree(outData);
        return ret;
    }

    ret = FormatAppUidList(&outBlob, appUidList);
    CmFree(outData);
    return ret;
}

int32_t CmClientIsAuthorizedApp(const struct CmBlob *authUri)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_CHECK_IS_AUTHED_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check is authed serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_REMOVE_GRANT_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove granted app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob signSpec = { sizeof(struct CmSignatureSpec), (uint8_t *)spec };
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = signSpec },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_INIT, params, CM_ARRAY_SIZE(params), handle);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS || CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_UPDATE, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* finish: inData and outData can be {0, NULL} */
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_FINISH, params, CM_ARRAY_SIZE(params), outData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("finish serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientAbort(const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_ABORT, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("abort serialization and send failed, ret = %d", ret);
    }
    return ret;
}

