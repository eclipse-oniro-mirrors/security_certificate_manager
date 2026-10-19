/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cm_ipc_service_cert_pack.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"
#include "cm_ipc_service_serialization.h"
#include "cm_x509.h"

#include "cert_manager_check.h"
#include "cert_manager_query.h"

#define CM_CERT_INFO_FIELD_NUM 6

static int32_t CmGetCertListPack(const struct CertBlob *certBlob, uint32_t *status, uint32_t certCount,
    struct CmBlob *certificateList)
{
    uint32_t offset = 0;
    if (certCount > MAX_COUNT_CERTIFICATE_ALL) {
        CM_LOG_E("cert count is too large");
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * certCount;
    if (certificateList->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    certificateList->size = buffSize;

    int32_t ret = CopyUint32ToBuffer(certCount, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy cert count failed");
        return ret;
    }
    uint32_t *unpackCertCount = (uint32_t *)certificateList->data;
    for (uint32_t i = 0; i < certCount; i++) {
        if (certBlob->uri[i].size == 0) {
            (*unpackCertCount)--;
            continue;
        }
        ret = CopyBlobToBuffer(&(certBlob->subjectName[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate subject failed");
            return ret;
        }
        ret = CopyUint32ToBuffer(status[i], certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate status failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->uri[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate uri failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->certAlias[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate certAlias failed");
            return ret;
        }
    }

    /* Avoid returning too large a size */
    certificateList->size = offset;
    return ret;
}

int32_t CmServiceGetCertListPack(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CmBlob *certificateList)
{
    if (context == NULL || certFileList == NULL || CmCheckBlob(certificateList) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint32_t status[MAX_COUNT_CERTIFICATE_ALL] = {0};
    struct CertBlob certBlob;
    (void)memset_s(&certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    int32_t ret = CmGetCertListInfo(context, store, certFileList, &certBlob, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListInfo fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    ret = CmGetCertListPack(&certBlob, status, certFileList->size, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListPack fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    CmFreeCertBlob(&certBlob);
    return ret;
}

static void FreeX509FieldBlobs(struct CmBlob *fields)
{
    for (uint32_t i = 0; i < CM_CERT_INFO_FIELD_NUM; ++i) {
        CM_FREE_PTR(fields[i].data);
        fields[i].size = 0;
    }
}

/*
 * Parse the certificate on the service side and append the six display
 * fields (subjectName, issuerName, serial, notBefore, notAfter,
 * fingerprintSha256) after certAlias, so the client no longer needs
 * OpenSSL to fill struct CertInfo. Field order matches the client-side
 * unpack table in CmCertificateInfoUnpackFromService.
 */
static int32_t CopyX509InfoToBuffer(const struct CmBlob *certificateData, struct CmBlob *certificateInfo,
    uint32_t *offset)
{
    static const uint32_t fieldMaxLen[CM_CERT_INFO_FIELD_NUM] = {
        MAX_LEN_SUBJECT_NAME, MAX_LEN_ISSUER_NAME, MAX_LEN_SERIAL,
        MAX_LEN_NOT_BEFORE, MAX_LEN_NOT_AFTER, MAX_LEN_FINGER_PRINT_SHA256,
    };

    X509 *cert = InitCertContext(certificateData->data, certificateData->size);
    if (cert == NULL) {
        CM_LOG_E("Parse X509 cert fail");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    struct CmBlob fields[CM_CERT_INFO_FIELD_NUM] = {{0, NULL}};
    for (uint32_t i = 0; i < CM_CERT_INFO_FIELD_NUM; ++i) {
        fields[i].size = fieldMaxLen[i];
        fields[i].data = (uint8_t *)CmMalloc(fieldMaxLen[i]);
        if (fields[i].data == NULL) {
            FreeX509FieldBlobs(fields);
            FreeCertContext(cert);
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(fields[i].data, fieldMaxLen[i], 0, fieldMaxLen[i]);
    }

    int32_t fieldLen[CM_CERT_INFO_FIELD_NUM];
    fieldLen[0] = GetX509SubjectNameLongFormat(cert, (char *)fields[0].data, fieldMaxLen[0]);
    fieldLen[1] = GetX509IssueNameLongFormat(cert, (char *)fields[1].data, fieldMaxLen[1]);
    fieldLen[2] = GetX509SerialNumber(cert, (char *)fields[2].data, fieldMaxLen[2]);
    fieldLen[3] = GetX509NotBefore(cert, (char *)fields[3].data, fieldMaxLen[3]);
    fieldLen[4] = GetX509NotAfter(cert, (char *)fields[4].data, fieldMaxLen[4]);
    fieldLen[5] = GetX509Fingerprint(cert, (char *)fields[5].data, fieldMaxLen[5]);

    int32_t ret = CM_SUCCESS;
    for (uint32_t i = 0; i < CM_CERT_INFO_FIELD_NUM; ++i) {
        if (fieldLen[i] <= 0) {
            CM_LOG_E("get cert info field %u failed, ret = %d", i, fieldLen[i]);
            ret = CM_FAILURE;
            break;
        }
        fields[i].size = (uint32_t)fieldLen[i] + 1; /* wire format carries the NUL terminator */
    }

    for (uint32_t i = 0; ret == CM_SUCCESS && i < CM_CERT_INFO_FIELD_NUM; ++i) {
        ret = CopyBlobToBuffer(&fields[i], certificateInfo, offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("copy cert info field %u failed", i);
        }
    }

    FreeX509FieldBlobs(fields);
    FreeCertContext(cert);
    return ret;
}

int32_t CmServiceGetCertInfoPack(const uint32_t store, const struct CmBlob *certificateData,
    uint32_t status, const struct CmBlob *certUri, struct CmBlob *certificateInfo)
{
    if (certificateData != NULL && certificateData->size == 0) {
        CM_LOG_D("cert file is not exist");
        return CM_SUCCESS;
    }
    if (CmCheckBlob(certificateData) != CM_SUCCESS || CmCheckBlob(certUri) != CM_SUCCESS ||
        CmCheckBlob(certificateInfo) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* must mirror GetCertInfoInitOutData on the client side */
    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t) +
        MAX_LEN_CERT_ALIAS + sizeof(uint32_t) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_SUBJECT_NAME) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_ISSUER_NAME) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_SERIAL) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_NOT_BEFORE) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_NOT_AFTER) +
        sizeof(uint32_t) + ALIGN_SIZE(MAX_LEN_FINGER_PRINT_SHA256);
    if (certificateInfo->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    certificateInfo->size = buffSize;

    uint32_t offset = 0;
    int32_t ret = CopyBlobToBuffer(certificateData, certificateInfo, &offset); /* certData */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(status, certificateInfo, &offset); /* status */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert status failed");
        return ret;
    }

    struct CmBlob certAlias;
    certAlias.size = MAX_LEN_CERT_ALIAS;
    certAlias.data = (uint8_t *)CmMalloc(MAX_LEN_CERT_ALIAS);
    if (certAlias.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certAlias.data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);

    ret = CmGetCertAlias(store, (char *)certUri->data, certificateData, &(certAlias));
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert certAlias");
        CM_FREE_BLOB(certAlias);
        return ret;
    }

    ret = CopyBlobToBuffer(&certAlias, certificateInfo, &offset); /* certAlias */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        CM_FREE_BLOB(certAlias);
        return ret;
    }
    CM_FREE_BLOB(certAlias);

    ret = CopyX509InfoToBuffer(certificateData, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert x509 info failed");
        return ret;
    }
    return ret;
}