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

#include "cert_manager.h"

#include <unistd.h>

#include "cert_manager_auth_mgr.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"

#include "securec.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#define MAX_FILES_IN_DIR                    1000
#define CERT_MANAGER_MD5_SIZE               32
#define CERT_MANAGER_MAX_CERT_SIZE          4096

#define MAX_NAME_PREFIX                     32
#define MAX_NAME_DIGEST_LEN                 9

#define MAX_PATH_LEN                        256
#define NAME_DIGEST_SIZE                    4

#ifdef __cplusplus
extern "C" {
#endif

static bool g_hksInitialized = false;

struct CmMathedIndexPara {
    char *path;
    uint32_t store;
    uint32_t *status;
    uint32_t *count;
    uint8_t *indexes;
};

int32_t CertManagerInitialize(void)
{
    if (!g_hksInitialized) {
        ASSERT_CM_CALL(HksInitialize());
        g_hksInitialized = true;
    }

    if (CmMakeDir(CERT_DIR) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s\n", CERT_DIR);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }

    ASSERT_FUNC(CertManagerStatusInit());

    return CMR_OK;
}

static int32_t CmFreeCaFileNames(struct CmMutableBlob *fileNames)
{
    uint32_t i;
    int32_t ret = 0;
    struct CmMutableBlob *fNames;

    if (fileNames == NULL) {
        CM_LOG_E("Failed to free memory for certificate names");
        return -1;
    }
    fNames = (struct CmMutableBlob *)fileNames->data;

    for (i = 0; i < fileNames->size; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Failed to free memory for certificate name: %u", i);
            ret = -1;
        } else {
            if (memset_s(fNames[i].data, MAX_LEN_URI, 0, fNames[i].size) != EOK) {
                return CMR_ERROR;
            }
            fNames[i].size = 0;
            CMFree(fNames[i].data);
        }
    }
    CMFree(fNames);
    fileNames->size = 0;

    return ret;
}

static int32_t GetFilePath(const struct CmContext *context, uint32_t store, char *pathPtr,
    char *suffix, uint32_t *suffixLen)
{
    int32_t ret, retVal;
    if (suffix == NULL || suffixLen == NULL) {
        CM_LOG_E("NULL pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    switch (store) {
        if (context == NULL) {
            CM_LOG_E("Null pointer failture");
            return CMR_ERROR_NULL_POINTER;
        }
        case CM_CREDENTIAL_STORE:
        case CM_USER_TRUSTED_STORE:
        case CM_PRI_CREDENTIAL_STORE:
            if (store == CM_CREDENTIAL_STORE) {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", CREDNTIAL_STORE, context->userId);
            } else if (store == CM_PRI_CREDENTIAL_STORE) {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", APP_CA_STORE, context->userId);
            } else {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", USER_CA_STORE, context->userId);
            }

            retVal = sprintf_s(suffix, MAX_SUFFIX_LEN, "%u", context->uid);
            if (ret < 0 || retVal < 0) {
                CM_LOG_E("Construct file Path failed ret:%d, retVal:%d", ret, retVal);
                return CMR_ERROR;
            }
            break;
        case CM_SYSTEM_TRUSTED_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s", SYSTEM_CA_STORE);
            if (ret < 0) {
                return CMR_ERROR;
            }
            break;

        default:
            return CMR_ERROR_NOT_SUPPORTED;
    }
    *suffixLen = (uint32_t)strlen(suffix);
    return CMR_OK;
}

static int32_t CmGetFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[MAX_PATH_LEN] = {0};
    uint32_t suffixLen = 0;
    char suffixBuf[MAX_SUFFIX_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = GetFilePath(context, store, pathPtr, suffixBuf, &suffixLen);
    if (ret != CMR_OK) {
        CM_LOG_E("Get file path faild");
        return CMR_ERROR;
    }

    /* Create folder if it does not exist */
    if (CmMakeDir(pathPtr) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create path folder:%s", pathPtr);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }

    if (pathBlob->size - 1 < strlen(pathPtr) + suffixLen) {
        CM_LOG_E("Failed to copy path");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    char *path = (char *)pathBlob->data;
    if (suffixLen == 0) {
        if (sprintf_s(path, MAX_PATH_LEN, "%s", pathPtr) < 0) {
            return CM_FAILURE;
        }
    } else {
        if (sprintf_s(path, MAX_PATH_LEN, "%s/%s", pathPtr, suffixBuf) < 0) {
            return CM_FAILURE;
        }
    }

    pathBlob->size = strlen(path) + 1;
    if (CmMakeDir(path) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s", path);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    return CMR_OK;
}

static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != CMR_OK) {
        CM_LOG_E("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != CMR_OK) {
        CM_LOG_E("HksAddParams failed");
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != CMR_OK) {
        CM_LOG_E("HksBuildParamSet failed");
        return ret;
    }

    return ret;
}

static int32_t NameHash(struct HksBlob *subjectName, struct CmMutableBlob *nameDigest)
{
    if ((nameDigest == NULL) || (nameDigest->data == NULL) || (nameDigest->size < NAME_DIGEST_SIZE)) {
        CM_LOG_E("Invalid parameter");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CMR_OK;

    struct HksParam hashParam = {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_MD5
    };
    struct HksParamSet *hashParamSet;
    ret = InitParamSet(&hashParamSet, &hashParam, sizeof(hashParam) / sizeof(struct HksParam));
    if (ret != CMR_OK) {
        ret = CMR_ERROR;
        goto cleanup;
    }

    uint8_t hashBuff[CERT_MANAGER_MD5_SIZE];
    struct HksBlob hash = { sizeof(hashBuff), hashBuff};
    struct HksBlob tmp = HKS_BLOB(subjectName);
    ret = HksHash(hashParamSet, &tmp, &hash);
    if (ret != CMR_OK) {
        ret = CMR_ERROR;
        goto cleanup;
    }
    nameDigest->size = NAME_DIGEST_SIZE;
    if (sprintf_s((char*)nameDigest->data, MAX_NAME_PREFIX, "%02x%02x%02x%02x",
        hashBuff[3], hashBuff[2], hashBuff[1], hashBuff[0]) < 0) { /* 2 3 is array index */
            ret = CMR_ERROR;
            goto cleanup;
        }

cleanup:
    if (hashParamSet != NULL) {
        HksFreeParamSet(&hashParamSet);
    }
    return ret;
}

int32_t CertManagerFindCertFileNameByUri(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmMutableBlob *path)
{
    ASSERT_ARGS(context && certUri && certUri->data);
    int32_t ret = CMR_ERROR_NOT_FOUND;
    struct CmMutableBlob *fNames = NULL;
    struct CmMutableBlob fileNames = {0, NULL};
    struct CmBlob uri[MAX_COUNT_CERTIFICATE];

    if (CmGetFilePath(context, store, path) != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %x\n", store);
        return CMR_ERROR;
    }

    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(uri, len, 0, len);
    if (CertManagerGetFilenames(&fileNames, (char*)path->data, uri) < 0) {
        CM_LOG_E("Failed obtain filenames from path: %s", (char *)path->data);
        ret = CMR_ERROR_STORAGE;
        goto cleanup;
    }

    fNames = (struct CmMutableBlob *)fileNames.data;

    for (uint32_t i = 0; i < fileNames.size; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Corrupted file name at index: %u", i);
            ret = CMR_ERROR_STORAGE;
            goto cleanup;
        }
        /* Check if url is matching with the cert filename */
        if ((certUri->size <= fNames[i].size) && (memcmp(certUri->data, fNames[i].data, certUri->size) == 0)) {
            ret = CMR_OK;
            break;
        }
    }

cleanup:
    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);
    if (fileNames.data != NULL) {
        (void)CmFreeCaFileNames(&fileNames);
    }

    return ret;
}

int32_t CmRemoveAppCert(const struct CmContext *context, const struct CmBlob *keyUri,
    const uint32_t store)
{
    ASSERT_ARGS(context && keyUri && keyUri->data && keyUri->size);
    int32_t ret;
    if (store == CM_CREDENTIAL_STORE) {
        ret = CmAuthDeleteAuthInfo(context, keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth info failed when remove app certificate."); /* ignore ret code, only record log */
        }
    }

    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob path = { sizeof(pathBuf), (uint8_t*) pathBuf };

    ret = CmGetFilePath(context, store, &path);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %u", store);
        return ret;
    }

    ret = CertManagerFileRemove(pathBuf, (char *)keyUri->data);
    if (ret != CMR_OK) {
        CM_LOG_E("CertManagerFileRemove failed ret: %d", ret);
        return ret;
    }
    ret = CmKeyOpDeleteKey(keyUri);
    if (ret != CM_SUCCESS) { /* ignore the return of deleteKey */
        CM_LOG_I("CertManagerKeyRemove failed, ret: %d", ret);
    }

    return CMR_OK;
}

static void ClearAuthInfo(const struct CmContext *context, const struct CmBlob *keyUri, const uint32_t store)
{
    if (store != CM_CREDENTIAL_STORE) {
        return;
    }

    int32_t ret = CmAuthDeleteAuthInfo(context, keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("delete auth info failed."); /* ignore ret code, only record log */
    }
}

static int32_t CmAppCertGetFilePath(const struct CmContext *context, const uint32_t store, struct CmBlob *path)
{
    int32_t ret = CM_FAILURE;

    switch (store) {
        case CM_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u/%u", CREDNTIAL_STORE, context->userId, context->uid);
            break;
        case CM_PRI_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u", APP_CA_STORE, context->userId);
            break;
        default:
            break;
    }
    if (ret < 0) {
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize)
{
    if (fileNames == NULL) {
        CM_LOG_E("CmFreeFileNames fileNames is null");
        return;
    }

    for (uint32_t i = 0; i < fileSize; i++) {
        if (fileNames[i].data != NULL) {
            CMFree(fileNames[i].data);
            fileNames[i].size = 0;
        }
    }
}

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob)
{
    uint32_t i;
    if ((filePath == NULL) || (uriBlob == NULL) || (uriBlob->data == NULL)) {
        CM_LOG_E("CmGetUri param is null");
        return CM_FAILURE;
    }

    uint32_t filePathLen = strlen(filePath) + 1; /* include '\0' at end */
    for (i = filePathLen - 1; i >= 0; i--) {
        if (filePath[i] == '/') {
            break;
        }
    }

    uint32_t uriLen = filePathLen - i - 1;
    if ((uriLen == 0) || (memcpy_s(uriBlob->data, MAX_LEN_URI, &filePath[i + 1], uriLen) != EOK)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uriBlob->size = uriLen;

    return CM_SUCCESS;
}

static int32_t CmRemoveSpecifiedAppCert(const struct CmContext *context, const uint32_t store)
{
    uint32_t fileCount = 0;
    int32_t retCode, ret = CM_SUCCESS;
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    char uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };
    struct CmBlob uriBlob = { sizeof(uriBuf), (uint8_t*)uriBuf };
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    do {
        if (CmAppCertGetFilePath(context, store, &path) != CM_SUCCESS) {
            ret = CM_FAILURE;
            CM_LOG_E("Get file path for store:%u faild", store);
            break;
        }

        if (CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, MAX_COUNT_CERTIFICATE, &fileCount) != CM_SUCCESS) {
            ret = CM_FAILURE;
            CM_LOG_E("Get file count and names from path faild: %s", pathBuf);
            break;
        }

        CM_LOG_I("CmRemoveSpecifiedAppCert fileCount:%u", fileCount);

        for (uint32_t i = 0; i < fileCount; i++) {
            if (CertManagerFileRemove(NULL, (char *)fileNames[i].data) != CM_SUCCESS) {
                CM_LOG_E("App cert %u remove faild", i);
                continue;
            }

            (void)memset_s(uriBuf, MAX_LEN_URI, 0, MAX_LEN_URI);
            if (CmGetUri((char *)fileNames[i].data, &uriBlob) != CM_SUCCESS) {
                CM_LOG_E("Get uri failed");
                continue;
            }

            CM_LOG_I("CmRemoveSpecifiedAppCert i:%d, uri:%s", i, (char *)uriBlob.data);

            retCode = CmKeyOpDeleteKey(&uriBlob);
            if (retCode != CM_SUCCESS) { /* ignore the return of deleteKey */
                CM_LOG_I("App key %u remove failed ret: %d", i, retCode);
            }
            ClearAuthInfo(context, &uriBlob, store);
        }
    } while (0);

    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
    return ret;
}

int32_t CmRemoveAllAppCert(const struct CmContext *context)
{
    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    /* Only public and private credential removed can be returned */
    /* remove pubic credential app cert */
    int32_t ret = CmRemoveSpecifiedAppCert(context, CM_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove pubic credential app cert faild");
    }

    /* remove private credential app cert */
    ret = CmRemoveSpecifiedAppCert(context, CM_PRI_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove private credential app cert faild");
    }

    return ret;
}

void CmFreeFileNameUri(struct CmBlob *uri, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        CM_FREE_BLOB(uri[i]);
    }
}

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };

    int32_t ret = CmAppCertGetFilePath(context, store, &path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path for store:%u faild", store);
        return CM_FAILURE;
    }

    CM_LOG_I("Get app cert list path:%s", pathBuf);

    if (store == CM_CREDENTIAL_STORE) {
        ret = CmUidLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    } else {
        ret = CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names from path faild ret:%d, path:%s", ret, pathBuf);
        return ret;
    }

    CM_LOG_I("Get app cert list fileCount:%u", *fileCount);

    return CM_SUCCESS;
}

static int32_t CherkCertCountBeyondMax(const char *path, const char *fileName)
{
    int32_t ret = CM_FAILURE;

    do {
        int32_t tempCount = GetCertCount(path);
        if (tempCount < MAX_COUNT_CERTIFICATE) {
            ret = CM_SUCCESS;
            break;
        }

        char fullFileName[CM_MAX_FILE_NAME_LEN] = {0};
        if (snprintf_s(fullFileName, CM_MAX_FILE_NAME_LEN, CM_MAX_FILE_NAME_LEN - 1, "%s/%s", path, fileName) < 0) {
            CM_LOG_E("mkdir full name failed");
            ret = CM_FAILURE;
            break;
        }

        if (access(fullFileName, F_OK) == 0) {
            ret = CM_SUCCESS;
            break;
        }
    } while (0);
    return ret;
}

static int32_t ConstructCertUri(const struct CmContext *context, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    struct CmBlob commonUri = { 0, NULL };
    int32_t ret;
    do {
        ret = CmConstructCommonUri(context, CM_URI_TYPE_CERTIFICATE, certAlias, &commonUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct cert uri get common uri failed");
            break;
        }

        if (certUri->size < commonUri.size) {
            CM_LOG_E("out cert uri size[%u] too small", certUri->size);
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        if (memcpy_s(certUri->data, certUri->size, commonUri.data, commonUri.size) != EOK) {
            CM_LOG_E("copy cert uri failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }

        certUri->size = commonUri.size;
    } while (0);

    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    if (certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("alias size is too large");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret;
    do {
        ret = ConstructCertUri(context, certAlias, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert uri failed");
            break;
        }

        if (certUri->size > MAX_LEN_URI) {
            CM_LOG_E("uri size is too large");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }

        ret = CherkCertCountBeyondMax((char*)pathBlob->data, (char *)certUri->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("cert count beyond maxcount, can't install");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }

        if (CmFileWrite((char*)pathBlob->data, (char *)certUri->data, 0, userCert->data, userCert->size) != CMR_OK) {
            CM_LOG_E("Failed to write certificate: %s in to %s", certAlias->data, pathBlob->data);
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
    } while (0);
    return ret;
}

int32_t NameHashFromUri(const char *fName, struct CmMutableBlob *nameDigest)
{
    uint32_t buffSize = (uint32_t)strlen(fName) + 1;
    struct HksBlob certName = { buffSize, (uint8_t *)fName };

    return NameHash(&certName, nameDigest);
}

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri)
{
    return CertManagerFileRemove((char *)pathBlob->data, (char *)certUri->data);
}

static int32_t RemoveAllUserCert(const struct CmContext *context, uint32_t store, const char* path)
{
    ASSERT_ARGS(path);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob fileNames = { 0, NULL };
    struct CmMutableBlob *fNames = NULL;
    struct CmBlob uri[MAX_COUNT_CERTIFICATE];
    struct CmMutableBlob pathBlob = { strlen(path) + 1, (uint8_t *)path }; /* include '\0' at end. */

    uint32_t uriArraryLen = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(uri, uriArraryLen, 0, uriArraryLen);
    if (CertManagerGetFilenames(&fileNames, path, uri) < 0) {
        CM_LOG_E("Failed obtain filenames from path: %s", path);
        return CM_FAILURE;
    }

    fNames = (struct CmMutableBlob *)fileNames.data;
    for (uint32_t i = 0; i < fileNames.size; i++) {
        ret = CertManagerFileRemove(path, (char *)fNames[i].data);
        if (ret != CMR_OK) {
            CM_LOG_E("User Cert %d remove failed, ret: %d", i, ret);
            continue;
        }
        ret = CmSetStatusEnable(context, &pathBlob, &uri[i], store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Update StatusFile %d fail, ret = %d", i, ret);
            continue;
        }
    }
    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);
    (void)CmFreeCaFileNames(&fileNames);
    return ret;
}

static int32_t RemoveAllUidDir(const char* path)
{
    return CM_ERROR(CmDirRemove(path));
}

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *certPathList)
{
    ASSERT_ARGS(certPathList && certPathList->data && certPathList->size);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob *path = (struct CmMutableBlob *)certPathList->data;

    for (uint32_t i = 0; i < certPathList->size; i++) {
        ret = RemoveAllUserCert(context, store, (char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed remove usercert of path %s", (char *)path[i].data);
            continue;
        }
        ret = RemoveAllUidDir((char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Remove UidPath %s fail, ret = %d", (char *)path[i].data, ret);
            continue;
        }
    }
    return ret;
}

#ifdef __cplusplus
}
#endif