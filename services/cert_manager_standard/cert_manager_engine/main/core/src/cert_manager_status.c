/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "cert_manager_status.h"

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cm_root_ca_store_rdb.h"
#include "cert_manager_uri.h"
#include "cert_manager_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status)
{
    if (fileName == NULL || status == NULL) {
        CM_LOG_E("Check param invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CMUri uriObj = { 0 };
    int32_t ret = CertManagerUriDecode(&uriObj, fileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }
    char confFilePath[CERT_MAX_PATH_LEN] = { 0 };
    if (sprintf_s(confFilePath, CERT_MAX_PATH_LEN, "%s/%s/%s/%s%s", CERT_BACKUP_CONFIG_ROOT_DIR, uriObj.user,
        uriObj.app, fileName, CERT_CONFIG_FILE_SUFFIX) < 0) {
        CM_LOG_E("Failed sprintf conf file path");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    (void)CertManagerFreeUri(&uriObj);

    ret = CmIsFileExist(NULL, confFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("Cert config file not exist");
        *status = CERT_STATUS_DISABLED;
    } else {
        CM_LOG_I("Cert config file exist");
        *status = CERT_STATUS_ENABLED;
    }
    return CM_SUCCESS;
}

/* one writer at a time: the tmp file name is fixed, so concurrent
 * regeneration would interleave writes (same pattern as g_authMgrLock) */
static pthread_mutex_t g_policyFileLock = PTHREAD_MUTEX_INITIALIZER;

/* serialize the disabled rows into the tmp file, push it to disk, then
 * atomically rename it over the published policy file */
static int32_t WriteAndPublishPolicyFile(const struct RootCaStoreRecord *records, uint32_t count,
    const char *tmpPath)
{
    int32_t ret = CM_SUCCESS;
    FILE *fp = fopen(tmpPath, "wb");
    if (fp == NULL) {
        CM_LOG_E("open %s failed", tmpPath);
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    do {
        for (uint32_t i = 0; i < count; i++) {
            /* line format: <seq>,<cert pk hash>; the seq is fixed to 1 */
            if (fprintf(fp, "1,%s\n", records[i].certPkHash) < 0) {
                CM_LOG_E("write policy line failed");
                ret = CMR_ERROR_WRITE_FILE_FAIL;
                break;
            }
        }
        if (ret != CM_SUCCESS) {
            break;
        }
        if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
            CM_LOG_E("flush policy tmp file failed");
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
        /* fclose destroys the stream even when it fails: close exactly once,
         * retrying it in the cleanup below would be undefined behavior */
        int closeRet = fclose(fp);
        fp = NULL;
        if (closeRet != 0) {
            CM_LOG_E("close policy tmp file failed");
            ret = CMR_ERROR_CLOSE_FILE_FAIL;
            break;
        }
        /* for-all-app consumers only read the file */
        if (chmod(tmpPath, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
            CM_LOG_E("chmod policy tmp file failed");
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
        if (rename(tmpPath, FORCE_CHECK_POLICY_FILE) != 0) {
            CM_LOG_E("rename policy tmp file failed, errno = 0x%x", errno);
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
    } while (0);

    if (fp != NULL) {
        (void)fclose(fp);
    }
    return ret;
}

int32_t CmRegenerateRevocationPolicyFile(void)
{
    pthread_mutex_lock(&g_policyFileLock);

    int32_t ret = CM_SUCCESS;
    struct RootCaStoreRecord *records = NULL;
    const char *tmpPath = FORCE_CHECK_POLICY_FILE ".tmp";
    do {
        /* the cfg mkdir is the primary source of the directory; this is the
         * fresh-boot/self-healing fallback and must match its 0701 mode */
        if (CmIsDirExist(FORCE_CHECK_POLICY_DIR) != CM_SUCCESS) {
            mode_t mode0701 = S_IRWXU | S_IXOTH;
            (void)CmUserBakupMakeDir(FORCE_CHECK_POLICY_DIR, &mode0701);
        }

        /* MAX_COUNT_CERTIFICATE_ALL (512) matches the system store list bound
         * (125 preset root CAs today) */
        records = (struct RootCaStoreRecord *)CMMalloc(MAX_COUNT_CERTIFICATE_ALL *
            sizeof(struct RootCaStoreRecord));
        if (records == NULL) {
            CM_LOG_E("malloc records failed");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }
        uint32_t count = 0;
        ret = QueryDisabledRootCa(records, MAX_COUNT_CERTIFICATE_ALL, &count);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("query disabled root ca failed, ret = %d", ret);
            break;
        }

        ret = WriteAndPublishPolicyFile(records, count, tmpPath);
    } while (0);

    if (ret != CM_SUCCESS) {
        (void)unlink(tmpPath);
    }
    CM_FREE_PTR(records);
    pthread_mutex_unlock(&g_policyFileLock);
    return ret;
}

uint32_t CmGetSystemCaAlgType(const char *certPath)
{
    if (certPath == NULL) {
        return CM_ROOT_CA_ALG_TYPE_INTERNATIONAL;
    }
    return (strcmp(certPath, SYSTEM_CA_STORE_GM) == 0) ? CM_ROOT_CA_ALG_TYPE_GM :
        CM_ROOT_CA_ALG_TYPE_INTERNATIONAL;
}

/* digest the matched certificate and upsert its root_ca_cert_store row;
 * the alg type follows the store directory the file was enumerated from */
static int32_t UpsertRootCaRecord(const struct CmBlob *certData, const struct CmBlob *certUri,
    const char *certPath, uint32_t status, char *certPkHashOut)
{
    uint32_t algType = CmGetSystemCaAlgType(certPath);
    char localPkHash[CM_ROOT_CA_PK_HASH_HEX_LEN + 1] = { 0 };
    /* the hash is always needed for the upsert; the out param only decides
     * where the digest lands */
    char *certPkHash = (certPkHashOut != NULL) ? certPkHashOut : localPkHash;
    int32_t ret = CmGetCertPubKeyHashHex(certData, certPkHash);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cert pubkey hash failed, ret = %d", ret);
        return ret;
    }
    uint32_t enable = (status == CERT_STATUS_ENANLED) ? 1 : 0;
    ret = UpsertRootCaStore((const char *)certUri->data, certUri->size, algType, enable, certPkHash);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("upsert root ca store failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmSetSystemCertStatus(const struct CmContext *context,
    const struct CmBlob *certUri, uint32_t status, char *certPkHash)
{
    if (context == NULL || certUri == NULL || certUri->data == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (status != CERT_STATUS_ENANLED && status != CERT_STATUS_DISABLED) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret;
    struct CmMutableBlob certFileList = { 0, NULL };
    do {
        /* enumerate the real system store and match the uri against it:
         * a uri that is not a preset file name cannot reach the disk */
        const struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
        ret = CmServiceGetCertList(context, &prop, CM_SYSTEM_TRUSTED_STORE, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get system cert list failed, ret = %d", ret);
            break;
        }

        uint32_t matchIndex = CmGetMatchedCertIndex(&certFileList, certUri);
        if ((matchIndex == MAX_COUNT_CERTIFICATE) || (matchIndex == certFileList.size)) {
            CM_LOG_E("certUri don't match any system cert");
            ret = CMR_ERROR_NOT_EXIST;
            break;
        }

        struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList.data;
        struct CmBlob certData = { 0, NULL };
        ret = CmStorageGetBuf((char *)cFileList[matchIndex].path.data,
            (char *)cFileList[matchIndex].fileName.data, &certData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("read cert data failed, ret = %d", ret);
            break;
        }

        ret = UpsertRootCaRecord(&certData, certUri, (char *)cFileList[matchIndex].path.data, status,
            certPkHash);
        CM_FREE_BLOB(certData);
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = CmRegenerateRevocationPolicyFile();
    } while (0);

    CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    return ret;
}
#ifdef __cplusplus
}
#endif
