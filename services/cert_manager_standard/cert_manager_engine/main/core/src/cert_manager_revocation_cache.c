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

#include "cert_manager_revocation_cache.h"
#include "cm_error_code.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "securec.h"

#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cert_manager_storage.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_revocation_cache.h"
#include "cm_revocation_cache_rdb.h"

static pthread_mutex_t g_revocationCacheLock = PTHREAD_MUTEX_INITIALIZER;

static int32_t EnsureDirWithMode(const char *dir, const mode_t *mode)
{
    int32_t ret = CmUserBakupMakeDir(dir, mode);
    if (ret == CMR_ERROR_ALREADY_EXISTS) {
        return CMR_OK;
    }
    return ret;
}

static bool IsFileNameCache(const char *name)
{
    if (name == NULL) {
        return false;
    }
    size_t len = strlen(name);
    if (len < 6) {
        return false;
    }
    if (strcmp(name + len - 6, ".cache") == 0) {
        return true;
    }
    return false;
}

static bool IsFileNameTmp(const char *name)
{
    if (name == NULL) {
        return false;
    }
    size_t len = strlen(name);
    if (len < 4) {
        return false;
    }
    if (strcmp(name + len - 4, ".tmp") == 0) {
        return true;
    }
    return false;
}

static int32_t BuildRelPathFromFileName(const char *prefix, const char *hexName, char *relPath, uint32_t relPathLen)
{
    if (prefix == NULL || hexName == NULL || relPath == NULL || relPathLen == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int ret = snprintf(relPath, relPathLen, "%s/%c%c/%s", prefix, hexName[0], hexName[1], hexName);
    if ((ret < 0) || ((uint32_t)ret >= relPathLen)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    return CMR_OK;
}

static bool IsPathInValidSet(char **paths, uint32_t count, const char *targetRel)
{
    if (paths == NULL || targetRel == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (paths[i] == NULL) {
            continue;
        }
        if (strcmp(paths[i], targetRel) == 0) {
            return true;
        }
    }
    return false;
}

int32_t CmServiceSaveRevocationCache(const struct CmBlob *key, uint32_t type, const struct CmBlob *data,
    int64_t expireTimeUtc)
{
    if (key == NULL || data == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int64_t clampedExpire = 0;
    int32_t ret = CmRevocationCacheValidateSaveParams(key, type, data, expireTimeUtc, &clampedExpire);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    char relPath[512] = {0};
    ret = CmRevocationCacheBuildRelPath(type, key, relPath, sizeof(relPath));
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t payloadLen = (uint32_t)sizeof(int64_t) + data->size;
    uint8_t *payload = (uint8_t *)CMMalloc(payloadLen);
    if (payload == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    CmRevocationCacheEncodeInt64Be(clampedExpire, payload);
    if (memcpy_s(payload + sizeof(int64_t), payloadLen - sizeof(int64_t), data->data, data->size) != EOK) {
        CMFree(payload);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    pthread_mutex_lock(&g_revocationCacheLock);
    int64_t now = (int64_t)time(NULL);
    int64_t lastClean = 0;
    ret = GetRevocationCacheMeta(&lastClean);
    if (ret != CM_SUCCESS || (now - lastClean > REVOCATION_CACHE_CLEAN_INTERVAL_SEC)) {
        // clean expired
        struct RevocationCacheRecord rec = { 0 };
        while (QueryExpiredRevocationCacheRecord(now, &rec) == CM_SUCCESS) {
            char fullFile[PATH_MAX] = {0};
            (void)snprintf(fullFile, sizeof(fullFile), "%s%s", REVOCATION_CACHE_DIR, rec.filePath);
            (void)unlink(fullFile);
            if (DeleteRevocationCacheRecord(rec.filePath) != CM_SUCCESS) {
                CM_LOG_W("delete expired revocation cache record failed");
                break;
            }
            (void)memset_s(&rec, sizeof(rec), 0, sizeof(rec));
        }
        // orphan cleanup
        char **paths = NULL;
        uint32_t pathCount = 0;
        if (QueryAllRevocationCacheFilePaths(&paths, &pathCount) == CM_SUCCESS) {
            const char *base = REVOCATION_CACHE_DIR;
            const char *types[] = { "ocsp", "crl" };
            for (uint32_t t = 0; t < 2; ++t) {
                char typeDir[PATH_MAX] = {0};
                (void)snprintf(typeDir, sizeof(typeDir), "%s%s/", base, types[t]);
                void *dirp = CmOpenDir(typeDir);
                if (dirp == NULL) {
                    continue;
                }
                struct CmFileDirentInfo dent;
                while (CmGetSubDir(dirp, &dent) == CM_SUCCESS) {
                    char subDir[PATH_MAX] = {0};
                    (void)snprintf(subDir, sizeof(subDir), "%s%s", typeDir, dent.fileName);
                    void *subp = CmOpenDir(subDir);
                    if (subp == NULL) {
                        continue;
                    }
                    struct CmFileDirentInfo f;
                    while (CmGetDirFile(subp, &f) == CM_SUCCESS) {
                        if (IsFileNameTmp(f.fileName)) {
                            char tmpFull[PATH_MAX] = {0};
                            (void)snprintf(tmpFull, sizeof(tmpFull), "%s/%s", subDir, f.fileName);
                            (void)unlink(tmpFull);
                            continue;
                        }
                        if (IsFileNameCache(f.fileName)) {
                            char relCand[512] = {0};
                            if (BuildRelPathFromFileName(types[t], f.fileName, relCand, sizeof(relCand)) == CM_SUCCESS) {
                                if (!IsPathInValidSet(paths, pathCount, relCand)) {
                                    char fullCand[PATH_MAX] = {0};
                                    (void)snprintf(fullCand, sizeof(fullCand), "%s%s", base, relCand);
                                    (void)unlink(fullCand);
                                }
                            }
                        }
                    }
                    CmCloseDir(subp);
                }
                CmCloseDir(dirp);
            }
            FreeRevocationCacheFilePaths(paths, pathCount);
        }
        (void)SetRevocationCacheMeta(now);
    }

    // capacity
    uint64_t totalSize = 0;
    (void)QueryRevocationCacheSumSize(&totalSize);
    while (totalSize + (uint64_t)payloadLen > (uint64_t)REVOCATION_CACHE_MAX_TOTAL_BYTES) {
        struct RevocationCacheRecord oldest;
        if (QueryRevocationCacheRecordByExpireAsc(&oldest) != CM_SUCCESS) {
            break;
        }
        char oldestFull[PATH_MAX] = {0};
        (void)snprintf(oldestFull, sizeof(oldestFull), "%s%s", REVOCATION_CACHE_DIR, oldest.filePath);
        (void)unlink(oldestFull);
        if (DeleteRevocationCacheRecord(oldest.filePath) != CM_SUCCESS) {
            CM_LOG_W("delete revocation cache record for capacity failed");
            break;
        }
        totalSize = (totalSize >= oldest.dataSize) ? (totalSize - oldest.dataSize) : 0;
    }
    // ensure dirs and write
    int32_t writeRet = CMR_OK;
    mode_t mode0701 = S_IRWXU | S_IXOTH;
    if (EnsureDirWithMode(REVOCATION_CACHE_DIR, &mode0701) == CMR_ERROR_MAKE_DIR_FAIL) {
        writeRet = CMR_ERROR_MAKE_DIR_FAIL;
        goto cleanup;
    }
    // ensure type dir and prefix dir
    {
        const char *prefixType = (type == CM_REVOCATION_TYPE_OCSP) ? "ocsp" : "crl";
        char typeDir[PATH_MAX] = {0};
        (void)snprintf(typeDir, sizeof(typeDir), "%s%s/", REVOCATION_CACHE_DIR, prefixType);
        (void)EnsureDirWithMode(typeDir, &mode0701);
        // ensure prefix dir
        char hexName[PATH_MAX] = {0};
        const char *lastSlash = strrchr(relPath, '/');
        if (lastSlash != NULL) {
            (void)strncpy_s(hexName, sizeof(hexName), lastSlash + 1, strlen(lastSlash + 1) - 6);
        }
        if (hexName[0] != '\0' && hexName[1] != '\0') {
            char prefixDir[PATH_MAX] = {0};
            (void)snprintf(prefixDir, sizeof(prefixDir), "%s%s/%c%c/", REVOCATION_CACHE_DIR, prefixType, hexName[0], hexName[1]);
            (void)EnsureDirWithMode(prefixDir, &mode0701);
        }
    }

    writeRet = CmRevocationCacheWriteAtomic(relPath, payload, payloadLen);
    if (writeRet != CMR_OK) {
        goto cleanup;
    }

    struct RevocationCacheRecord recWrite = { 0 };
    recWrite.expireTimeUtc = clampedExpire;
    if (strncpy_s(recWrite.filePath, sizeof(recWrite.filePath), relPath, strlen(relPath)) != EOK) {
        writeRet = CMR_ERROR_MEM_OPERATION_COPY;
        goto cleanup;
    }
    recWrite.dataSize = (uint64_t)sizeof(int64_t) + (uint64_t)data->size;
    if (InsertRevocationCacheRecord(&recWrite) != CM_SUCCESS) {
        writeRet = CMR_ERROR_WRITE_FILE_FAIL;
        goto cleanup;
    }

cleanup:
    pthread_mutex_unlock(&g_revocationCacheLock);
    CMFree(payload);
    return writeRet;
}
