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

static const size_t CACHE_SUFFIX_LEN = sizeof(".cache") - 1;
static const size_t TMP_SUFFIX_LEN = sizeof(".tmp") - 1;

static bool IsFileNameCache(const char *name)
{
    if (name == NULL) {
        return false;
    }
    size_t len = strlen(name);
    if (len < CACHE_SUFFIX_LEN) {
        return false;
    }
    return strcmp(name + len - CACHE_SUFFIX_LEN, ".cache") == 0;
}

static bool IsFileNameTmp(const char *name)
{
    if (name == NULL) {
        return false;
    }
    size_t len = strlen(name);
    if (len < TMP_SUFFIX_LEN) {
        return false;
    }
    return strcmp(name + len - TMP_SUFFIX_LEN, ".tmp") == 0;
}

static int32_t BuildRelPathFromFileName(const char *prefix, const char *encodedName, char *relPath, uint32_t relPathLen)
{
    if (prefix == NULL || encodedName == NULL || relPath == NULL || relPathLen == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int ret = snprintf_s(relPath, relPathLen, relPathLen - 1, "%s/%s", prefix, encodedName);
    if (ret < 0) {
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

static int32_t RemoveExpiredRecords(int64_t now)
{
    struct RevocationCacheRecord rec = { 0 };
    while (QueryExpiredRevocationCacheRecord(now, &rec) == CM_SUCCESS) {
        /* a corrupted row must never turn unlink into an arbitrary delete */
        if (CmRevocationCacheValidateRelPath(rec.filePath) == CM_SUCCESS) {
            char fullFile[PATH_MAX] = {0};
            if (snprintf_s(fullFile, sizeof(fullFile), sizeof(fullFile) - 1, "%s%s", REVOCATION_CACHE_DIR,
                rec.filePath) >= 0) {
                (void)unlink(fullFile);
            }
        }
        if (DeleteRevocationCacheRecord(rec.filePath) != CM_SUCCESS) {
            CM_LOG_W("delete expired revocation cache record failed");
            return CMR_ERROR;
        }
        (void)memset_s(&rec, sizeof(rec), 0, sizeof(rec));
    }
    return CMR_OK;
}

static void RemoveOrphanFileIfNeed(const char *subDir, const char *typePrefix,
    const struct CmFileDirentInfo *file, char **paths, uint32_t pathCount)
{
    if (IsFileNameTmp(file->fileName)) {
        char tmpFull[PATH_MAX] = {0};
        if (snprintf_s(tmpFull, sizeof(tmpFull), sizeof(tmpFull) - 1, "%s/%s", subDir,
            file->fileName) >= 0) {
            (void)unlink(tmpFull);
        }
        return;
    }
    if (!IsFileNameCache(file->fileName)) {
        return;
    }
    char relCand[512] = {0};
    if (BuildRelPathFromFileName(typePrefix, file->fileName, relCand, sizeof(relCand)) != CM_SUCCESS) {
        return;
    }
    /* only well-formed cache sub-paths take part in orphan cleanup */
    if (CmRevocationCacheValidateRelPath(relCand) != CM_SUCCESS) {
        return;
    }
    if (IsPathInValidSet(paths, pathCount, relCand)) {
        return;
    }
    char fullCand[PATH_MAX] = {0};
    if (snprintf_s(fullCand, sizeof(fullCand), sizeof(fullCand) - 1, "%s%s", REVOCATION_CACHE_DIR,
        relCand) >= 0) {
        (void)unlink(fullCand);
    }
}

static int32_t RemoveOrphanRecords(void)
{
    char **paths = NULL;
    uint32_t pathCount = 0;
    if (QueryAllRevocationCacheFilePaths(&paths, &pathCount) != CM_SUCCESS) {
        return CMR_OK;
    }
    /* two-level layout: cache files live directly in the store dir, no fanout */
    const char *types[] = { "ocsp", "crl" };
    for (uint32_t t = 0; t < CM_ARRAY_SIZE(types); ++t) {
        char typeDir[PATH_MAX] = {0};
        if (snprintf_s(typeDir, sizeof(typeDir), sizeof(typeDir) - 1, "%s%s", REVOCATION_CACHE_DIR,
            types[t]) < 0) {
            continue;
        }
        void *dirp = CmOpenDir(typeDir);
        if (dirp == NULL) {
            continue;
        }
        struct CmFileDirentInfo f;
        while (CmGetDirFile(dirp, &f) == CM_SUCCESS) {
            RemoveOrphanFileIfNeed(typeDir, types[t], &f, paths, pathCount);
        }
        CmCloseDir(dirp);
    }
    FreeRevocationCacheFilePaths(paths, pathCount);
    return CMR_OK;
}

/*
 * Expired/orphan cleanup must stay inside the save lock: unlinking files while
 * another thread is writing the same key would delete a freshly written entry.
 * The cost is bounded because it only runs once per REVOCATION_CACHE_CLEAN_INTERVAL_SEC.
 */
static void CleanupExpiredAndOrphans(int64_t now)
{
    (void)RemoveExpiredRecords(now);
    (void)RemoveOrphanRecords();
    (void)SetRevocationCacheMeta(now);
}

/* unlinks the file of an evicted or expired row: only a strict cache
 * sub-path may be unlinked, never an arbitrary one */
static void UnlinkCacheFileForPath(const char *relPath)
{
    if (CmRevocationCacheValidateRelPath(relPath) != CM_SUCCESS) {
        return;
    }
    char full[PATH_MAX] = {0};
    if (snprintf_s(full, sizeof(full), sizeof(full) - 1, "%s%s", REVOCATION_CACHE_DIR, relPath) >= 0) {
        (void)unlink(full);
    }
}

static void EvictUntilCapacity(const char *selfKey, const char *selfType, uint64_t newSize,
    uint64_t *totalSize)
{
    while (*totalSize + newSize > (uint64_t)REVOCATION_CACHE_MAX_TOTAL_BYTES) {
        struct RevocationCacheRecord cand;
        if (QueryRevocationCacheEvictCandidate(selfKey, selfType, &cand) != CM_SUCCESS) {
            break; /* nothing left to evict: accept the overage rather than loop */
        }
        if (cand.expireTimeUtc <= (int64_t)time(NULL)) {
            /* expired (same boundary as the read path): reap physically, the
             * file goes with the row */
            UnlinkCacheFileForPath(cand.filePath);
            if (DeleteRevocationCacheRecord(cand.filePath) != CM_SUCCESS) {
                CM_LOG_W("delete revocation cache record for capacity failed");
                break;
            }
        } else {
            /* unexpired: mark deleted and keep the file, the periodic cleanup
             * reaps the row and file once the expire time passes */
            if (MarkRevocationCacheRecordDeleted(cand.filePath) != CM_SUCCESS) {
                CM_LOG_W("mark revocation cache record deleted for capacity failed");
                break;
            }
        }
        *totalSize = (*totalSize >= cand.dataSize) ? (*totalSize - cand.dataSize) : 0;
    }
}

/* two-level layout: the cache root plus the one store dir per type */
static int32_t EnsureCacheDirs(uint32_t type)
{
    mode_t mode0701 = S_IRWXU | S_IXOTH;
    if (EnsureDirWithMode(REVOCATION_CACHE_DIR, &mode0701) == CMR_ERROR_MAKE_DIR_FAIL) {
        return CMR_ERROR_MAKE_DIR_FAIL;
    }
    const char *prefixType = (type == CM_REVOCATION_TYPE_OCSP) ? "ocsp" : "crl";
    char typeDir[PATH_MAX] = {0};
    if (snprintf_s(typeDir, sizeof(typeDir), sizeof(typeDir) - 1, "%s%s/", REVOCATION_CACHE_DIR,
        prefixType) >= 0) {
        (void)EnsureDirWithMode(typeDir, &mode0701);
    }
    return CMR_OK;
}

static int32_t BuildRevocationCachePayload(int64_t clampedExpire, const struct CmBlob *data,
    uint8_t **payloadOut, uint32_t *payloadLenOut)
{
    uint32_t payloadLen = (uint32_t)sizeof(int64_t) + data->size;
    uint8_t *payload = (uint8_t *)CMMalloc(payloadLen);
    if (payload == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    struct CmBlob expireBlob = { sizeof(int64_t), payload };
    CmRevocationCacheEncodeInt64Be(clampedExpire, &expireBlob);
    if (memcpy_s(payload + sizeof(int64_t), payloadLen - sizeof(int64_t), data->data, data->size) != EOK) {
        CMFree(payload);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    *payloadOut = payload;
    *payloadLenOut = payloadLen;
    return CM_SUCCESS;
}

/* splits "<type>/<encoded>.cache" into the hex key and the type string: the
 * row keeps both, derived from the same rel path as the file */
static int32_t GetKeyAndTypeFromRelPath(const char *relPath, char *keyOut, uint32_t keyOutLen,
    char *typeOut, uint32_t typeOutLen)
{
    const char *lastSlash = strrchr(relPath, '/');
    if (lastSlash == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    const char *encodedName = lastSlash + 1;
    size_t nameLen = strlen(encodedName);
    if (nameLen <= CACHE_SUFFIX_LEN || (nameLen - CACHE_SUFFIX_LEN) > keyOutLen - 1) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strncpy_s(keyOut, keyOutLen, encodedName, nameLen - CACHE_SUFFIX_LEN) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    size_t typeLen = (size_t)(lastSlash - relPath);
    if (typeLen == 0 || typeLen > typeOutLen - 1) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (strncpy_s(typeOut, typeOutLen, relPath, typeLen) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

static int32_t SaveRevocationCacheRecord(const char *relPath, int64_t clampedExpire, uint64_t dataSize)
{
    struct RevocationCacheRecord recWrite = { 0 };
    recWrite.expireTimeUtc = clampedExpire;
    if (strncpy_s(recWrite.filePath, sizeof(recWrite.filePath), relPath, strlen(relPath)) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    recWrite.dataSize = dataSize;
    if (GetKeyAndTypeFromRelPath(relPath, recWrite.key, sizeof(recWrite.key),
        recWrite.type, sizeof(recWrite.type)) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (InsertRevocationCacheRecord(&recWrite) != CM_SUCCESS) {
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    return CMR_OK;
}

/* the save pipeline under the cache lock: cleanup pass, durable write with
 * accounted sizing, capacity eviction, then the row insert */
static int32_t SaveCacheEntryUnderLock(uint32_t type, const char *relPath, int64_t clampedExpire,
    const uint8_t *payload, uint32_t payloadLen)
{
    int64_t now = (int64_t)time(NULL);
    int64_t lastClean = 0;
    int32_t ret = GetRevocationCacheMeta(&lastClean);
    if (ret != CM_SUCCESS || (now - lastClean > REVOCATION_CACHE_CLEAN_INTERVAL_SEC)) {
        CleanupExpiredAndOrphans(now);
    }

    ret = EnsureCacheDirs(type);
    if (ret != CMR_OK) {
        return ret;
    }

    /* the write bills the accounted size, measured before the rename */
    uint64_t accountedSize = 0;
    ret = CmRevocationCacheWriteAtomic(relPath, payload, payloadLen, &accountedSize);
    if (ret != CMR_OK) {
        return ret;
    }

    /* self-exclusion: the row this save is about to replace must neither be
     * billed nor evicted while the REPLACE insert is still in flight; the
     * split cannot fail for a BuildRelPath path, the branch is a guard */
    char selfKey[CM_REVOCATION_CACHE_KEY_HEX_MAX_LEN + 1] = { 0 };
    char selfType[CM_REVOCATION_CACHE_TYPE_LEN] = { 0 };
    if (GetKeyAndTypeFromRelPath(relPath, selfKey, sizeof(selfKey), selfType, sizeof(selfType)) !=
        CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint64_t totalSize = 0;
    (void)QueryRevocationCacheActiveSumSize(selfKey, selfType, &totalSize);
    EvictUntilCapacity(selfKey, selfType, accountedSize, &totalSize);

    return SaveRevocationCacheRecord(relPath, clampedExpire, accountedSize);
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

    uint8_t *payload = NULL;
    uint32_t payloadLen = 0;
    ret = BuildRevocationCachePayload(clampedExpire, data, &payload, &payloadLen);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&g_revocationCacheLock);
    int32_t writeRet = SaveCacheEntryUnderLock(type, relPath, clampedExpire, payload, payloadLen);
    pthread_mutex_unlock(&g_revocationCacheLock);
    (void)memset_s(payload, payloadLen, 0, payloadLen);
    CMFree(payload);
    return writeRet;
}
