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

#include "cm_cloud_policy_store.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "cm_log.h"

namespace {
/* every path this module touches is fixed at build time: the cm_type.h
 * bases plus this header's names, never any caller-provided path */
const char CLOUD_POLICY_FILE_PATH[] = FORCE_CHECK_POLICY_DIR "/" CM_CLOUD_POLICY_FILE_NAME;
const char CLOUD_VERSION_FILE_PATH[] = FORCE_CHECK_POLICY_DIR "/" CM_CLOUD_VERSION_FILE_NAME;
const char CLOUD_TMP_DIR_PATH[] = REVOCATION_CACHE_BASE CM_CLOUD_TMP_DIR_NAME;

/* stream-copy chunk for publishing a staged file into forceCheck */
constexpr uint32_t PUBLISH_COPY_CHUNK = 4096;
/* a valid version is at most 20 decimal digits; anything at or above this
 * read length is malformed by definition and never parsed */
constexpr uint32_t VERSION_READ_MAX_LEN = 64;

bool PathIsDir(const char *path)
{
    struct stat st = {};
    return (stat(path, &st) == 0) && S_ISDIR(st.st_mode);
}

bool PathIsRegularFile(const char *path)
{
    struct stat st = {};
    return (stat(path, &st) == 0) && S_ISREG(st.st_mode);
}

/*
 * The atomic publish tail, the WriteAndPublishPolicyFile pattern of
 * cert_manager_status.c: push the open tmp stream to disk, close it exactly
 * once, pin the mode, then rename it over the published path. fp must be an
 * open write stream and is closed on every return path; a failed publish
 * also removes the tmp file so no residue stays behind.
 */
int32_t PublishTmpFile(FILE *fp, const std::string &tmpPath, const std::string &destPath,
    mode_t mode)
{
    int32_t ret = CM_SUCCESS;
    do {
        if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
            CM_LOG_E("flush %s failed, errno = 0x%x", tmpPath.c_str(), errno);
            ret = CMR_ERROR;
            break;
        }
        /* fclose destroys the stream even when it fails: close exactly once,
         * retrying it in the cleanup below would be undefined behavior */
        int closeRet = fclose(fp);
        fp = nullptr;
        if (closeRet != 0) {
            CM_LOG_E("close %s failed, errno = 0x%x", tmpPath.c_str(), errno);
            ret = CMR_ERROR;
            break;
        }
        /* the mode is pinned by the caller's argument, not the umask that
         * happened to be active when fopen created the tmp file */
        if (chmod(tmpPath.c_str(), mode) != 0) {
            CM_LOG_E("chmod %s failed, errno = 0x%x", tmpPath.c_str(), errno);
            ret = CMR_ERROR;
            break;
        }
        if (rename(tmpPath.c_str(), destPath.c_str()) != 0) {
            CM_LOG_E("rename %s failed, errno = 0x%x", tmpPath.c_str(), errno);
            ret = CMR_ERROR;
            break;
        }
    } while (0);

    if (fp != nullptr) {
        (void)fclose(fp);
    }
    if (ret != CM_SUCCESS) {
        (void)unlink(tmpPath.c_str());
    }
    return ret;
}

/* write content to "<destPath>.tmp" and publish it atomically over destPath */
int32_t WriteFileAtomic(const std::string &destPath, const std::string &content, mode_t mode)
{
    const std::string tmpPath = destPath + ".tmp";
    FILE *fp = fopen(tmpPath.c_str(), "wb");
    if (fp == nullptr) {
        CM_LOG_E("open %s failed, errno = 0x%x", tmpPath.c_str(), errno);
        return CMR_ERROR;
    }
    if (!content.empty() && fwrite(content.data(), 1, content.size(), fp) != content.size()) {
        CM_LOG_E("write %s failed, errno = 0x%x", tmpPath.c_str(), errno);
        (void)fclose(fp);
        (void)unlink(tmpPath.c_str());
        return CMR_ERROR;
    }
    return PublishTmpFile(fp, tmpPath, destPath, mode);
}

/*
 * Depth-first removal of a file or (small) directory tree. lstat based: a
 * symlink is removed itself and never followed, so nothing inside the
 * staging directory can point the cleanup outside it.
 */
void RemoveTreeNoFollow(const std::string &path)
{
    struct stat st = {};
    if (lstat(path.c_str(), &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path.c_str());
        return;
    }
    DIR *dir = opendir(path.c_str());
    if (dir != nullptr) {
        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
                continue;
            }
            RemoveTreeNoFollow(path + "/" + entry->d_name);
        }
        (void)closedir(dir);
    }
    (void)rmdir(path.c_str());
}

/*
 * strtoull with endptr validation: only fully consumed decimal input is a
 * version. Everything else -- empty content, trailing garbage, a leading
 * sign (strtoull would silently wrap "-1" to a huge value that locks the
 * sync out), or an overflowing digit count -- reads as version 0, so a
 * malformed store keeps the sync gating on a fresh state instead of
 * trusting a broken file. version is assigned only on success.
 */
bool ParseVersionContent(const char *buf, uint64_t &version)
{
    /* skip the whitespace strtoull would skip, so the sign check sees the
     * first real character */
    size_t first = strspn(buf, " \t\n\v\f\r");
    if ((buf[first] == '-') || (buf[first] == '+')) {
        return false;
    }
    errno = 0;
    char *endPtr = nullptr;
    unsigned long long parsed = strtoull(buf, &endPtr, 10);
    if ((endPtr == buf) || (*endPtr != '\0') || (errno == ERANGE)) {
        return false;
    }
    version = static_cast<uint64_t>(parsed);
    return true;
}
} // namespace

int32_t CmCloudStoreSelfHealPreset(void)
{
    /* item 1 of 3: the forceCheck directory at 0701, the mode the service
     * cfg mkdirs it with; the cfg is the primary source and this is the
     * fresh-boot fallback, the same self-healing mkdir the engine does */
    if (!PathIsDir(FORCE_CHECK_POLICY_DIR)) {
        if (mkdir(FORCE_CHECK_POLICY_DIR, S_IRWXU | S_IXOTH) == 0) {
            CM_LOG_I("self-heal created the forceCheck dir");
        } else if (!PathIsDir(FORCE_CHECK_POLICY_DIR)) {
            /* a racing creator may have made it between the two checks */
            CM_LOG_E("mkdir forceCheck dir failed, errno = 0x%x", errno);
            return CMR_ERROR;
        }
    }

    int32_t ret = CM_SUCCESS;
    do {
        /* item 2 of 3: a fresh version counter at 0; an existing one is
         * never rewritten, so a synced device keeps its version */
        if (!PathIsRegularFile(CLOUD_VERSION_FILE_PATH)) {
            ret = WriteFileAtomic(CLOUD_VERSION_FILE_PATH, "0", S_IRUSR | S_IWUSR);
            if (ret != CM_SUCCESS) {
                break;
            }
            CM_LOG_I("self-heal created the cloud version file");
        } else {
            CM_LOG_D("cloud version file already present");
        }
        /* item 3 of 3: the preset policy lines; an existing file -- the
         * preset or an already published sync -- is never overwritten */
        if (!PathIsRegularFile(CLOUD_POLICY_FILE_PATH)) {
            ret = WriteFileAtomic(CLOUD_POLICY_FILE_PATH,
                std::string(CM_CLOUD_POLICY_PRESET_LINE_1) + CM_CLOUD_POLICY_PRESET_LINE_2,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
            if (ret != CM_SUCCESS) {
                break;
            }
            CM_LOG_I("self-heal created the preset cloud policy file");
        } else {
            CM_LOG_D("cloud policy file already present");
        }
    } while (0);
    return ret;
}

int32_t CmCloudStoreReadVersion(uint64_t &version)
{
    /* assigned on every path: the caller can read it without checking */
    version = 0;
    FILE *fp = fopen(CLOUD_VERSION_FILE_PATH, "rb");
    if (fp == nullptr) {
        /* fail-open: a missing or unreadable store reads as version 0 so
         * the sync keeps gating and the next round re-downloads */
        CM_LOG_D("cloud version file missing or unreadable, errno = 0x%x", errno);
        return CM_SUCCESS;
    }
    char buf[VERSION_READ_MAX_LEN + 1] = {0};
    size_t readLen = fread(buf, 1, sizeof(buf), fp);
    bool readFailed = (ferror(fp) != 0);
    (void)fclose(fp);
    if (readFailed) {
        CM_LOG_W("read cloud version file failed, errno = 0x%x", errno);
        return CM_SUCCESS;
    }
    if (readLen == 0) {
        CM_LOG_W("cloud version file is empty");
        return CM_SUCCESS;
    }
    if (readLen == sizeof(buf)) {
        /* more bytes than any valid version: malformed without parsing */
        CM_LOG_W("cloud version file is oversized");
        return CM_SUCCESS;
    }
    buf[readLen] = '\0';
    if (!ParseVersionContent(buf, version)) {
        CM_LOG_W("malformed cloud version file content");
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

int32_t CmCloudStoreWriteVersion(uint64_t version)
{
    /* pure decimal digits, no trailing newline: exactly what the read side
     * accepts as fully consumed */
    return WriteFileAtomic(CLOUD_VERSION_FILE_PATH, std::to_string(version), S_IRUSR | S_IWUSR);
}

int32_t CmCloudStorePrepareTmpDir(void)
{
    if (PathIsDir(CLOUD_TMP_DIR_PATH)) {
        return CM_SUCCESS;
    }
    if (mkdir(CLOUD_TMP_DIR_PATH, S_IRWXU) != 0 && !PathIsDir(CLOUD_TMP_DIR_PATH)) {
        /* a racing creator may have made it between the two checks */
        CM_LOG_E("mkdir cloud tmp dir failed, errno = 0x%x", errno);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}

const char *CmCloudStoreTmpDirPath(void)
{
    return CLOUD_TMP_DIR_PATH;
}

int32_t CmCloudStoreCleanupTmpDir(void)
{
    struct stat st = {};
    if (stat(CLOUD_TMP_DIR_PATH, &st) != 0) {
        /* nothing staged: the steady state between syncs */
        return CM_SUCCESS;
    }
    RemoveTreeNoFollow(CLOUD_TMP_DIR_PATH);
    if (stat(CLOUD_TMP_DIR_PATH, &st) == 0) {
        CM_LOG_E("remove cloud tmp dir failed, errno = 0x%x", errno);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}

int32_t CmCloudStorePublishFile(const std::string &srcPath, const char *destName, mode_t mode)
{
    if (srcPath.empty() || (destName == nullptr) || (destName[0] == '\0')) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* a plain file name only: the dest path is FORCE_CHECK_POLICY_DIR plus
     * destName, so a name carrying '/' could never be allowed to escape it */
    if (strchr(destName, '/') != nullptr) {
        CM_LOG_E("publish dest name must be a plain file name");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    FILE *src = fopen(srcPath.c_str(), "rb");
    if (src == nullptr) {
        CM_LOG_E("open publish source %s failed, errno = 0x%x", srcPath.c_str(), errno);
        return CMR_ERROR;
    }
    const std::string destPath = std::string(FORCE_CHECK_POLICY_DIR "/") + destName;
    const std::string tmpPath = destPath + ".tmp";
    FILE *dst = fopen(tmpPath.c_str(), "wb");
    if (dst == nullptr) {
        /* a missing forceCheck lands here: publish never creates the dir */
        CM_LOG_E("open %s failed, errno = 0x%x", tmpPath.c_str(), errno);
        (void)fclose(src);
        return CMR_ERROR;
    }

    int32_t ret = CM_SUCCESS;
    char chunk[PUBLISH_COPY_CHUNK] = {0};
    while (true) {
        size_t readLen = fread(chunk, 1, sizeof(chunk), src);
        if ((readLen > 0) && (fwrite(chunk, 1, readLen, dst) != readLen)) {
            CM_LOG_E("write %s failed, errno = 0x%x", tmpPath.c_str(), errno);
            ret = CMR_ERROR;
            break;
        }
        if (readLen < sizeof(chunk)) {
            /* a short read is EOF only when the error flag is clear */
            if (ferror(src) != 0) {
                CM_LOG_E("read publish source %s failed, errno = 0x%x", srcPath.c_str(), errno);
                ret = CMR_ERROR;
            }
            break;
        }
    }
    (void)fclose(src);
    if (ret != CM_SUCCESS) {
        (void)fclose(dst);
        (void)unlink(tmpPath.c_str());
        return ret;
    }
    return PublishTmpFile(dst, tmpPath, destPath, mode);
}
