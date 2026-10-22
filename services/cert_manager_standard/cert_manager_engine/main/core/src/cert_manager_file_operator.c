/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cert_manager_file_operator.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "securec.h"

#include "cert_manager_mem.h"
#include "cert_manager_storage.h"
#include "cert_manager_updateflag.h"
#include "cm_log.h"
#include "cm_revocation_cache.h"

static int32_t GetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
{
    if (path != NULL && strlen(path) > 0) {
        if (strncpy_s(fullFileName, fullFileNameLen, path, strlen(path)) != EOK) {
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }

        if (path[strlen(path) - 1] != '/') {
            if (strncat_s(fullFileName, fullFileNameLen, "/", strlen("/")) != EOK) {
                return CMR_ERROR_MEM_OPERATION_PRINT;
            }
        }

        if (strncat_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    } else {
        if (strncpy_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    }
    return CMR_OK;
}

static int32_t GetFullFileName(const char *path, const char *fileName, char **fullFileName)
{
    uint32_t nameLen = CM_MAX_FILE_NAME_LEN;
    char *tmpFileName = (char *)CMMalloc(nameLen);
    if (tmpFileName == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(tmpFileName, nameLen, 0, nameLen);

    int32_t ret = GetFileName(path, fileName, tmpFileName, nameLen);
    if (ret != CMR_OK) {
        CM_LOG_E("get full fileName failed");
        CM_FREE_PTR(tmpFileName);
        return ret;
    }
    *fullFileName = tmpFileName;

    return CMR_OK;
}

static int32_t IsFileExist(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        return CMR_ERROR_NOT_EXIST;
    }

    return CMR_OK;
}

static int32_t ValidatePath(const char *verifyPath, char *realPath)
{
    if (verifyPath == NULL) {
        CM_LOG_E("verify path is null");
        return CMR_ERROR_NULL_POINTER;
    }

    if (strstr(verifyPath, "..") != NULL) {
        CM_LOG_E("The verify path is relative path: %s", verifyPath);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (realpath(verifyPath, realPath) == NULL) {
        CM_LOG_E("The verify path is invalid: %s", verifyPath);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return CMR_OK;
}

int32_t CmIsDirExist(const char *path)
{
    char realPath[PATH_MAX + 1] = {0};
    if (ValidatePath(path, realPath) != CMR_OK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return IsFileExist(realPath);
}

static uint32_t FileRead(const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    (void)offset;
    char filePath[PATH_MAX + 1] = {0};
    if (ValidatePath(fileName, filePath) != CMR_OK) {
        return 0;
    }

    if (IsFileExist(filePath) != CMR_OK) {
        return 0;
    }

    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL) {
        CM_LOG_E("failed to open file");
        return 0;
    }

    uint32_t size = fread(buf, 1, len, fp);
    if (fclose(fp) < 0) {
        CM_LOG_E("failed to close file");
        return 0;
    }

    return size;
}

static uint32_t FileSize(const char *fileName)
{
    char filePath[PATH_MAX + 1] = {0};
    if (ValidatePath(fileName, filePath) != CMR_OK) {
        return 0;
    }

    if (IsFileExist(filePath) != CMR_OK) {
        return 0;
    }

    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));

    if (stat(filePath, &fileStat) != 0) {
        CM_LOG_E("file stat fail.");
        return 0;
    }

    return (uint32_t)fileStat.st_size;
}

static uint64_t CreateFdsanOwnTag(void* addr)
{
    uint64_t tag = 0;
    if (addr != NULL) {
        tag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, (uint64_t)addr);
    }
    return tag;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len, bool isWriteBakFile)
{
    (void)offset;
    char filePath[PATH_MAX + 1] = {0};
    if (memcpy_s(filePath, sizeof(filePath) - 1, fileName, strlen(fileName)) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (strstr(filePath, "..") != NULL) {
        CM_LOG_E("invalid filePath");
        return CMR_ERROR_NOT_EXIST;
    }
    /* Ignore return value: realpath will return null in musl c when the file does not exist */
    (void)realpath(fileName, filePath);

    int32_t fd;
    if (isWriteBakFile) {
        fd = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    } else {
        fd = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    }
    if (fd < 0) {
        CM_LOG_E("open file failed, errno = 0x%x", errno);
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    uint64_t new_tag = CreateFdsanOwnTag(&fd);
    fdsan_exchange_owner_tag(fd, 0, new_tag);

    if (write(fd, buf, len) < 0) {
        CM_LOG_E("write file failed, errno = 0x%x", errno);
        fdsan_close_with_tag(fd, new_tag);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    if (fsync(fd) < 0) {
        CM_LOG_E("sync file failed");
        fdsan_close_with_tag(fd, new_tag);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    fdsan_close_with_tag(fd, new_tag);
    return CMR_OK;
}

static int32_t FileRemove(const char *fileName)
{
    char filePath[PATH_MAX + 1] = {0};
    if (ValidatePath(fileName, filePath) != CMR_OK) {
        return CMR_ERROR_NOT_EXIST;
    }

    int32_t ret = IsFileExist(filePath);
    if (ret != CMR_OK) {
        return CMR_OK; /* if file not exist, return ok */
    }

    struct stat tmp;
    if (stat(filePath, &tmp) != 0) {
        return CMR_ERROR_FILE_STAT;
    }

    if (S_ISDIR(tmp.st_mode)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((unlink(filePath) != 0) && (errno != ENOENT)) {
        CM_LOG_E("failed to remove file: errno = 0x%x", errno);
        return CMR_ERROR_REMOVE_FILE_FAIL;
    }

    return CMR_OK;
}

int32_t CmFileRemove(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return ret;
    }

    ret = FileRemove(fullFileName);
    CM_FREE_PTR(fullFileName);
    return ret;
}

int32_t CmMakeDir(const char *path)
{
    if (path == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (IsFileExist(path) == CMR_OK) {
        return CMR_OK;
    }

    if (strstr(path, "..") != NULL) {
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (mkdir(path, S_IRWXU) == 0) {
        return CMR_OK;
    } else {
        if (errno == EEXIST || errno == EAGAIN) {
            return CMR_ERROR_ALREADY_EXISTS;
        } else {
            return CMR_ERROR_MAKE_DIR_FAIL;
        }
    }
}

int32_t CmUserBakupMakeDir(const char *path, const mode_t *mode)
{
    mode_t modeTmp = S_IRWXU | S_IROTH | S_IXOTH; /* The default directory permission is 0705 */

    if (IsFileExist(path) == CMR_OK) {
        return CMR_OK;
    }

    if (strstr(path, "..") != NULL) {
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (mode != NULL) {
        modeTmp = *mode;
    }
    if (mkdir(path, modeTmp) == 0) {
        return CMR_OK;
    } else {
        if (errno == EEXIST || errno == EAGAIN) {
            return CMR_ERROR_ALREADY_EXISTS;
        } else {
            return CMR_ERROR_MAKE_DIR_FAIL;
        }
    }
}

void *CmOpenDir(const char *path)
{
    return (void *)opendir(path);
}

int32_t CmCloseDir(void *dirp)
{
    return closedir((DIR *)dirp);
}

int32_t CmGetDirFile(void *dirp, struct CmFileDirentInfo *direntInfo)
{
    DIR *dir = (DIR *)dirp;
    struct dirent *dire = readdir(dir);

    while (dire != NULL) {
        if (dire->d_type != DT_REG) { /* only care about files. */
            dire = readdir(dir);
            continue;
        }

        uint32_t len = strlen(dire->d_name);
        if (memcpy_s(direntInfo->fileName, sizeof(direntInfo->fileName) - 1, dire->d_name, len) != EOK) {
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
        direntInfo->fileName[len] = '\0';
        return CMR_OK;
    }

    return CMR_ERROR_NOT_EXIST;
}

uint32_t CmFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return 0;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return 0;
    }

    uint32_t size = FileRead(fullFileName, offset, buf, len);
    CM_FREE_PTR(fullFileName);
    return size;
}

int32_t CmFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return ret;
    }

    ret = FileWrite(fullFileName, offset, buf, len, false);
    CM_FREE_PTR(fullFileName);
    return ret;
}

int32_t CmUserBackupFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return ret;
    }

    ret = FileWrite(fullFileName, offset, buf, len, true);
    CM_FREE_PTR(fullFileName);
    return ret;
}

uint32_t CmFileSize(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        CM_LOG_E("fileName is NULL");
        return 0;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        CM_LOG_E("GetFullFileName failed");
        return 0;
    }

    uint32_t size = FileSize(fullFileName);
    CM_FREE_PTR(fullFileName);
    return size;
}

static int32_t CmUidLayerGetFileNames(const char *filePath, struct CmBlob *credFilePaths,
    const uint32_t arraySize, uint32_t count)
{
    if (count >= arraySize) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uint32_t filePathLen = strlen(filePath);
    if (filePathLen >= CM_MAX_FILE_NAME_LEN) {
        CM_LOG_E("CmUidLayerGetFileNames filePathLen:%u", filePathLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    credFilePaths[count].data = (uint8_t *)CMMalloc(filePathLen + 1);
    if (credFilePaths[count].data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(credFilePaths[count].data, filePathLen + 1, 0, filePathLen + 1);
    if (memcpy_s(credFilePaths[count].data, filePathLen + 1, filePath, filePathLen) != EOK) {
        /* credFilePaths memory free in top layer function */
        CM_FREE_PTR(credFilePaths[count].data);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    credFilePaths[count].size = filePathLen + 1; /* include '\0' at end */
    return CM_SUCCESS;
}

int32_t CmUidLayerGetFileCountAndNames(const char *path, struct CmBlob *credFilePaths,
    const uint32_t arraySize, uint32_t *fileCount)
{
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_D("Uid layer dir is not exist");
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir == NULL) {
        CM_LOG_E("open uid layer dir failed");
        return CMR_ERROR_FILE_OPEN_DIR;
    }

    int32_t ret = CM_SUCCESS;
    uint32_t count = *fileCount;
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        char uidPath[CM_MAX_FILE_NAME_LEN] = {0};
        if (strncpy_s(uidPath, sizeof(uidPath), path, strlen(path)) != EOK) {
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }

        if (uidPath[strlen(uidPath) - 1] != '/') {
            if (strncat_s(uidPath, sizeof(uidPath), "/", strlen("/")) != EOK) {
                ret = CMR_ERROR_MEM_OPERATION_COPY;
                break;
            }
        }

        if (strncat_s(uidPath, sizeof(uidPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }

        if ((dire->d_type == DT_REG) && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            ret = CmUidLayerGetFileNames(uidPath, credFilePaths, arraySize, count);
            if (ret != CM_SUCCESS) {
                break;
            }
            count++;
        }
        dire = readdir(dir);
    }
    *fileCount = count;
    closedir(dir);
    return ret;
}

int32_t CmUserIdLayerGetFileCountAndNames(const char *path, struct CmBlob *credFilePaths,
    const uint32_t arraySize, uint32_t *fileCount)
{
    char userIdPath[CM_MAX_FILE_NAME_LEN] = { 0 };
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_D("UserId layer dir is not exist");
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open userId layer dir failed");
        return CMR_ERROR_FILE_OPEN_DIR;
    }
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        (void)memset_s(userIdPath, CM_MAX_FILE_NAME_LEN, 0, CM_MAX_FILE_NAME_LEN);
        if (strncpy_s(userIdPath, sizeof(userIdPath), path, strlen(path)) != EOK) {
            closedir(dir);
            return CMR_ERROR_MEM_OPERATION_COPY;
        }

        if (userIdPath[strlen(userIdPath) - 1] != '/') {
            if (strncat_s(userIdPath, sizeof(userIdPath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return CMR_ERROR_MEM_OPERATION_COPY;
            }
        }

        if (strncat_s(userIdPath, sizeof(userIdPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return CMR_ERROR_MEM_OPERATION_COPY;
        }

        if ((dire->d_type == DT_DIR) && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            if (CmUidLayerGetFileCountAndNames(userIdPath, credFilePaths, arraySize, fileCount) != CM_SUCCESS) {
                CM_LOG_E("CmUidLayerGetFileCountAndNames faild");
                closedir(dir);
                return CM_FAILURE;
            }
        } else if (dire->d_type != DT_DIR) {
            (void)remove(userIdPath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    return CM_SUCCESS;
}

int32_t CmIsFileExist(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        CM_LOG_E("fileName is NULL");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetFullFileName failed");
        return ret;
    }

    ret = IsFileExist(fullFileName);
    CM_FREE_PTR(fullFileName);
    return ret;
}

int32_t CmGetSubDir(void *dirp, struct CmFileDirentInfo *direntInfo)
{
    DIR *dir = (DIR *)dirp;
    struct dirent *dire = readdir(dir);

    while (dire != NULL) {
        if ((dire->d_type != DT_DIR) || (strcmp(dire->d_name, ".") == 0) ||
            (strcmp(dire->d_name, "..") == 0)) {
            dire = readdir(dir);
            continue;
        }

        uint32_t dirLen = strlen(dire->d_name);
        if (memcpy_s(direntInfo->fileName, sizeof(direntInfo->fileName) - 1, dire->d_name, dirLen) != EOK) {
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
        direntInfo->fileName[dirLen] = '\0';
        return CMR_OK;
    }

    return CMR_ERROR_NOT_EXIST;
}

static int32_t DirRemove(const char *path)
{
    char filePath[PATH_MAX + 1] = {0};
    if (ValidatePath(path, filePath) != CMR_OK) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (IsFileExist(filePath) != CMR_OK) {
        return CMR_ERROR_NOT_EXIST;
    }

    struct stat tmp;
    if (stat(filePath, &tmp) != 0) {
        return CMR_ERROR_FILE_STAT;
    }

    if (S_ISDIR(tmp.st_mode)) {
        uint32_t i = 0;
        struct dirent *dire = NULL;
        DIR *dirp = opendir(filePath);
        if (dirp == NULL) {
            CM_LOG_E("open dir failed");
            return CMR_ERROR_OPEN_FILE_FAIL;
        }
        while ((dire = readdir(dirp)) != NULL) {
            if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
                continue;
            }
            i++;
        }
        closedir(dirp);

        if (i != 0) {
            CM_LOG_E("Dir is not empty");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        if (rmdir(filePath) != 0) {
            CM_LOG_E("failed  to remove dir, errno = 0x%x", errno);
            return CMR_ERROR_REMOVE_FILE_FAIL;
        }
        return CMR_OK;
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmDirRemove(const char *path)
{
    if (path == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return DirRemove(path);
}

/* one metadata page is billed on top of the payload: the file system charges
 * an inode page per file */
#define REVOCATION_CACHE_BLOCK_ALIGN_BYTES 4096UL

/* accounting size: the file size plus one 4 KiB metadata page, rounded up to
 * the next 4 KiB block boundary — equivalent to the earlier wording of
 * "round the file size to KiB, add 4 KiB, then align to 4 KiB" */
static uint64_t AccountedSize(uint64_t fileSize)
{
    return ((fileSize + REVOCATION_CACHE_BLOCK_ALIGN_BYTES + (REVOCATION_CACHE_BLOCK_ALIGN_BYTES - 1)) /
        REVOCATION_CACHE_BLOCK_ALIGN_BYTES) * REVOCATION_CACHE_BLOCK_ALIGN_BYTES;
}

/*
 * Writes the payload to the tmp file through stdio and pushes it to disk.
 * fileno() is used only to pin the file mode and to fsync: the mode must stay
 * 0644 regardless of the umask, and crash consistency after the rename needs
 * the data on disk, not just inside the stdio buffer.
 */
static int32_t WriteTmpFile(const char *tmpPath, const uint8_t *buf, uint32_t len, uint64_t *fileSizeOut)
{
    FILE *fp = fopen(tmpPath, "wb");
    if (fp == NULL) {
        CM_LOG_E("open tmp file failed, errno = 0x%x", errno);
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    /* pin the mode regardless of the process umask: a cache file must never
     * become group/world writable, or readers could be fed tampered data */
    if (fchmod(fileno(fp), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        CM_LOG_E("set tmp file mode failed, errno = 0x%x", errno);
        (void)fclose(fp);
        (void)unlink(tmpPath);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    int32_t ret = CMR_OK;
    if (fwrite(buf, 1, len, fp) != (size_t)len) {
        CM_LOG_E("write tmp file failed, errno = 0x%x", errno);
        ret = CMR_ERROR_WRITE_FILE_FAIL;
    }
    if ((ret == CMR_OK) && (fflush(fp) != 0)) {
        CM_LOG_E("flush tmp file failed, errno = 0x%x", errno);
        ret = CMR_ERROR_WRITE_FILE_FAIL;
    }
    while (ret == CMR_OK) {
        if (fsync(fileno(fp)) == 0) {
            break;
        }
        if (errno != EINTR) {
            CM_LOG_E("sync tmp file failed, errno = 0x%x", errno);
            ret = CMR_ERROR_WRITE_FILE_FAIL;
        }
    }
    /* size the tmp inode while it is still open: capacity is billed before
     * the rename makes the entry visible, so a failed stat leaves the final
     * path and any previous row untouched */
    if (ret == CMR_OK) {
        struct stat st = { 0 };
        if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode)) {
            CM_LOG_E("stat tmp file failed, errno = 0x%x", errno);
            ret = CMR_ERROR_FILE_STAT;
        } else {
            *fileSizeOut = (uint64_t)st.st_size;
        }
    }
    if ((fclose(fp) != 0) && (ret == CMR_OK)) {
        CM_LOG_E("close tmp file failed, errno = 0x%x", errno);
        ret = CMR_ERROR_WRITE_FILE_FAIL;
    }
    if (ret != CMR_OK) {
        (void)unlink(tmpPath);
    }
    return ret;
}

static int32_t SyncParentDir(const char *fullPath)
{
    char dirPath[PATH_MAX] = {0};
    if (strcpy_s(dirPath, sizeof(dirPath), fullPath) != EOK) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    char *slash = strrchr(dirPath, '/');
    if (slash == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    *slash = '\0';
    /* validate before open: only a directory inside the cache root may ever
     * be opened, a symlinked or escaped path fails closed */
    if (CmRevocationCacheCheckPathUnderRoot(REVOCATION_CACHE_DIR, dirPath) != CM_SUCCESS) {
        return CMR_ERROR_NOT_EXIST;
    }
    int dirFd = open(dirPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd < 0) {
        /* the entry itself is durable, the dir sync is advisory */
        CM_LOG_W("open parent dir failed, errno = 0x%x", errno);
        return CMR_OK;
    }
    uint64_t tag = CreateFdsanOwnTag(&dirFd);
    fdsan_exchange_owner_tag(dirFd, 0, tag);
    (void)fsync(dirFd);
    fdsan_close_with_tag(dirFd, tag);
    return CMR_OK;
}

/*
 * The parent directory of the cache file must resolve inside the cache root;
 * this also fails closed when the directory is missing or symlinked.
 */
static int32_t CheckParentDirUnderRoot(const char *fullPath)
{
    char parentDir[PATH_MAX] = {0};
    if (strcpy_s(parentDir, sizeof(parentDir), fullPath) != EOK) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    char *lastSlash = strrchr(parentDir, '/');
    if (lastSlash == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    *lastSlash = '\0';
    if (CmRevocationCacheCheckPathUnderRoot(REVOCATION_CACHE_DIR, parentDir) != CM_SUCCESS) {
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    return CMR_OK;
}

int32_t CmRevocationCacheWriteAtomic(const char *relPath, const uint8_t *buf, uint32_t len,
    uint64_t *accountedSizeOut)
{
    if (relPath == NULL || buf == NULL || len == 0 || accountedSizeOut == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* validate before use: only the strict cache sub-path grammar is
     * accepted, so the write can never escape the cache root */
    if (CmRevocationCacheValidateRelPath(relPath) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    char fullPath[PATH_MAX] = {0};
    int32_t ret = snprintf_s(fullPath, sizeof(fullPath), sizeof(fullPath) - 1, "%s%s",
        REVOCATION_CACHE_DIR, relPath);
    if (ret < 0) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    ret = CheckParentDirUnderRoot(fullPath);
    if (ret != CMR_OK) {
        return ret;
    }
    char tmpPath[PATH_MAX] = {0};
    ret = snprintf_s(tmpPath, sizeof(tmpPath), sizeof(tmpPath) - 1, "%s.tmp", fullPath);
    if (ret < 0) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    /* a leftover tmp must never be followed: remove it so the write always
     * starts from a fresh regular file (the save lock keeps this race-free) */
    (void)unlink(tmpPath);
    uint64_t fileSize = 0;
    ret = WriteTmpFile(tmpPath, buf, len, &fileSize);
    if (ret != CMR_OK) {
        return ret;
    }
    if (rename(tmpPath, fullPath) != 0) {
        CM_LOG_E("rename tmp file failed, errno = 0x%x", errno);
        (void)unlink(tmpPath);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    /* fsync the parent directory so the rename survives a power loss; a
     * validation failure here fails the save — for a fresh key the orphan
     * cleanup reclaims the renamed file, on a re-save the old row still
     * references it and the expiry cleanup does the reaping */
    ret = SyncParentDir(fullPath);
    if (ret != CMR_OK) {
        return ret;
    }
    *accountedSizeOut = AccountedSize(fileSize);
    return CMR_OK;
}
