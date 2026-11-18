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

#include "cm_cloud_zip.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

#include "cm_log.h"
#include "unzip.h"

namespace {
/* the untrusted bundle is staged to this fixed name inside destDir and
 * removed again on every exit path; nothing attacker-controlled reaches the
 * final file system state */
const char * const CLOUD_ZIP_STAGE_NAME = "bundle.tmp";
/* stack-sized chunk fed through unzReadCurrentFile */
constexpr uint32_t CLOUD_ZIP_READ_CHUNK = 4096;
/* member-name buffer: whitelist entries are short file names, so a central
 * directory entry longer than this can never match the exact whitelist
 * comparison (a truncated copy just fails strcmp) */
constexpr uint32_t CLOUD_ZIP_NAME_BUF_LEN = 512;

/*
 * Extract the currently positioned member (already whitelist-matched) into
 * destPath, enforcing the member cap on both the declared size and the
 * bytes actually streamed: a hostile header may lie about uncompressed_size.
 * CMR codes only; a failed call leaves no target file behind.
 */
int32_t CmExtractCurrentMember(unzFile archive, uLong memberSize, const std::string &destPath)
{
    if (memberSize > CM_CLOUD_ZIP_MAX_MEMBER_SIZE) {
        CM_LOG_E("cloud zip member too large, size = %lu", static_cast<unsigned long>(memberSize));
        return CMR_ERROR;
    }
    if (unzOpenCurrentFile(archive) != UNZ_OK) {
        CM_LOG_E("open cloud zip member failed");
        return CMR_ERROR;
    }

    FILE *out = fopen(destPath.c_str(), "wb");
    if (out == nullptr) {
        CM_LOG_E("open cloud zip member target file failed");
        (void)unzCloseCurrentFile(archive);
        return CMR_ERROR;
    }

    int32_t ret = CM_SUCCESS;
    char chunk[CLOUD_ZIP_READ_CHUNK] = { 0 };
    uint32_t totalLen = 0;
    while (true) {
        int readLen = unzReadCurrentFile(archive, chunk, sizeof(chunk));
        if (readLen < 0) {
            /* decompression or CRC failure inside the member data */
            CM_LOG_E("read cloud zip member failed, readLen = %d", readLen);
            ret = CMR_ERROR;
            break;
        }
        if (readLen == 0) {
            break; /* member fully consumed */
        }
        totalLen += static_cast<uint32_t>(readLen);
        if (totalLen > CM_CLOUD_ZIP_MAX_MEMBER_SIZE) {
            /* the declared size can lie: enforce the cap on real bytes too */
            CM_LOG_E("cloud zip member exceeded the member cap while streaming");
            ret = CMR_ERROR;
            break;
        }
        if (fwrite(chunk, 1, static_cast<size_t>(readLen), out) != static_cast<size_t>(readLen)) {
            CM_LOG_E("write cloud zip member target file failed");
            ret = CMR_ERROR;
            break;
        }
    }

    /* minizip verifies the member CRC here; both handles close exactly once
     * whatever the outcome was */
    int closeMember = unzCloseCurrentFile(archive);
    int closeOut = fclose(out);
    if (ret == CM_SUCCESS) {
        if (closeMember != UNZ_OK) {
            CM_LOG_E("cloud zip member crc check failed, ret = %d", closeMember);
            ret = CMR_ERROR;
        } else if (closeOut != 0) {
            CM_LOG_E("close cloud zip member target file failed");
            ret = CMR_ERROR;
        }
    }
    if (ret != CM_SUCCESS) {
        (void)remove(destPath.c_str());
        return ret;
    }

    /* readable for every consumer of the policy dir, no exec bits */
    if (chmod(destPath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
        CM_LOG_E("chmod cloud zip member target file failed");
        (void)remove(destPath.c_str());
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}

/*
 * Walk the archive entries and extract the one byte-for-byte equal to
 * memberName; nothing else is ever opened or written. CMR codes only.
 */
int32_t CmExtractWhitelistedMember(unzFile archive, const char *memberName, const std::string &destPath)
{
    char nameBuf[CLOUD_ZIP_NAME_BUF_LEN] = { 0 };
    int err = unzGoToFirstFile(archive);
    while (err == UNZ_OK) {
        unz_file_info info = { 0 };
        nameBuf[0] = '\0';
        if (unzGetCurrentFileInfo(archive, &info, nameBuf, sizeof(nameBuf), nullptr, 0,
            nullptr, 0) != UNZ_OK) {
            CM_LOG_E("read cloud zip entry info failed");
            return CMR_ERROR;
        }
        /* exact-name whitelist match: path-carrying entries ("../evil",
         * "sub/dir/f") simply never equal the plain file name */
        if (strcmp(nameBuf, memberName) == 0) {
            return CmExtractCurrentMember(archive, info.uncompressed_size, destPath);
        }
        err = unzGoToNextFile(archive);
    }
    return CMR_ERROR;
}
} // namespace

int32_t CmCloudZipExtractWhitelisted(const struct CmBlob *zipData,
    const char *memberName, const char *destDir)
{
    if ((CmCheckBlob(zipData) != CM_SUCCESS) || (memberName == nullptr) || (memberName[0] == '\0') ||
        (destDir == nullptr) || (destDir[0] == '\0')) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* the whitelist entry must itself be a plain file name so destDir plus
     * memberName stays inside destDir for whatever the caller passes */
    if (strchr(memberName, '/') != nullptr) {
        CM_LOG_E("cloud zip member name must be a plain file name");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (zipData->size > CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE) {
        CM_LOG_E("cloud zip bundle too large, size = %u", zipData->size);
        return CMR_ERROR;
    }

    /* stage the bundle to a fixed temp name; this tree's minizip has no
     * unzOpenBuffer, so the archive must be read from a file */
    std::string stagePath = std::string(destDir) + "/" + CLOUD_ZIP_STAGE_NAME;
    FILE *stage = fopen(stagePath.c_str(), "wb");
    if (stage == nullptr) {
        CM_LOG_E("open cloud zip stage file failed");
        return CMR_ERROR;
    }
    size_t written = fwrite(zipData->data, 1, zipData->size, stage);
    int closeStage = fclose(stage);
    if ((written != zipData->size) || (closeStage != 0)) {
        CM_LOG_E("write cloud zip stage file failed");
        (void)remove(stagePath.c_str());
        return CMR_ERROR;
    }

    unzFile archive = unzOpen(stagePath.c_str());
    if (archive == nullptr) {
        CM_LOG_E("open cloud zip bundle failed");
        (void)remove(stagePath.c_str());
        return CMR_ERROR;
    }

    int32_t ret = CmExtractWhitelistedMember(archive, memberName,
        std::string(destDir) + "/" + memberName);
    unzClose(archive);
    (void)remove(stagePath.c_str());
    return ret;
}
