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

#include "cm_hsdr_protocol.h"

#include <cerrno>
#include <cstddef>
#include <string>
#include <sys/types.h>
#include <unistd.h>

#include "securec.h"

#include "cm_cloud_zip.h"
#include "cm_log.h"
#include "cm_mem.h"

namespace {
/* read step of the fd-to-blob loop: a stack-sized chunk keeps the loop
 * bounded per iteration regardless of what the hostile fd reports */
constexpr size_t CM_HSDR_READ_CHUNK = 16 * 1024;
} // namespace

int32_t CmHsdrPackRequest(MessageParcel &data, const std::u16string &token,
    const CloudResourceScene &scene)
{
    if (!data.WriteInterfaceToken(token)) {
        CM_LOG_E("hsdr request pack failed: interface token rejected, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    if (!data.WriteString16(std::u16string(scene.callerParam))) {
        CM_LOG_E("hsdr request pack failed: caller param rejected, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    if (!data.WriteString16(std::u16string(scene.resourceParam))) {
        CM_LOG_E("hsdr request pack failed: resource param rejected, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}

int32_t CmHsdrParseReply(MessageParcel &reply, const std::u16string &token,
    const CloudResourceScene &scene, struct CmBlob &zipOut)
{
    std::u16string replyToken = reply.ReadInterfaceToken();
    if (replyToken != token) {
        CM_LOG_E("hsdr reply rejected: interface token mismatch, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    int32_t result = reply.ReadInt32();
    if (result != 0) {
        CM_LOG_E("hsdr reply rejected: result code %d, scene %s cmd %u",
            result, scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    int32_t fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        CM_LOG_E("hsdr reply rejected: no zip fd in reply, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    /* chunked read to EOF; the cap stops a hostile answer from turning a
     * small reply into unbounded memory */
    std::string bytes;
    char chunk[CM_HSDR_READ_CHUNK] = { 0 };
    while (true) {
        ssize_t readLen = read(fd, chunk, sizeof(chunk));
        if (readLen < 0) {
            if (errno == EINTR) {
                continue;
            }
            CM_LOG_E("hsdr reply rejected: zip fd read failed, errno = 0x%x, scene %s cmd %u",
                errno, scene.bundleName, scene.cmdId);
            close(fd);
            return CMR_ERROR;
        }
        if (readLen == 0) {
            break;
        }
        bytes.append(chunk, static_cast<size_t>(readLen));
        if (bytes.size() > CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE) {
            CM_LOG_E("hsdr reply rejected: zip over the archive cap, size = %lu, scene %s cmd %u",
                static_cast<unsigned long>(bytes.size()), scene.bundleName, scene.cmdId);
            close(fd);
            return CMR_ERROR;
        }
    }
    /* the fd is a dup handed to this reader: closed on every path above
     * and here, so nothing leaks whatever the reply carried */
    close(fd);

    if (bytes.empty()) {
        CM_LOG_E("hsdr reply rejected: zip is empty, scene %s cmd %u", scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    /* the blob carries the real length only; the only CmMalloc happens
     * after every rejection point, so a failed call leaves nothing
     * allocated and the blob untouched */
    uint32_t zipSize = static_cast<uint32_t>(bytes.size());
    uint8_t *blobData = static_cast<uint8_t *>(CmMalloc(zipSize));
    if (blobData == nullptr) {
        CM_LOG_E("hsdr reply rejected: blob malloc failed, size = %lu, scene %s cmd %u",
            static_cast<unsigned long>(zipSize), scene.bundleName, scene.cmdId);
        return CMR_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(blobData, zipSize, bytes.data(), zipSize) != EOK) {
        CM_LOG_E("hsdr reply rejected: blob copy failed, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        CmFree(blobData);
        return CMR_ERROR;
    }
    zipOut.data = blobData;
    zipOut.size = zipSize;
    return CM_SUCCESS;
}
