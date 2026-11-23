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
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <sys/types.h>
#include <unistd.h>

#include "errors.h"
#include "message_option.h"
#include "securec.h"

#include "cm_cloud_zip.h"
#include "cm_log.h"
#include "cm_mem.h"

namespace {
/* read step of the fd-to-blob loop: a stack-sized chunk keeps the loop
 * bounded per iteration regardless of what the hostile fd reports */
constexpr size_t CM_HSDR_READ_CHUNK = 16 * 1024;

/*
 * Chunked read to EOF into bytes; the cap stops a hostile answer from
 * turning a small reply into unbounded memory. The caller owns the fd.
 */
int32_t ReadZipBytes(int32_t fd, const CloudResourceScene &scene, std::string &bytes)
{
    char chunk[CM_HSDR_READ_CHUNK] = { 0 };
    ssize_t readLen = read(fd, chunk, sizeof(chunk));
    while ((readLen > 0) || ((readLen < 0) && (errno == EINTR))) {
        if (readLen > 0) {
            bytes.append(chunk, static_cast<size_t>(readLen));
            if (bytes.size() > CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE) {
                CM_LOG_E("hsdr reply rejected: zip over the archive cap, size = %lu, scene %s cmd %u",
                    static_cast<unsigned long>(bytes.size()), scene.bundleName, scene.cmdId);
                return CMR_ERROR;
            }
        }
        readLen = read(fd, chunk, sizeof(chunk));
    }
    if (readLen < 0) {
        CM_LOG_E("hsdr reply rejected: zip fd read failed, errno = 0x%x, scene %s cmd %u",
            errno, scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}
} // namespace

CmHsdrProxy::CmHsdrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<CmHsdrInterface>(impl) {}

int32_t CmHsdrProxy::InvokeHsdrAsync(const CloudResourceScene &scene, const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option; /* the transport ack stays synchronous; the
                           * authoritative result arrives through the
                           * callback, so the immediate reply carries
                           * nothing this request reads */
    /* the interface token is this proxy's own descriptor, never a
     * runtime-queried value: the service's permission check keys on the
     * fixed OHOS.Security.HSDR identity */
    if (!data.WriteInterfaceToken(GetDescriptor())) {
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
    if (callback == nullptr) {
        CM_LOG_E("hsdr request pack failed: no callback object, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        CM_LOG_E("hsdr request pack failed: callback object rejected, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    int32_t ret = Remote()->SendRequest(scene.cmdId, data, reply, option);
    if (ret != OHOS::ERR_OK) {
        CM_LOG_E("hsdr request send failed: ret = %d, scene %s cmd %u",
            ret, scene.bundleName, scene.cmdId);
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
    int32_t readRet = ReadZipBytes(fd, scene, bytes);
    /* the fd is a dup handed to this reader: closed on every path above
     * and here, so nothing leaks whatever the reply carried */
    close(fd);
    if (readRet != CM_SUCCESS) {
        return readRet;
    }

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

CmHsdrCallbackStub::CmHsdrCallbackStub(const CloudResourceScene &scene) : scene_(scene) {}

CmHsdrCallbackStub::~CmHsdrCallbackStub()
{
    /* the destructor is the last resort: whatever the fetch thread did,
     * a blob still held here was never taken and must not leak */
    CM_FREE_BLOB(zipBlob_);
}

void CmHsdrCallbackStub::Abandon(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    abandoned_ = true;
    /* wake a WaitForResult still parked so it observes the abandonment */
    cond_.notify_all();
}

bool CmHsdrCallbackStub::WaitForResult(uint32_t timeoutMs)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return cond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
        [this] { return resultReady_ || abandoned_; });
}

bool CmHsdrCallbackStub::HasResult(void) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return resultReady_;
}

int32_t CmHsdrCallbackStub::GetResult(void) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return result_;
}

bool CmHsdrCallbackStub::TakeZipBlob(struct CmBlob &zipOut)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!resultReady_ || (zipBlob_.data == nullptr)) {
        return false;
    }
    zipOut.data = zipBlob_.data;
    zipOut.size = zipBlob_.size;
    zipBlob_.data = nullptr;
    zipBlob_.size = 0;
    return true;
}

int32_t CmHsdrCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    (void)code;
    (void)reply;
    (void)option;
    /* parse first, outside the lock: the layout is the synchronous reply
     * layout, and every path through CmHsdrParseReply closes the fd, so
     * the parcel is fully consumed whatever happens next */
    struct CmBlob zipOut = { 0, nullptr };
    int32_t ret = CmHsdrParseReply(data, GetDescriptor(), scene_, zipOut);
    std::lock_guard<std::mutex> lock(mutex_);
    if (abandoned_) {
        /* the fetch thread gave up before this callback landed: the
         * result and the blob (if any) are discarded, never handed out */
        CM_LOG_I("hsdr callback dropped: fetch already abandoned, ret = %d, scene %s cmd %u",
            ret, scene_.bundleName, scene_.cmdId);
        CM_FREE_BLOB(zipOut);
        return ret;
    }
    result_ = ret;
    resultReady_ = true;
    if (ret == CM_SUCCESS) {
        zipBlob_ = zipOut;
    }
    cond_.notify_all();
    return ret;
}
