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

#ifndef CM_HSDR_PROTOCOL_H
#define CM_HSDR_PROTOCOL_H

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <sys/stat.h>

#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "message_parcel.h"

#include "cm_cloud_policy_store.h"
#include "cm_type.h"

/* the HSDR requests and replies walk OHOS::MessageParcel; the
 * using-declaration keeps the pack/parse signatures below on the plain
 * MessageParcel name while this header stays a free-function module; the
 * callback stub below needs the same treatment for its IPC base and
 * parcel types */
using OHOS::BrokerDelegator;
using OHOS::IRemoteBroker;
using OHOS::IRemoteObject;
using OHOS::IRemoteProxy;
using OHOS::IRemoteStub;
using OHOS::MessageOption;
using OHOS::MessageParcel;
using OHOS::iface_cast;
using OHOS::sptr;

/*
 * One cloud-push scene: the external service to connect to, the command to
 * send over it, and where the resource inside the answer lands. A
 * compile-time table entry (the only instance today is CLOUD_POLICY_SCENE
 * below); a new cloud-push scenario adds an entry and reuses the generic
 * client unchanged.
 */
struct CloudResourceScene {
    const char *bundleName;              /* "com.huawei.hmos.hsdr" */
    const char *abilityName;            /* "HSDRService" */
    uint32_t cmdId;                      /* 4 */
    std::u16string_view callerParam;    /* u"com.huawei.certmanager" */
    std::u16string_view resourceParam;  /* u"certRevocationPolicy" */
    const char *zipMember;               /* CM_CLOUD_POLICY_FILE_NAME (extraction whitelist) */
    const char *destDir;                 /* FORCE_CHECK_POLICY_DIR (publish target directory) */
    const char *destFile;                /* CM_CLOUD_POLICY_FILE_NAME (published file name) */
    mode_t destMode;                     /* 0644 */
};

/* the certificate revocation policy cloud-push scene, the requirement
 * spec's scene table verbatim; defined inline here so no consumer has to
 * link a scene-table translation unit */
inline constexpr CloudResourceScene CLOUD_POLICY_SCENE {
    "com.huawei.hmos.hsdr",
    "HSDRService",
    4,
    u"com.huawei.certmanager",
    u"certRevocationPolicy",
    CM_CLOUD_POLICY_FILE_NAME,
    FORCE_CHECK_POLICY_DIR,
    CM_CLOUD_POLICY_FILE_NAME,
    0644,
};

/*
 * The HSDR service-side interface the proxy talks to: the descriptor is
 * the fixed service identity, the value the service's permission check
 * (ohos.permission.hsdr.REQUEST_HSDR) keys on.
 */
class CmHsdrInterface : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.HSDR");

    /*
     * Forward one scene request with the reply callback; see the proxy
     * for the parcel layout and the return contract.
     */
    virtual int32_t InvokeHsdrAsync(const CloudResourceScene &scene,
        const sptr<IRemoteObject> &callback) = 0;
};

/*
 * The asynchronous request proxy: one InvokeHsdrAsync call packs the
 * request parcel -- the interface token is the proxy's own descriptor
 * (OHOS.Security.HSDR), then the scene's two u16 parameters, then the
 * callback remote object the service answers through -- and forwards it
 * with the scene's cmdId over the connected remote. The token must be
 * the proxy's own GetDescriptor(), never a runtime-queried value: the
 * service's permission check keys on that fixed identity, which is what
 * makes the SA cfg's requested permission effective.
 *
 * The return value is the transport status only; the authoritative
 * result arrives asynchronously through the callback object carried in
 * the parcel.
 */
class CmHsdrProxy : public IRemoteProxy<CmHsdrInterface> {
public:
    explicit CmHsdrProxy(const sptr<IRemoteObject> &impl);
    ~CmHsdrProxy() override = default;

    /*
     * Forward one scene request with the reply callback.
     *
     * @param scene the cloud-push scene whose parameters and cmdId ride
     *        the request
     * @param callback the callback stub's remote object appended as the
     *        reply channel; a null callback is refused, nothing is sent
     * @return CM_SUCCESS when the request was forwarded; CMR_ERROR on
     *         any parcel write failure or a failed send
     */
    int32_t InvokeHsdrAsync(const CloudResourceScene &scene,
        const sptr<IRemoteObject> &callback) override;

private:
    static inline BrokerDelegator<CmHsdrProxy> delegator_;
};

/*
 * Parse one HSDR reply: interface token, execution result, then the zip
 * file descriptor, whose whole content is read into zipOut.
 *
 * The reply comes from an external cloud-facing service and is validated
 * before any byte is accepted: the token must equal the request token, the
 * result code must be 0, the fd must exist, and the zip read is capped at
 * CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE so a hostile answer cannot turn a small
 * reply into unbounded memory. The fd (a dup handed to this reader) is
 * closed on every path. Every rejection logs one CM_LOG_E line carrying
 * the cmdId and the scene bundle name.
 *
 * zipOut must arrive zeroed; it is assigned only on success, so a failed
 * call leaves nothing to free and no half-filled blob behind. On success
 * zipOut.data is CmMalloc'd and the caller releases it with CM_FREE_BLOB.
 *
 * @param reply the reply parcel to consume
 * @param token the interface token the reply must carry
 * @param scene the scene (cmdId and bundle name for the diagnostics)
 * @param zipOut receives the archive bytes on success
 * @return CM_SUCCESS; CMR_ERROR on a token mismatch, a non-zero result
 *         code, a missing fd, a read failure or an oversized or empty
 *         zip; CMR_ERROR_MALLOC_FAIL when the blob cannot be allocated
 */
int32_t CmHsdrParseReply(MessageParcel &reply, const std::u16string &token,
    const CloudResourceScene &scene, struct CmBlob &zipOut);

/*
 * The broker type behind the HSDR callback stub: the descriptor the
 * service's callback parcel must carry, the HSDR client family's shared
 * convention (the telephony HSDR helpers use the same descriptor).
 */
class CmHsdrCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.CloudConnectCallback");
};

/*
 * The asynchronous reply endpoint: one stub instance rides inside one
 * request parcel, and the service's callback lands in OnRemoteRequest.
 * The callback parcel layout is the synchronous reply layout unchanged
 * (interface token, result code, zip fd), so CmHsdrParseReply does the
 * parsing and this class only manages the result handover.
 *
 * Lifecycle contract with the fetch thread:
 * - the fetch thread creates the stub, packs it, sends, then waits on
 *   WaitForResult; TakeZipBlob moves the blob out once, on success
 * - a fetch that gives up (timeout or send failure) calls Abandon first;
 *   a callback that lands afterwards is parsed in full (the fd is still
 *   consumed and closed) but its result and blob are discarded
 * - the mutex + result-ready flag make every interleaving safe: the
 *   callback thread and the fetch thread never touch the blob slots at
 *   the same time, and a late callback can only fill already-abandoned
 *   slots, never in-flight ones
 */
class CmHsdrCallbackStub : public IRemoteStub<CmHsdrCallback> {
public:
    explicit CmHsdrCallbackStub(const CloudResourceScene &scene);
    ~CmHsdrCallbackStub() override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

    /* the fetch thread gave up: mark the stub dead for results */
    void Abandon(void);

    /* block until the callback arrived or timeoutMs passed; false means
     * no callback arrived in the window */
    bool WaitForResult(uint32_t timeoutMs);

    /* whether a (non-abandoned) result has arrived */
    bool HasResult(void) const;

    /* the callback's outcome: CM_SUCCESS only when the callback carried
     * result 0 and the zip fd parsed into the blob slot */
    int32_t GetResult(void) const;

    /* move the parsed blob out; false when there is no blob to take */
    bool TakeZipBlob(struct CmBlob &zipOut);

private:
    CloudResourceScene scene_;
    /* mutable: the const observers (HasResult/GetResult) lock it too */
    mutable std::mutex mutex_;
    std::condition_variable cond_;
    bool abandoned_ = false;
    bool resultReady_ = false;
    int32_t result_ = CMR_ERROR;
    struct CmBlob zipBlob_ = { 0, nullptr };
};

#endif /* CM_HSDR_PROTOCOL_H */
