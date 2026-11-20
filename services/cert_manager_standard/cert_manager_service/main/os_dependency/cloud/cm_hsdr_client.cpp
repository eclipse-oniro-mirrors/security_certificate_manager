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

#include "cm_hsdr_client.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>

#include "ability_connect_callback_stub.h"
#include "errors.h"
#include "extension_manager_client.h"
#include "ipc_skeleton.h"
#include "message_option.h"
#include "want.h"

#include "cm_log.h"

/* the connection skeleton types (sptr, AAFwk, IPCSkeleton, ...) live in
 * namespace OHOS; the cm_response.cpp / hisysevent_wrapper.cpp pattern for
 * a free-function TU: a file-scope using-directive, confined to this TU */
using namespace OHOS;

namespace {
/*
 * The HSDR service connection object: the ability manager reports the
 * asynchronous connect result into OnAbilityConnectDone, so the fetch
 * thread parks on the condition variable until that callback (or the
 * timeout) releases it. A late callback after the fetch ended only sets
 * the flag again; it cannot touch anything in flight.
 */
class CmHsdrConnection : public AAFwk::AbilityConnectionStub {
public:
    CmHsdrConnection() = default;
    ~CmHsdrConnection() override = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int resultCode) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        remote_ = remoteObject;
        resultCode_ = resultCode;
        connected_ = true;
        cond_.notify_all();
    }

    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
        int resultCode) override
    {
        /* a mid-request service death surfaces as the SendRequest failing
         * on the fetch thread; nothing to do here beyond leaving a trace */
        CM_LOG_I("hsdr service disconnected");
    }

    /*
     * Block until OnAbilityConnectDone reports a live remote, or timeoutMs
     * passes. nullptr when the wait timed out or the callback carried an
     * error code or no remote object.
     */
    sptr<IRemoteObject> WaitForConnect(uint32_t timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        bool connected = cond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this] { return connected_; });
        if (!connected || (resultCode_ != ERR_OK) || (remote_ == nullptr)) {
            return nullptr;
        }
        return remote_;
    }

private:
    std::mutex mutex_;
    std::condition_variable cond_;
    sptr<IRemoteObject> remote_;
    int resultCode_ = -1;
    bool connected_ = false;
};

/* tear the connection down; errors such as already disconnected (service
 * dead / never connected) are safe to ignore, the dialog pattern */
void DisconnectHsdr(const sptr<IRemoteObject> &connObject)
{
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(connObject);
    if (ret != ERR_OK) {
        CM_LOG_W("disconnect hsdr service ret: %d", ret);
    }
}

/*
 * Park until the service's asynchronous callback lands in the stub, then
 * collect its outcome: the wait window, the callback's own verdict and
 * the blob handover each have their failure branch; every one of them
 * logs a CM_LOG_E line, because the stub itself stays silent.
 */
int32_t AwaitHsdrCallback(const CloudResourceScene &scene,
    const sptr<CmHsdrCallbackStub> &callback, struct CmBlob &zipOut)
{
    /* the service answers asynchronously: park until its callback lands
     * in the stub or the wait window closes */
    if (!callback->WaitForResult(CM_HSDR_CALLBACK_TIMEOUT_MS)) {
        /* nothing can hand the result out anymore, so the stub is
         * abandoned first; a late callback is then parsed and discarded
         * by the stub itself */
        callback->Abandon();
        CM_LOG_E("hsdr fetch failed: callback wait timed out after %u ms, scene %s cmd %u",
            CM_HSDR_CALLBACK_TIMEOUT_MS, scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    int32_t ret = callback->GetResult();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("hsdr fetch failed: callback rejected the reply, ret = %d, scene %s cmd %u",
            ret, scene.bundleName, scene.cmdId);
        return ret;
    }
    if (!callback->TakeZipBlob(zipOut)) {
        /* result was success but no blob moved: a defensive refusal, the
         * stub contract guarantees a blob on a successful result */
        CM_LOG_E("hsdr fetch failed: callback delivered no zip blob, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    return CM_SUCCESS;
}

/*
 * One request over the connected remote: build the proxy (its descriptor
 * is the fixed OHOS.Security.HSDR identity the service's permission
 * check keys on, and iface_cast refuses a remote that does not answer
 * with that descriptor), forward the scene request with the callback
 * stub riding inside the parcel, then wait for the service's callback
 * to land in the stub. The proxy has logged its own CM_LOG_E lines, so
 * this helper only adds the callback outcomes of its own.
 */
int32_t SendHsdrRequest(const CloudResourceScene &scene, const sptr<IRemoteObject> &remote,
    struct CmBlob &zipOut)
{
    sptr<CmHsdrCallbackStub> callback = new CmHsdrCallbackStub(scene);
    if ((callback == nullptr) || (callback->AsObject() == nullptr)) {
        CM_LOG_E("hsdr fetch failed: no callback object, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    sptr<CmHsdrInterface> proxy = iface_cast<CmHsdrInterface>(remote);
    if (proxy == nullptr) {
        CM_LOG_E("hsdr fetch failed: remote is not the hsdr service, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }
    int32_t ret = proxy->InvokeHsdrAsync(scene, callback->AsObject());
    if (ret != CM_SUCCESS) {
        return ret;
    }
    return AwaitHsdrCallback(scene, callback, zipOut);
}
} // namespace

int32_t CmHsdrFetchCloudZip(const CloudResourceScene &scene, struct CmBlob &zipOut)
{
    if ((scene.bundleName == nullptr) || (scene.abilityName == nullptr)) {
        CM_LOG_E("hsdr fetch rejected: scene without bundle or ability name, cmd %u", scene.cmdId);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    AAFwk::Want want;
    want.SetElementName(scene.bundleName, scene.abilityName);
    sptr<CmHsdrConnection> conn = new CmHsdrConnection();
    if ((conn == nullptr) || (conn->AsObject() == nullptr)) {
        CM_LOG_E("hsdr fetch failed: no connection object, scene %s cmd %u",
            scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    /* connect under the SA identity, the dialog launcher pattern */
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, conn->AsObject(), nullptr, -1);
    IPCSkeleton::SetCallingIdentity(identity);
    if (ret != ERR_OK) {
        /* the connect call itself failed: nothing was connected, so there
         * is nothing to disconnect */
        CM_LOG_E("hsdr fetch failed: connect ret = %d, scene %s cmd %u",
            ret, scene.bundleName, scene.cmdId);
        return CMR_ERROR;
    }

    sptr<IRemoteObject> remote = conn->WaitForConnect(CM_HSDR_CONNECT_TIMEOUT_MS);
    if (remote == nullptr) {
        CM_LOG_E("hsdr fetch failed: connect wait failed or timed out after %u ms, scene %s cmd %u",
            CM_HSDR_CONNECT_TIMEOUT_MS, scene.bundleName, scene.cmdId);
        DisconnectHsdr(conn->AsObject());
        return CMR_ERROR;
    }

    ret = SendHsdrRequest(scene, remote, zipOut);
    /* the connection is torn down no matter how the request ended */
    DisconnectHsdr(conn->AsObject());
    return ret;
}
