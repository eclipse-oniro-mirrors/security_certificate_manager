/**
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

#include "cmsystemdialogconnection_fuzzer.h"

#include <cstdint>
#include <string>

#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_system_dialog_connection.h"
#include "securec.h"

using namespace CmFuzzTest;

/* mocks live in the CertManager namespace (like the unit-test doubles) so the
 * OHOS-scoped IPC/sptr types resolve without qualification */
namespace OHOS::Security::CertManager {
namespace {
    const uint32_t UINT32_COUNT = 4;

    /* action bit assignments of the fuzz input selector byte */
    const uint8_t ACTION_NULL_REMOTE = 0x01;
    const uint8_t ACTION_CONNECT_DONE = 0x02;
    const uint8_t ACTION_RELEASE_WINDOW = 0x04;
    const uint8_t ACTION_CONNECT_DONE_AFTER_RELEASE = 0x08;
    const uint8_t ACTION_DISCONNECT_DONE = 0x10;
    const uint8_t ACTION_SCRUB_PARAMS = 0x20;
    const uint8_t ACTION_REAL_LAUNCHER = 0x40;
    const uint8_t ACTION_REAL_LAUNCHER_NULL_CONN = 0x80;

    /* two leading selector bytes: actionBits + sendRetSel */
    const uint32_t SELECTOR_COUNT = 2;
    const uint32_t SEND_RET_SELECTOR_COUNT = 2;

    /* dialog service send result: 0 = start command delivered, non-zero folds
     * into the OnDialogDisconnected failure branch */
    int32_t g_dialogSendRet = 0;

    class CmFuzzDialogBroker : public IRemoteBroker {
    public:
        DECLARE_INTERFACE_DESCRIPTOR(u"cm.fuzz.dialogservice");
    };

    /* local stand-in of the system dialog service: SendRequest lands here
     * directly and returns the fuzz-selected result code */
    class FuzzDialogRemote : public IRemoteStub<CmFuzzDialogBroker> {
    public:
        int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) override
        {
            return g_dialogSendRet;
        }
    };

    /* constructed before main: never a dangling global pointer */
    sptr<FuzzDialogRemote> g_fakeDialogRemote = new (std::nothrow) FuzzDialogRemote();

    /* parsed fuzz input; owned pointers are freed by FreeSystemDialogInput */
    struct SystemDialogInput {
        uint8_t actionBits = 0;
        uint8_t sendRetSel = 0;
        uint32_t resultCode = 0;
        char *requestId = nullptr;
        char *bundle = nullptr;
        char *ability = nullptr;
        char *paramsJson = nullptr;
    };

    void FreeSystemDialogInput(struct SystemDialogInput *in)
    {
        delete[] in->requestId;
        delete[] in->bundle;
        delete[] in->ability;
        delete[] in->paramsJson;
        in->requestId = nullptr;
        in->bundle = nullptr;
        in->ability = nullptr;
        in->paramsJson = nullptr;
    }

    /* layout: [actionBits byte][sendRetSel byte][resultCode u32]
     * [requestId string][bundle string][ability string][paramsJson string] */
    bool ParseSystemDialogInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct SystemDialogInput *in)
    {
        if (*remainSize >= SELECTOR_COUNT * sizeof(uint8_t)) {
            in->actionBits = myData[*offset];
            in->sendRetSel = myData[*offset + 1];
            *offset += SELECTOR_COUNT * sizeof(uint8_t);
            *remainSize -= SELECTOR_COUNT * sizeof(uint8_t);
        }
        g_dialogSendRet = (in->sendRetSel % SEND_RET_SELECTOR_COUNT != 0) ? -1 : 0;

        if (!GetUintFromBuffer(myData, remainSize, offset, &in->resultCode)) {
            return false;
        }
        return GetDynamicStringFromBuffer(myData, remainSize, offset, &in->requestId) &&
            GetDynamicStringFromBuffer(myData, remainSize, offset, &in->bundle) &&
            GetDynamicStringFromBuffer(myData, remainSize, offset, &in->ability) &&
            GetDynamicStringFromBuffer(myData, remainSize, offset, &in->paramsJson);
    }

    bool RunSystemDialogActions(const struct SystemDialogInput &in)
    {
        sptr<CmSystemDialogConnection> connection = new (std::nothrow) CmSystemDialogConnection(
            in.requestId, in.bundle, in.ability, in.paramsJson);
        if (connection == nullptr) {
            return false;
        }

        AppExecFwk::ElementName element("", in.bundle, in.ability);
        /* null remote covers the "dialog service remote object is null" branch */
        sptr<IRemoteObject> remote = ((in.actionBits & ACTION_NULL_REMOTE) != 0)
            ? nullptr : g_fakeDialogRemote;

        if ((in.actionBits & ACTION_CONNECT_DONE) != 0) {
            connection->OnAbilityConnectDone(element, remote, static_cast<int32_t>(in.resultCode));
        }
        if ((in.actionBits & ACTION_RELEASE_WINDOW) != 0) {
            connection->ReleaseWindow(remote);
        }
        if ((in.actionBits & ACTION_CONNECT_DONE_AFTER_RELEASE) != 0) {
            /* late callback after release: the released_ guard branch (R8) */
            connection->OnAbilityConnectDone(element, remote, static_cast<int32_t>(in.resultCode));
        }
        if ((in.actionBits & ACTION_DISCONNECT_DONE) != 0) {
            connection->OnAbilityDisconnectDone(element, static_cast<int32_t>(in.resultCode));
        }
        if ((in.actionBits & ACTION_SCRUB_PARAMS) != 0) {
            connection->ScrubParams();
        }
        if ((in.actionBits & ACTION_REAL_LAUNCHER) != 0) {
            /* real launcher: without a live ability manager the connect call
             * takes the failure path (still exercises the null-conn precheck first) */
            RealSystemDialogLauncher launcher;
            (void)launcher.Connect(connection);
            launcher.Disconnect(connection);
        }
        if ((in.actionBits & ACTION_REAL_LAUNCHER_NULL_CONN) != 0) {
            RealSystemDialogLauncher launcher;
            (void)launcher.Connect(nullptr);
            launcher.Disconnect(nullptr);
        }
        return true;
    }
} // namespace

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct SystemDialogInput in = {};

        bool parsed = ParseSystemDialogInput(myData, &remainSize, &offset, &in);
        bool dispatched = false;
        if (parsed) {
            dispatched = RunSystemDialogActions(in);
        }

        FreeSystemDialogInput(&in);
        CmFree(myData);
        return parsed && dispatched;
    }
} // namespace OHOS::Security::CertManager

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Security::CertManager::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
