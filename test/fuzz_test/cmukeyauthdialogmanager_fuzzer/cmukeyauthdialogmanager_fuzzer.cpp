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

#include "cmukeyauthdialogmanager_fuzzer.h"

#include <cstdint>
#include <cstring>
#include <string>

#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_system_dialog_connection.h"
#include "cm_type.h"
#include "cm_ukey_ability_type.h"
#include "cm_ukey_auth_dialog_manager.h"
#include "securec.h"

using namespace CmFuzzTest;

/* mocks live in the CertManager namespace (like the unit-test doubles) so the
 * OHOS-scoped IPC/sptr types resolve without qualification */
namespace OHOS::Security::CertManager {
namespace {
    const uint32_t UINT32_COUNT = 4;
    const char *DRIVER_BUNDLE = "com.example.ukeydrv";
    const char *DRIVER_ABILITY = "DrvUIExtAbility";

    /* mock timer profile: small values so the dialog / keep-alive timers
     * fire inside a single fuzz input despite no real UI behind them */
    const int32_t DIALOG_TIMEOUT_MIN_SEC = 2;
    const int32_t DIALOG_TIMEOUT_DEFAULT_SEC = 3;
    const int32_t DIALOG_TIMEOUT_MAX_SEC = 5;
    const int32_t DIALOG_TIMER_GRACE_MS = 100;
    const int32_t DIALOG_KEEPALIVE_INTERVAL_MS = 50;

    /* flag bit assignments of the fuzz input selector word */
    const uint32_t FLAG_PC_CHECKER_OK = 0x1;
    const uint32_t FLAG_DRIVER_ABILITY_OK = 0x2;
    const uint32_t FLAG_ABILITY_TYPE_SHIFT = 2;
    const uint32_t FLAG_LAUNCHER_FAIL_SHIFT = 4;
    const uint32_t FLAG_QUERIER_FAIL_SHIFT = 5;
    const uint32_t FLAG_SINGLE_BIT = 0x1;

    /* operation selector values (must stay below OP_COUNT = 9) */
    enum FuzzOp : uint8_t {
        OP_OPEN_DIALOG_PLAIN = 0,    /* OpenDialog without customData */
        OP_OPEN_DRIVER_DIALOG = 1,   /* OpenDriverDialog */
        OP_ON_REPORT_FUZZ_ID = 2,    /* OnReport with fuzz request id */
        OP_DISCONNECT_FUZZ_ID = 3,   /* OnDialogDisconnected with fuzz id */
        OP_CLIENT_DIED_FUZZ_ID = 4,  /* OnClientDied with fuzz id */
        OP_ON_REPORT_REAL_ID = 5,    /* OnReport with the live session id */
        OP_OPEN_DIALOG_CUSTOM = 6,   /* OpenDialog with customData */
        OP_OPEN_DIALOG_TIMER_FAIL = 7, /* OpenDialog with timer post failure */
        OP_DISCONNECT_REAL_ID = 8,   /* OnDialogDisconnected with live id */
    };
    const uint32_t OP_COUNT = 9;

    /* mock behavior knobs: written from the fuzz input before each dispatch,
     * read inside the injected fakes (always initialized, no dangling state) */
    int32_t g_querierRet = 0;
    uint32_t g_abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    bool g_pcOk = true;
    bool g_bmsOk = true;
    int32_t g_launcherRet = 0;
    bool g_envReady = false;

    class FuzzLauncher : public SystemDialogLauncher {
    public:
        int32_t Connect(const sptr<IAbilityConnection> &conn) override
        {
            return g_launcherRet;
        }
        void Disconnect(const sptr<IAbilityConnection> &conn) override {}
    };

    /* a minimal local broker so the fake callback is a real IRemoteStub
     * (pattern of cm_ukey_auth_dialog_manager_test.cpp) */
    class CmFuzzBroker : public IRemoteBroker {
    public:
        DECLARE_INTERFACE_DESCRIPTOR(u"cm.fuzz.dialog");
    };

    class FuzzClientCallback : public IRemoteStub<CmFuzzBroker> {
    public:
        int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
            MessageOption &option) override
        {
            return 0;
        }
    };

    void SetupDialogEnv(void)
    {
        if (g_envReady) {
            return;
        }
        auto manager = &CmUkeyAuthDialogManager::GetInstance();
        manager->SetLauncher(std::make_shared<FuzzLauncher>());
        manager->SetAbilityQuerier(
            [](const struct CmBlob *keyUri, std::string &bundleName, std::string &abilityName,
                uint32_t &abilityType, int32_t userId) -> int32_t {
                bundleName = DRIVER_BUNDLE;
                abilityName = DRIVER_ABILITY;
                abilityType = g_abilityType;
                return g_querierRet;
            });
        manager->SetPcChecker([]() -> bool { return g_pcOk; });
        manager->SetDriverAbilityChecker(
            [](const std::string &bundleName, const std::string &abilityName, int32_t userId) -> bool {
                return g_bmsOk;
            });
        manager->SetTimeoutRangeForTest(DIALOG_TIMEOUT_MIN_SEC, DIALOG_TIMEOUT_DEFAULT_SEC,
            DIALOG_TIMEOUT_MAX_SEC, DIALOG_TIMER_GRACE_MS);
        manager->SetKeepAliveIntervalForTest(DIALOG_KEEPALIVE_INTERVAL_MS); /* timers fire inside a run */
        manager->SetUnloadRenewal([]() {});
        manager->SetTimerPostFailForTest(false);
        g_envReady = true;
    }

    /* parsed fuzz input; owned pointers are freed by FreeUkeyDialogInput */
    struct UkeyDialogInput {
        uint8_t op = 0;
        uint32_t timeout = 0;
        uint32_t callerUid = 0;
        uint32_t userId = 0;
        uint32_t flags = 0;
        int32_t resultCode = 0;
        struct CmBlob keyUri = { 0, nullptr };
        struct CmBlob customData = { 0, nullptr };
        char *abilityName = nullptr;
        char *requestId = nullptr;
        char *bundle = nullptr;
    };

    void FreeUkeyDialogInput(struct UkeyDialogInput *in)
    {
        delete[] in->abilityName;
        delete[] in->requestId;
        delete[] in->bundle;
        in->abilityName = nullptr;
        in->requestId = nullptr;
        in->bundle = nullptr;
    }

    /* layout: [op byte][timeout u32][callerUid u32][userId u32][flags u32]
     * [resultCode u32][keyUriSize u32 + bytes][customSize u32 + bytes]
     * [abilityName string][requestId string][bundle string] */
    bool ParseUkeyDialogInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct UkeyDialogInput *in)
    {
        if (*remainSize >= sizeof(uint8_t)) {
            in->op = myData[*offset] % OP_COUNT;
            *offset += sizeof(uint8_t);
            *remainSize -= sizeof(uint8_t);
        }
        uint32_t resultCodeRaw = 0;
        if (!GetUintFromBuffer(myData, remainSize, offset, &in->timeout) ||
            !GetUintFromBuffer(myData, remainSize, offset, &in->callerUid) ||
            !GetUintFromBuffer(myData, remainSize, offset, &in->userId) ||
            !GetUintFromBuffer(myData, remainSize, offset, &in->flags) ||
            !GetUintFromBuffer(myData, remainSize, offset, &resultCodeRaw)) {
            return false;
        }
        /* dedicated result code: the JS protocol whitelist (29700001/2/3/6,
         * negative, unknown) must be reachable regardless of the flag bits */
        in->resultCode = static_cast<int32_t>(resultCodeRaw);

        /* keyUri blob: size is read from the data (0 = invalid-argument branch) */
        uint32_t keyUriSize = 0;
        if (!GetUintFromBuffer(myData, remainSize, offset, &keyUriSize)) {
            return false;
        }
        keyUriSize = keyUriSize % (MAX_LEN_URI + 1);
        if (keyUriSize > *remainSize) {
            keyUriSize = *remainSize;
        }
        in->keyUri = { keyUriSize, myData + *offset };
        *offset += keyUriSize;
        *remainSize -= keyUriSize;

        /* customData blob: cap keeps the >= max rejection branch reachable */
        uint32_t customSize = 0;
        if (!GetUintFromBuffer(myData, remainSize, offset, &customSize)) {
            return false;
        }
        customSize = customSize % (CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE + 1);
        if (customSize > *remainSize) {
            customSize = *remainSize;
        }
        in->customData = { customSize, myData + *offset };
        *offset += customSize;
        *remainSize -= customSize;

        return GetDynamicStringFromBuffer(myData, remainSize, offset, &in->abilityName) &&
            GetDynamicStringFromBuffer(myData, remainSize, offset, &in->requestId) &&
            GetDynamicStringFromBuffer(myData, remainSize, offset, &in->bundle);
    }

    /* retarget the injected fakes from the flag bits */
    void RetargetDialogMocks(uint32_t flags)
    {
        g_pcOk = (flags & FLAG_PC_CHECKER_OK) != 0;
        g_bmsOk = (flags & FLAG_DRIVER_ABILITY_OK) != 0;
        g_abilityType = ((flags >> FLAG_ABILITY_TYPE_SHIFT) & FLAG_SINGLE_BIT) != 0
            ? CM_UKEY_ABILITY_TYPE_UIEXTENSION : CM_UKEY_ABILITY_TYPE_UIABILITY;
        g_launcherRet = ((flags >> FLAG_LAUNCHER_FAIL_SHIFT) & FLAG_SINGLE_BIT) != 0
            ? -1 : 0; /* connect failure branch */
        g_querierRet = ((flags >> FLAG_QUERIER_FAIL_SHIFT) & FLAG_SINGLE_BIT) != 0
            ? 1 : 0;  /* not-registered branch */
    }

    UkeyOpenDialogRequest MakeOpenDialogReq(const struct UkeyDialogInput &in,
        const sptr<FuzzClientCallback> &clientCallback, bool withCustomData)
    {
        UkeyOpenDialogRequest req = {};
        req.keyUri = in.keyUri;
        req.callerUid = in.callerUid;
        req.timeoutSec = in.timeout;
        req.customData = withCustomData ? in.customData : CmBlob { 0, nullptr };
        req.clientCallback = clientCallback;
        req.userId = static_cast<int32_t>(in.userId);
        return req;
    }

    UkeyDriverDialogRequest MakeDriverDialogReq(const struct UkeyDialogInput &in,
        const sptr<FuzzClientCallback> &clientCallback)
    {
        UkeyDriverDialogRequest req = {};
        req.abilityName = { static_cast<uint32_t>(strlen(in.abilityName)) + 1,
            reinterpret_cast<uint8_t *>(in.abilityName) }; /* carries the trailing NUL */
        req.abilityType = g_abilityType;
        req.keyUri = in.keyUri;
        req.callerUid = in.callerUid;
        req.callerBundleName = (in.bundle[0] == '\0') ? DRIVER_BUNDLE : in.bundle;
        req.userId = static_cast<int32_t>(in.userId);
        req.timeoutSec = in.timeout;
        req.customData = in.customData;
        req.clientCallback = clientCallback;
        return req;
    }

    void DispatchUkeyDialogOp(const struct UkeyDialogInput &in)
    {
        auto manager = &CmUkeyAuthDialogManager::GetInstance();
        sptr<FuzzClientCallback> clientCallback = new (std::nothrow) FuzzClientCallback();

        if (in.op == OP_OPEN_DIALOG_PLAIN || in.op == OP_OPEN_DIALOG_CUSTOM) {
            (void)manager->OpenDialog(MakeOpenDialogReq(in, clientCallback,
                in.op == OP_OPEN_DIALOG_CUSTOM));
        } else if (in.op == OP_OPEN_DRIVER_DIALOG) {
            (void)manager->OpenDriverDialog(MakeDriverDialogReq(in, clientCallback));
        } else if (in.op == OP_ON_REPORT_FUZZ_ID) {
            (void)manager->OnReport(in.requestId, in.bundle, in.resultCode);
        } else if (in.op == OP_DISCONNECT_FUZZ_ID) {
            manager->OnDialogDisconnected(in.requestId);
        } else if (in.op == OP_CLIENT_DIED_FUZZ_ID) {
            manager->OnClientDied(in.requestId);
        } else if (in.op == OP_ON_REPORT_REAL_ID) {
            /* real request id: drives the session-found path of OnReport */
            std::string realId = manager->GetRequestIdForTest();
            (void)manager->OnReport(realId, DRIVER_BUNDLE, in.resultCode);
        } else if (in.op == OP_OPEN_DIALOG_TIMER_FAIL) {
            /* fault injection around a live session */
            manager->SetTimerPostFailForTest(true);
            (void)manager->OpenDialog(MakeOpenDialogReq(in, clientCallback, false));
            manager->SetTimerPostFailForTest(false);
        } else {
            /* real request id: drives the grace-waiting path of disconnect */
            std::string realId = manager->GetRequestIdForTest();
            manager->OnDialogDisconnected(realId);
        }
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
        struct UkeyDialogInput in = {};

        SetupDialogEnv();
        bool parsed = ParseUkeyDialogInput(myData, &remainSize, &offset, &in);
        if (parsed) {
            RetargetDialogMocks(in.flags);
            DispatchUkeyDialogOp(in);
        }

        FreeUkeyDialogInput(&in);
        CmFree(myData);
        return parsed;
    }
} // namespace OHOS::Security::CertManager

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Security::CertManager::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
