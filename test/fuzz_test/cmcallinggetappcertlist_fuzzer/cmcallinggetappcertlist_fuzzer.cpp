/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "cmcallinggetappcertlist_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"

using namespace CmFuzzTest;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    uint32_t minSize = sizeof(uint32_t) + sizeof(struct CredentialList);
    uint8_t *myData = nullptr;
    if (!CopyMyData(data, size, minSize, &myData)) {
        return false;
    }

    uint32_t remainSize = static_cast<uint32_t>(size);
    uint32_t offset = 0;

    uint32_t credStore;
    if (!GetUintFromBuffer(myData, &remainSize, &offset, &credStore)) {
        CmFree(myData);
        return false;
    }

    struct CredentialList credCertList = { 0, nullptr };
    if (!GetUintFromBuffer(myData, &remainSize, &offset, &(credCertList.credentialCount))) {
        CmFree(myData);
        return false;
    }
    if (credCertList.credentialCount > (remainSize / sizeof(struct CredentialAbstract))) {
        CmFree(myData);
        return false;
    }
    credCertList.credentialAbstract = reinterpret_cast<struct CredentialAbstract *>(myData + offset);

    SetATPermission();
    (void)CmCallingGetAppCertList(credStore, &credCertList);

    CmFree(myData);
    return true;
}
}
 
 /* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
 