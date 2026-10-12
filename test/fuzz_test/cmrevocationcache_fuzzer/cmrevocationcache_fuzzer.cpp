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

#include "cmrevocationcache_fuzzer.h"

#include <cstring>

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_revocation_cache.h"
#include "cm_ipc_service.h"
#include "cm_test_common.h"

namespace {
const uint32_t UINT32_COUNT = 1;
const uint32_t CM_BLOB_COUNT = 2;
const int64_t DEFAULT_EXPIRE_TIME = 3000000000LL; // 50 years in seconds approx as UTC
}

using namespace CmFuzzTest;
namespace OHOS {
bool DoSomethingInterestingWithRevocationCache(const uint8_t *data, size_t size)
{
    uint32_t minSize = sizeof(struct CmBlob) * CM_BLOB_COUNT + sizeof(uint32_t) * UINT32_COUNT + sizeof(int64_t);
    uint8_t *myData = nullptr;
    if (!CopyMyData(data, size, minSize, &myData)) {
        return false;
    }

    uint32_t remainSize = static_cast<uint32_t>(size);
    uint32_t offset = 0;

    struct CmBlob key = { 0, nullptr };
    if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &key)) {
        CmFree(myData);
        return false;
    }

    uint32_t type = 0;
    if (!GetUintFromBuffer(myData, &remainSize, &offset, &type)) {
        CmFree(myData);
        if (key.data != nullptr) {
            CmFree(key.data);
        }
        return false;
    }

    struct CmBlob cacheData = { 0, nullptr };
    if (!GetCmBlobFromBuffer(myData, &remainSize, &offset, &cacheData)) {
        CmFree(myData);
        if (key.data != nullptr) {
            CmFree(key.data);
        }
        return false;
    }

    int64_t expireTime = DEFAULT_EXPIRE_TIME;
    if (remainSize >= sizeof(int64_t)) {
        (void)memcpy_s(&expireTime, sizeof(int64_t), myData + offset, sizeof(int64_t));
    }

    (void)CmSaveRevocationCache(key, static_cast<enum CmRevocationType>(type), cacheData, expireTime);

    struct CmBlob outData = { 0, nullptr };
    (void)CmGetRevocationCache(key, static_cast<enum CmRevocationType>(type), &outData);
    CmFreeRevocationCache(&outData);

    if (key.data != nullptr) {
        CmFree(key.data);
    }
    if (cacheData.data != nullptr) {
        CmFree(cacheData.data);
    }
    CmFree(myData);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithRevocationCache(data, size);
    {
        CertmanagerTest::MockHapToken mockHap;
        (void)CmFuzzTest::IpcServiceApiFuzzerTest(data, size, CM_MSG_SAVE_REVOCATION_CACHE,
            false, CmIpcServiceSaveRevocationCache);
    }
    return 0;
}
