/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cmipcclient_fuzzer.h"

#include <cstdint>
#include <cstring>

#include "cm_fuzz_test_common.h"
#include "cm_ipc_client.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "securec.h"

using namespace CmFuzzTest;

namespace {
    /* fixed fields: 5 blob sizes, purpose, type and the null selector */
    const uint32_t UINT32_COUNT = 8;
    const uint32_t MAX_CERTPURPOSE = 6;
    /* ukey import dispatch: three of five rounds each hit one NULL-argument
     * rejection, the other two walk the full packing path */
    enum UkeyImportMode {
        UKEY_IMPORT_FULL = 0,          /* walk the full packing path */
        UKEY_IMPORT_NULL_KEY_URI = 1, /* reject on the NULL keyUri */
        UKEY_IMPORT_NULL_CERT = 2,    /* reject on the NULL cert */
        UKEY_IMPORT_NULL_UKEY_INFO = 3, /* reject on the NULL ukeyInfo */
        UKEY_IMPORT_FULL_AGAIN = 4,   /* walk the full packing path again */
    };
    const uint32_t UKEY_NULL_MODE_COUNT = UKEY_IMPORT_FULL_AGAIN + 1;
    /* cache type folds onto the OCSP, CRL and rejected values */
    const uint32_t REVOCATION_TYPE_COUNT = 3;

    /* parse keyUri, cert and the purpose selector for the ukey import;
     * returns false when the fuzz input is too short */
    bool ParseUkeyImportParams(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct CmBlob *keyUri, struct CmBlob *cert, struct UkeyInfo *ukeyInfo)
    {
        if (!GetCmBlobFromBuffer(myData, remainSize, offset, keyUri) ||
            !GetCmBlobFromBuffer(myData, remainSize, offset, cert)) {
            return false;
        }
        uint32_t purposeSel = 0;
        if (!GetUintFromBuffer(myData, remainSize, offset, &purposeSel)) {
            return false;
        }
        ukeyInfo->certPurpose = static_cast<enum CmCertificatePurpose>(purposeSel % MAX_CERTPURPOSE);
        return true;
    }

    /* parse the save-cache key, type, data and the raw expire field;
     * returns false when the fuzz input is too short */
    bool ParseSaveCacheParams(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct CmBlob *saveKey, uint32_t *typeSel, struct CmBlob *saveData, int64_t *rawExpire)
    {
        if (!GetCmBlobFromBuffer(myData, remainSize, offset, saveKey) ||
            !GetUintFromBuffer(myData, remainSize, offset, typeSel)) {
            return false;
        }
        if (!GetCmBlobFromBuffer(myData, remainSize, offset, saveData)) {
            return false;
        }
        if (*remainSize >= sizeof(int64_t)) {
            if (memcpy_s(rawExpire, sizeof(int64_t), myData + *offset, sizeof(int64_t)) != EOK) {
                *rawExpire = 0; /* a failed copy keeps the zero expire */
            }
            *offset += sizeof(int64_t);
            *remainSize -= sizeof(int64_t);
        }
        return true;
    }

    /* ukey import: each NULL argument lands in the guard's rejections, the
     * other rounds serialize keyUri, cert and the purpose into the param set
     * before the request fails and the set is freed */
    void RunUkeyImportRound(uint32_t nullSel, const struct CmBlob *keyUri, const struct CmBlob *cert,
        const struct UkeyInfo *ukeyInfo)
    {
        switch (nullSel % UKEY_NULL_MODE_COUNT) {
            case UKEY_IMPORT_NULL_KEY_URI:
                (void)CmClientImportUkeyCert(nullptr, cert, ukeyInfo);
                break;
            case UKEY_IMPORT_NULL_CERT:
                (void)CmClientImportUkeyCert(keyUri, nullptr, ukeyInfo);
                break;
            case UKEY_IMPORT_NULL_UKEY_INFO:
                (void)CmClientImportUkeyCert(keyUri, cert, nullptr);
                break;
            case UKEY_IMPORT_FULL:
            case UKEY_IMPORT_FULL_AGAIN:
            default:
                (void)CmClientImportUkeyCert(keyUri, cert, ukeyInfo);
                break;
        }
    }
}

namespace OHOS {
    /* drive the IPC client serializers directly (cm_ipc_client.c): the ukey
     * import packing with its NULL guard and the revocation-cache save with
     * its big-endian expire encoding; the requests die at the samgr lookup
     * inside the fuzz process, so both the packing and the cleanup paths run */
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT + sizeof(int64_t);
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        struct CmBlob keyUri = { 0, nullptr };
        struct CmBlob cert = { 0, nullptr };
        struct UkeyInfo ukeyInfo = {};
        if (!ParseUkeyImportParams(myData, &remainSize, &offset, &keyUri, &cert, &ukeyInfo)) {
            CmFree(myData);
            return false;
        }

        struct CmBlob saveKey = { 0, nullptr };
        struct CmBlob saveData = { 0, nullptr };
        uint32_t typeSel = 0;
        int64_t rawExpire = 0;
        if (!ParseSaveCacheParams(myData, &remainSize, &offset, &saveKey, &typeSel, &saveData,
            &rawExpire)) {
            CmFree(myData);
            return false;
        }

        uint32_t nullSel = 0;
        if (!GetUintFromBuffer(myData, &remainSize, &offset, &nullSel)) {
            CmFree(myData);
            return false;
        }

        RunUkeyImportRound(nullSel, &keyUri, &cert, &ukeyInfo);

        /* revocation cache save: the client packs *key and *data into the
         * params up front, so neither pointer may be NULL; the expire runs
         * through the big-endian encoder, the type keeps the legal fold */
        (void)CmClientSaveRevocationCache(&saveKey, typeSel % REVOCATION_TYPE_COUNT,
            &saveData, rawExpire);

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
