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

#include "cmfindcert_fuzzer.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "cert_manager_api.h"
#include "cert_manager_check.h"
#include "cert_manager_service.h"
#include "cm_cert_property_rdb.h"
#include "cm_fuzz_test_common.h"
#include "cm_ipc_client.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "securec.h"

using namespace CmFuzzTest;

namespace {
    const uint32_t UINT32_COUNT = 8;
    /* seed at most 17 rows: one past MAX_COUNT_FIND_CERT_RESULT so the
     * result-count cap of the service path is reachable too */
    const uint32_t SEED_ROW_MAX = MAX_COUNT_FIND_CERT_RESULT + 1;
    const uint32_t FIND_SCOPE_COUNT = 4; /* three legal scopes plus one illegal */
    const uint32_t FIND_TYPE_COUNT = 3;  /* 0, 1, 2 type slots */
    /* the count-limit fold spans the truncation and the over-max boundaries */
    const uint32_t COUNT_LIMIT_FOLD_EXTRA = 4;

    void CopyStringToBuffer(char *dst, uint32_t dstSize, const char *src)
    {
        size_t len = strlen(src);
        if (len >= dstSize) {
            len = dstSize - 1;
        }
        if (memcpy_s(dst, dstSize, src, len) != EOK) {
            dst[0] = '\0';
            return;
        }
        dst[len] = '\0';
    }

    /* build a legal user-CA uri for row idx: CmGetCertConfigStatus decodes it
     * later, so the seeded rows must keep the CMUri shape */
    void BuildSeedUri(char *uri, uint32_t uriSize, uint32_t idx, const struct CmContext *context)
    {
        if (snprintf_s(uri, uriSize, uriSize - 1, "oh:t=c;o=fz%02u;u=%u;a=%u",
            idx, context->userId, context->uid) < 0) {
            uri[0] = '\0';
        }
    }

    /* seed one user-CA property row the query can find: uri/alias/subject/cert
     * are fixed, only the row count is fuzzed (the columns are the values the
     * result mapping copies, the row count drives the count-cap branches) */
    void SeedCertPropertyRow(const struct CmContext *context, uint32_t idx)
    {
        struct CertProperty prop;
        (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
        BuildSeedUri(prop.uri, sizeof(prop.uri), idx, context);
        CopyStringToBuffer(prop.alias, sizeof(prop.alias), "fuzzalias");
        CopyStringToBuffer(prop.subjectName, sizeof(prop.subjectName), "fuzzsubject");
        CopyStringToBuffer(prop.certType, sizeof(prop.certType), "c");
        prop.certStore = static_cast<int32_t>(CM_USER_TRUSTED_STORE);
        prop.userId = static_cast<int32_t>(context->userId);
        prop.uid = static_cast<int32_t>(context->uid);
        prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
        (void)InsertCertProperty(&prop);
    }

    /* fill the request: scope and cert types cover the legal and the rejected
     * shapes, name/certId come from the fuzzed strings, the count limit folds
     * across the truncation and the over-max boundaries */
    void FillFindCertRequest(struct FindCertRequest *request, uint32_t scopeSel, uint32_t typeSel,
        uint32_t typeValSel, uint32_t limitSel, const char *dynamicName, const char *dynamicId,
        enum CmFindCertType *typeSlots, uint32_t typeSlotCount)
    {
        (void)memset_s(request, sizeof(*request), 0, sizeof(*request));
        request->scope = static_cast<enum CmFindCertScope>(scopeSel % FIND_SCOPE_COUNT);
        request->certTypesCount = typeSel % FIND_TYPE_COUNT;
        if (request->certTypesCount > 0) {
            if ((typeValSel & 0x2) != 0) {
                /* count > 0 with a NULL array: the inconsistent-shape rejection */
                request->certTypes = nullptr;
            } else {
                /* every type value in the array is USER_CA or the rejected one */
                for (uint32_t i = 0; i < request->certTypesCount && i < typeSlotCount; i++) {
                    typeSlots[i] = static_cast<enum CmFindCertType>((typeValSel >> i) & 0x1);
                }
                request->certTypes = typeSlots;
            }
        } else {
            request->certTypes = nullptr; /* count 0: the null array stays legal */
        }
        request->countLimit = limitSel % (MAX_COUNT_FIND_CERT_RESULT + COUNT_LIMIT_FOLD_EXTRA);
        if (dynamicName != nullptr) {
            CopyStringToBuffer(request->name, sizeof(request->name), dynamicName);
        }
        if (dynamicId != nullptr) {
            CopyStringToBuffer(request->certId, sizeof(request->certId), dynamicId);
        }
    }

    /* parse the context and the query selectors; returns false when the fuzz
     * input is too short to carry the full header */
    bool ParseFindCertSelectors(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct CmContext *context, uint32_t *scopeSel, uint32_t *typeSel, uint32_t *typeValSel,
        uint32_t *limitSel, uint32_t *rowSel, char **dynamicName, char **dynamicId)
    {
        (void)memset_s(context, sizeof(*context), 0, sizeof(*context));
        if (!CreateCmContext(*context, myData, *remainSize, *offset)) {
            return false;
        }
        if (!GetUintFromBuffer(myData, remainSize, offset, scopeSel) ||
            !GetUintFromBuffer(myData, remainSize, offset, typeSel) ||
            !GetUintFromBuffer(myData, remainSize, offset, typeValSel) ||
            !GetUintFromBuffer(myData, remainSize, offset, limitSel) ||
            !GetUintFromBuffer(myData, remainSize, offset, rowSel)) {
            return false;
        }
        /* dynamic name/certId filters: parsing may fail, the fields stay empty */
        (void)GetDynamicStringFromBuffer(myData, remainSize, offset, dynamicName);
        (void)GetDynamicStringFromBuffer(myData, remainSize, offset, dynamicId);
        return true;
    }

    /* seed the property table so the query paths have rows to find */
    void SeedCertPropertyRows(const struct CmContext *context, uint32_t rowCount)
    {
        (void)CreateCertPropertyRdb();
        for (uint32_t i = 0; i < rowCount; i++) {
            SeedCertPropertyRow(context, i);
        }
    }

    /* remove the seeded rows again so long fuzz runs do not grow the table */
    void RemoveSeededRows(const struct CmContext *context, uint32_t rowCount)
    {
        for (uint32_t i = 0; i < rowCount; i++) {
            char seedUri[MAX_LEN_URI] = { 0 };
            BuildSeedUri(seedUri, sizeof(seedUri), i, context);
            (void)DeleteCertProperty(seedUri);
        }
    }

    /* run the three-layer chain: the unmocked check (denial branch), the
     * mocked service query (deep path) and the client serialization */
    void RunFindCertScenarios(const struct CmContext *context, const struct FindCertRequest *request)
    {
        /* stage 1: caller without the mocked permission hits the denial branch;
         * a NULL request exercises the argument guard as well */
        (void)CmServiceFindCertCheck(context, request);
        (void)CmServiceFindCertCheck(context, nullptr);

        /* stage 2: the permission-bearing system app walks the deep query path */
        {
            CertmanagerTest::MockHapToken mockHap;
            (void)CmServiceFindCertCheck(context, request);
            struct FindCertResult result;
            (void)memset_s(&result, sizeof(result), 0, sizeof(result));
            (void)CmServiceFindCertificate(context, request, &result);
            CmFreeFindCertResult(&result); /* frees the engine-allocated certData and array */
        }

        /* stage 3: the client serialization: the packing runs fully even
         * though the request itself fails to reach the SA in the fuzz process;
         * the NULL pairs hit the argument guard */
        {
            struct FindCertResult clientResult;
            (void)memset_s(&clientResult, sizeof(clientResult), 0, sizeof(clientResult));
            (void)CmClientFindCertificate(request, &clientResult);
            (void)CmClientFindCertificate(nullptr, &clientResult);
            (void)CmClientFindCertificate(request, nullptr);
            CmFreeFindCertResult(&clientResult);
        }
    }
}

namespace OHOS {
    /* exercise the find-certificate chain: the check helper (cert_manager_check.c),
     * the service query (cert_manager_service.c) and the client serialization
     * (cm_ipc_client.c) over a seeded property table */
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;

        struct CmContext context;
        uint32_t scopeSel = 0;
        uint32_t typeSel = 0;
        uint32_t typeValSel = 0;
        uint32_t limitSel = 0;
        uint32_t rowSel = 0;
        char *dynamicName = nullptr;
        char *dynamicId = nullptr;
        if (!ParseFindCertSelectors(myData, &remainSize, &offset, &context, &scopeSel, &typeSel,
            &typeValSel, &limitSel, &rowSel, &dynamicName, &dynamicId)) {
            CmFree(myData);
            return false;
        }

        struct FindCertRequest request;
        enum CmFindCertType typeSlots[MAX_COUNT_FIND_CERT_TYPE] = {};
        FillFindCertRequest(&request, scopeSel, typeSel, typeValSel, limitSel, dynamicName,
            dynamicId, typeSlots, CM_ARRAY_SIZE(typeSlots));

        uint32_t rowCount = rowSel % (SEED_ROW_MAX + 1);
        SeedCertPropertyRows(&context, rowCount);
        RunFindCertScenarios(&context, &request);
        RemoveSeededRows(&context, rowCount);

        delete[] dynamicName;
        delete[] dynamicId;
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
