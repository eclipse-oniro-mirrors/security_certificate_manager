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

#include "cmquerycertproperty_fuzzer.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "cm_cert_property_rdb.h"
#include "cm_fuzz_test_common.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "securec.h"

using namespace CmFuzzTest;
namespace {
    const uint32_t UINT32_COUNT = 4;
    const uint32_t MAX_CONDITION_USER_IDS = 8;

    void CopyStringTruncated(char *dst, uint32_t dstSize, const char *src)
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

    void FreeConditionStrings(char *strs[], uint32_t count)
    {
        for (uint32_t i = 0; i < count; i++) {
            delete[] strs[i];
            strs[i] = nullptr;
        }
    }

    /* parsed fuzz input; owned pointers are freed by FreeQueryCertPropertyInput */
    struct QueryCertPropertyInput {
        char *uri = nullptr;
        char *alias = nullptr;
        char *subjectName = nullptr;
        char *certType = nullptr;
        char *name = nullptr;
        char *certId = nullptr;
        uint32_t store = 0;
        uint32_t userId = 0;
        uint32_t uid = 0;
        int32_t userIds[MAX_CONDITION_USER_IDS] = { 0 };
        uint32_t userIdCount = 0;
        bool certTypeNull = false;
        bool userIdsNull = false;
        bool nameNull = false;
        bool certIdNull = false;
    };

    void FreeQueryCertPropertyInput(struct QueryCertPropertyInput *in)
    {
        char *strs[] = { in->uri, in->alias, in->subjectName, in->certType, in->name, in->certId };
        FreeConditionStrings(strs, sizeof(strs) / sizeof(strs[0]));
        in->uri = nullptr;
        in->alias = nullptr;
        in->subjectName = nullptr;
        in->certType = nullptr;
        in->name = nullptr;
        in->certId = nullptr;
    }

    /* layout: 6 dynamic strings + 3 uint32 scalars + 1 byte userIdCount
     * + up to 8 uint32 userIds + 4 selector uint32s */
    bool ParseQueryCertPropertyInput(uint8_t *myData, uint32_t *remainSize, uint32_t *offset,
        struct QueryCertPropertyInput *in)
    {
        if (!GetDynamicStringFromBuffer(myData, remainSize, offset, &in->uri) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->alias) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->subjectName) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->certType) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->name) ||
            !GetDynamicStringFromBuffer(myData, remainSize, offset, &in->certId)) {
            return false;
        }
        if (!GetUintFromBuffer(myData, remainSize, offset, &in->store) ||
            !GetUintFromBuffer(myData, remainSize, offset, &in->userId) ||
            !GetUintFromBuffer(myData, remainSize, offset, &in->uid)) {
            return false;
        }

        /* userId filter array: small count keeps the predicates loop bounded */
        if (*remainSize >= sizeof(uint8_t)) {
            in->userIdCount = static_cast<uint32_t>(myData[*offset]) % (MAX_CONDITION_USER_IDS + 1);
            *offset += sizeof(uint8_t);
            *remainSize -= sizeof(uint8_t);
        }
        for (uint32_t i = 0; i < in->userIdCount; i++) {
            uint32_t id = 0;
            if (!GetUintFromBuffer(myData, remainSize, offset, &id)) {
                return false;
            }
            in->userIds[i] = static_cast<int32_t>(id);
        }

        /* each filter pointer of CmFindCertCondition is either the fuzzed
         * string or nullptr (BuildPredicatesFromCondition skips null/empty) */
        in->certTypeNull = TenPercentChanceOfBeingTrue(myData, remainSize, offset);
        in->userIdsNull = TenPercentChanceOfBeingTrue(myData, remainSize, offset);
        in->nameNull = TenPercentChanceOfBeingTrue(myData, remainSize, offset);
        in->certIdNull = TenPercentChanceOfBeingTrue(myData, remainSize, offset);
        return true;
    }

    /* seed one row so the query paths have data to find (uri is the key) */
    void SeedCertPropertyRow(const struct QueryCertPropertyInput &in)
    {
        struct CertProperty prop = {};
        CopyStringTruncated(prop.uri, MAX_LEN_URI, in.uri);
        CopyStringTruncated(prop.alias, MAX_LEN_CERT_ALIAS, in.alias);
        CopyStringTruncated(prop.subjectName, MAX_LEN_SUBJECT_NAME, in.subjectName);
        CopyStringTruncated(prop.certType, MAX_LEN_CERT_TYPE, in.certType);
        prop.certStore = static_cast<int32_t>(in.store);
        prop.userId = static_cast<int32_t>(in.userId);
        prop.uid = static_cast<int32_t>(in.uid);
        prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
        (void)CreateCertPropertyRdb();
        (void)InsertCertProperty(&prop);
    }

    void RunQueryCertProperty(const struct QueryCertPropertyInput &in)
    {
        SeedCertPropertyRow(in);

        /* target: QueryCertProperty (hit + invalid-argument branches) */
        struct CertProperty queried = {};
        (void)QueryCertProperty(in.uri, &queried);
        (void)QueryCertProperty(nullptr, nullptr);

        /* target: QueryCertPropertyByCondition (mixed filter combinations) */
        struct CmFindCertCondition condition = {};
        condition.certType = in.certTypeNull ? nullptr : in.certType;
        condition.userIds = (in.userIdsNull || in.userIdCount == 0) ? nullptr : in.userIds;
        condition.userIdCount = in.userIdCount;
        condition.name = in.nameNull ? nullptr : in.name;
        condition.certId = in.certIdNull ? nullptr : in.certId;
        struct CertProperty *results = nullptr;
        uint32_t resultCount = 0;
        (void)QueryCertPropertyByCondition(&condition, &results, &resultCount);
        if (results != nullptr) {
            free(results); /* engine allocates the array with malloc */
        }
        (void)QueryCertPropertyByCondition(nullptr, nullptr, nullptr);
    }
}

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t minSize = sizeof(uint32_t) * UINT32_COUNT +
            sizeof(uint32_t) * MAX_CONDITION_USER_IDS;
        uint8_t *myData = nullptr;
        if (!CopyMyData(data, size, minSize, &myData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        struct QueryCertPropertyInput in = {};

        bool parsed = ParseQueryCertPropertyInput(myData, &remainSize, &offset, &in);
        if (parsed) {
            RunQueryCertProperty(in);
        }

        FreeQueryCertPropertyInput(&in);
        CmFree(myData);
        return parsed;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
