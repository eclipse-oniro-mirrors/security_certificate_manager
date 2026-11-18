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

#include "cmcloudzip_fuzzer.h"

#include <cstdint>
#include <sys/stat.h>

#include "cm_cloud_zip.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "securec.h"

namespace {
/* fuzz-owned scratch dir: created defensively at entry and kept at exit so
 * consecutive runs share one place to inspect extraction leftovers */
const char *FUZZ_DEST_DIR = "/data/local/tmp/cmcloudzip_fuzz";
/* fixed whitelist member: the force-check policy file name used by the real
 * sync flow, so the fuzzer exercises the intended call shape */
const char *FUZZ_MEMBER_NAME = "certRevocationPolicy_user.cfg";
} // namespace

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)mkdir(FUZZ_DEST_DIR, 0755); /* defensive: exists after the first run */

    /* hand the module a private copy of the input: the blob must be owned
     * CmMalloc memory and the fuzz buffer is const */
    uint8_t *input = static_cast<uint8_t *>(CmMalloc(size));
    if (input == nullptr) {
        return 0;
    }
    if ((size > 0) && (memcpy_s(input, size, data, size) != EOK)) {
        CmFree(input);
        return 0;
    }
    struct CmBlob blob = { static_cast<uint32_t>(size), input };
    (void)CmCloudZipExtractWhitelisted(&blob, FUZZ_MEMBER_NAME, FUZZ_DEST_DIR);
    CmFree(input);
    return 0;
}
