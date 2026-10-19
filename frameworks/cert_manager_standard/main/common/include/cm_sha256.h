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

#ifndef CM_SHA256_H
#define CM_SHA256_H

#include <stdint.h>

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_SHA256_HASH_LEN 32

/*
 * One-shot SHA-256 (FIPS 180-4), self-contained: no OpenSSL, no dynamic
 * allocation. Used to derive revocation-cache file paths from caller keys
 * on both the SDK read side and the service write side, so both ends share
 * one implementation. Correctness is pinned by the NIST vectors in
 * test/unittest/src/cm_sha256_test.cpp.
 * Note: modular (wrapping) uint32 additions are inherent to the algorithm;
 * the function names match the platform integer-overflow blocklist.
 */
int32_t CmSha256(const uint8_t *data, uint32_t dataLen, uint8_t hash[CM_SHA256_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* CM_SHA256_H */
