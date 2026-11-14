/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#ifndef CERT_MANAGER_STATUS_H
#define CERT_MANAGER_STATUS_H

#include "cert_manager_mem.h"
#include "cm_type.h"

#define  CERT_STATUS_ENANLED           ((uint32_t) 0)
#define  CERT_STATUS_DISABLED          ((uint32_t) 1)

#define ASSERT_ARGS(c) if (!(c)) { CM_LOG_W("Invalid args: %s\n", #c); return CMR_ERROR_INVALID_ARGUMENT; }

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status);

/* algorithm classification of a system root CA certificate from the store
 * DIRECTORY its file lives in: the product partitions GM (national
 * cryptography) root CAs into SYSTEM_CA_STORE_GM and international ones
 * into SYSTEM_CA_STORE, and that partition is authoritative — parsing the
 * certificate public key is not (preset GM certificates commonly encode
 * the key with the standard EC algorithm OID, which OpenSSL reads back as
 * a plain EC key, never as SM2)
 * @param certPath the store directory of the certificate file, as
 *                 enumerated into CertFileInfo.path
 * @return CM_ROOT_CA_ALG_TYPE_GM when the directory is the GM store,
 *         CM_ROOT_CA_ALG_TYPE_INTERNATIONAL otherwise (including NULL) */
uint32_t CmGetSystemCaAlgType(const char *certPath);

/* set the manual enable/disable state of one SYSTEM root CA certificate
 * (certUri must match a file enumerated from the system store); commits the
 * root_ca_cert_store row and regenerates the force-check policy file.
 * Atomic on failure: when the regeneration fails the committed row is
 * rolled back to its pre-call state (a previously absent uri keeps an
 * enable=1 row, functionally the same "not disabled" state) and the
 * published policy file stays untouched (its rename is the last write
 * step), so the store never contradicts the published file */
int32_t CmSetSystemCertStatus(const struct CmContext *context,
    const struct CmBlob *certUri, uint32_t status);

/* pk hash of one SYSTEM root CA certificate (certUri must match a file
 * enumerated from the system store): the SHA256 over its SubjectPublicKeyInfo
 * DER as CM_ROOT_CA_PK_HASH_HEX_LEN uppercase hex chars
 * @param outPkHashHex buffer of at least CM_ROOT_CA_PK_HASH_HEX_LEN + 1
 *        bytes, receives the NUL-terminated hash
 * @param outPkHashHexLen size of outPkHashHex in bytes; too small a buffer
 *        fails with CMR_ERROR_INVALID_ARGUMENT and writes nothing */
int32_t CmGetSystemCertPkHash(const struct CmContext *context,
    const struct CmBlob *certUri, char *outPkHashHex, uint32_t outPkHashHexLen);

/* rewrite the force-check policy file from the disabled rows of
 * root_ca_cert_store (atomic tmp + rename); 0 bytes when nothing is disabled */
int32_t CmRegenerateRevocationPolicyFile(void);
#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_STATUS_H