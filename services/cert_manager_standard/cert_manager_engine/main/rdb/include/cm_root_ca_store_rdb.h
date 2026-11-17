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

#ifndef CM_ROOT_CA_STORE_RDB_H
#define CM_ROOT_CA_STORE_RDB_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* uppercase hex SHA256 over the SubjectPublicKeyInfo DER, without NUL */
#define CM_ROOT_CA_PK_HASH_HEX_LEN 64
/* values align with the public d.ts enum CertAlgorithm { INTERNATIONAL = 1, SM = 2 } */
#define CM_ROOT_CA_ALG_TYPE_INTERNATIONAL 1
#define CM_ROOT_CA_ALG_TYPE_GM 2

/* one row of the root_ca_cert_store table: the manual enable/disable state of
 * a single system root CA certificate, keyed by its uri (the file name under
 * /etc/security/certificates and /etc/security/certificates_gm) */
struct RootCaStoreRecord {
    char uri[MAX_LEN_URI];                                  /* NUL terminated */
    uint32_t algType;                                       /* 1 = international, 2 = GM */
    uint32_t enable;                                        /* 1 = enabled, 0 = disabled */
    char certPkHash[CM_ROOT_CA_PK_HASH_HEX_LEN + 1];
};

int32_t CreateRootCaStoreRdb(void);

/* insert or update one row; uriLen may or may not count the trailing NUL of
 * uri (engine blobs are sized strlen + 1): both spellings address one row */
int32_t UpsertRootCaStore(const char *uri, uint32_t uriLen, uint32_t algType,
    uint32_t enable, const char *certPkHash);

/* all disabled rows ordered by uri (the order keeps the policy-file output
 * deterministic); records holds at most maxCount rows, *count receives the
 * number of filled rows; more than maxCount disabled rows is an error */
int32_t QueryDisabledRootCa(struct RootCaStoreRecord *records, uint32_t maxCount, uint32_t *count);

/* enable state of one uri; a uri without a row counts as enabled */
int32_t QueryRootCaEnable(const char *uri, uint32_t uriLen, uint32_t *enable);

#ifdef __cplusplus
}
#endif

#endif /* CM_ROOT_CA_STORE_RDB_H */
