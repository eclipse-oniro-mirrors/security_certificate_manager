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

#ifndef CM_HSDR_PROTOCOL_H
#define CM_HSDR_PROTOCOL_H

#include <cstdint>
#include <string>
#include <string_view>
#include <sys/stat.h>

#include "message_parcel.h"

#include "cm_cloud_policy_store.h"
#include "cm_type.h"

/* the HSDR requests and replies walk OHOS::MessageParcel; the
 * using-declaration keeps the pack/parse signatures below on the plain
 * MessageParcel name while this header stays a free-function module */
using OHOS::MessageParcel;

/*
 * One cloud-push scene: the external service to connect to, the command to
 * send over it, and where the resource inside the answer lands. A
 * compile-time table entry (the only instance today is CLOUD_POLICY_SCENE
 * below); a new cloud-push scenario adds an entry and reuses the generic
 * client unchanged.
 */
struct CloudResourceScene {
    const char *bundleName;              /* "com.huawei.hmos.hsdr" */
    const char *abilityName;            /* "HSDRService" */
    uint32_t cmdId;                      /* 4 */
    std::u16string_view callerParam;    /* u"com.huawei.certmanager" */
    std::u16string_view resourceParam;  /* u"certManagerConfig" */
    const char *zipMember;               /* CM_CLOUD_POLICY_FILE_NAME (extraction whitelist) */
    const char *destDir;                 /* FORCE_CHECK_POLICY_DIR (publish target directory) */
    const char *destFile;                /* CM_CLOUD_POLICY_FILE_NAME (published file name) */
    mode_t destMode;                     /* 0644 */
};

/* the certificate revocation policy cloud-push scene, the requirement
 * spec's scene table verbatim; defined inline here so no consumer has to
 * link a scene-table translation unit */
inline constexpr CloudResourceScene CLOUD_POLICY_SCENE {
    "com.huawei.hmos.hsdr",
    "HSDRService",
    4,
    u"com.huawei.certmanager",
    u"certManagerConfig",
    CM_CLOUD_POLICY_FILE_NAME,
    FORCE_CHECK_POLICY_DIR,
    CM_CLOUD_POLICY_FILE_NAME,
    0644,
};

/*
 * Pack one HSDR request: the interface token first, then the scene's two
 * u16 parameters. The field order is the requirement-spec protocol layout,
 * the sole authority for the byte stream.
 *
 * @param data the request parcel to fill
 * @param token the interface token written ahead of the parameters
 * @param scene the scene whose caller/resource parameters are packed
 * @return CM_SUCCESS; CMR_ERROR when any parcel write fails
 */
int32_t CmHsdrPackRequest(MessageParcel &data, const std::u16string &token,
    const CloudResourceScene &scene);

/*
 * Parse one HSDR reply: interface token, execution result, then the zip
 * file descriptor, whose whole content is read into zipOut.
 *
 * The reply comes from an external cloud-facing service and is validated
 * before any byte is accepted: the token must equal the request token, the
 * result code must be 0, the fd must exist, and the zip read is capped at
 * CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE so a hostile answer cannot turn a small
 * reply into unbounded memory. The fd (a dup handed to this reader) is
 * closed on every path. Every rejection logs one CM_LOG_E line carrying
 * the cmdId and the scene bundle name.
 *
 * zipOut must arrive zeroed; it is assigned only on success, so a failed
 * call leaves nothing to free and no half-filled blob behind. On success
 * zipOut.data is CmMalloc'd and the caller releases it with CM_FREE_BLOB.
 *
 * @param reply the reply parcel to consume
 * @param token the interface token the reply must carry
 * @param scene the scene (cmdId and bundle name for the diagnostics)
 * @param zipOut receives the archive bytes on success
 * @return CM_SUCCESS; CMR_ERROR on a token mismatch, a non-zero result
 *         code, a missing fd, a read failure or an oversized or empty
 *         zip; CMR_ERROR_MALLOC_FAIL when the blob cannot be allocated
 */
int32_t CmHsdrParseReply(MessageParcel &reply, const std::u16string &token,
    const CloudResourceScene &scene, struct CmBlob &zipOut);

#endif /* CM_HSDR_PROTOCOL_H */
