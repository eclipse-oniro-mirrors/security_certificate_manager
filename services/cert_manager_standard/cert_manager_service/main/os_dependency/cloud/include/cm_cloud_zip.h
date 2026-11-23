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

#ifndef CM_CLOUD_ZIP_H
#define CM_CLOUD_ZIP_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* hard input cap: a cloud policy bundle above this is rejected before any
 * byte is staged to disk */
#define CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE (1024 * 1024) /* input blob upper bound */
/* hard member cap: even a whitelisted member may not decompress beyond this,
 * so a hostile archive cannot turn a small blob into unbounded work */
#define CM_CLOUD_ZIP_MAX_MEMBER_SIZE (64 * 1024) /* decompressed member upper bound */

/*
 * Extract exactly one whitelisted member from a cloud-pushed zip bundle.
 *
 * The bundle bytes come from an external cloud service and are treated as
 * hostile: the archive is walked entry by entry and only an entry whose
 * name is byte-for-byte equal to memberName is extracted, written to
 * destDir/memberName with mode 0644. The exact-name match is the security
 * boundary: entries such as "../evil" or "sub/dir/f" never match and never
 * reach the file system, so nothing can be written outside destDir.
 *
 * memberName must be a plain file name (no '/'), destDir must already
 * exist; neither is created here.
 *
 * On every failure the staged archive and any partially extracted member
 * are removed, so a failed call leaves no new file behind.
 *
 * @param zipData the raw bundle bytes (caller-owned); size is checked
 *        against CM_CLOUD_ZIP_MAX_ARCHIVE_SIZE first
 * @param memberName the single whitelisted member name to extract
 * @param destDir existing directory the member is written into
 * @return CM_SUCCESS when destDir/memberName holds the extracted content;
 *         CMR_ERROR_INVALID_ARGUMENT for null/empty arguments, a memberName
 *         containing '/', or an empty blob; CMR_ERROR for an oversized
 *         bundle, a missing or oversized member, and any zip/CRC/file error
 */
int32_t CmCloudZipExtractWhitelisted(const struct CmBlob *zipData,
    const char *memberName, const char *destDir);

#ifdef __cplusplus
}
#endif

#endif /* CM_CLOUD_ZIP_H */
