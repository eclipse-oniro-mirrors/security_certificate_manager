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

#ifndef CM_CLOUD_POLICY_STORE_H
#define CM_CLOUD_POLICY_STORE_H

#include <cstdint>
#include <string>
#include <sys/stat.h>

#include "cm_type.h"

/* cloud policy state, all inside the forceCheck directory: the published
 * policy file and the version counter of the cloud content it holds */
#define CM_CLOUD_POLICY_FILE_NAME  "certRevocationPolicy_cloud.cfg"
#define CM_CLOUD_VERSION_FILE_NAME "version.cfg"
/* staging directory for a download in flight, cleared again after publish */
#define CM_CLOUD_TMP_DIR_NAME      "cloud_tmp"

/* preset cloud policy content, byte-exact: "<seq>,<cert pk hash>" per line,
 * each "\n"-terminated (the line format of the force-check policy files);
 * the pinned revocations the image ships with */
#define CM_CLOUD_POLICY_PRESET_LINE_1 "1,BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3\n"
#define CM_CLOUD_POLICY_PRESET_LINE_2 "1,8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782\n"

/*
 * Ensure the cloud policy state exists: the forceCheck directory (0701, the
 * service cfg mode), a fresh version.cfg holding "0" (0600) and the preset
 * policy lines (0644).
 *
 * Idempotent: every item that already exists is left untouched, so a device
 * that has already synced keeps its published content and version. Every
 * file is written through a "<path>.tmp" and renamed over the final path,
 * the atomic pattern of cert_manager_status.c WriteAndPublishPolicyFile.
 * The service cfg mkdir is the primary source of the directory; this is the
 * fresh-boot/self-healing fallback.
 *
 * @return CM_SUCCESS when all three items exist (created or pre-existing);
 *         CMR_ERROR when an item is missing and cannot be created
 */
int32_t CmCloudStoreSelfHealPreset(void);

/*
 * Read the local version counter of the published cloud policy.
 *
 * Fail-open by design: a missing, empty, malformed or unreadable version.cfg
 * reads as version 0 and still returns CM_SUCCESS, so the sync keeps gating
 * on "no cloud content yet" and the next round re-downloads instead of
 * trusting a broken file. Hard IO problems surface at publish/write time.
 * The out parameter is assigned on every return path.
 *
 * @param version receives the stored version, 0 when unknown or invalid
 * @return CM_SUCCESS
 */
int32_t CmCloudStoreReadVersion(uint64_t &version);

/*
 * Store a new version counter, written atomically ("<path>.tmp" then rename)
 * with mode 0600: only the service reads or writes it.
 * Callers serialize writers; the fixed tmp name cannot take two writers.
 *
 * @param version the version to persist
 * @return CM_SUCCESS when version.cfg holds the value; CMR_ERROR on any
 *         write/publish failure
 */
int32_t CmCloudStoreWriteVersion(uint64_t version);

/*
 * Create the cloud_tmp staging directory (0700) under the revocation cache
 * base; a directory that already exists counts as success.
 *
 * @return CM_SUCCESS when the directory exists; CMR_ERROR when it cannot
 *         be created (or something other than a directory occupies the path)
 */
int32_t CmCloudStorePrepareTmpDir(void);

/*
 * The staging directory path: REVOCATION_CACHE_BASE plus CM_CLOUD_TMP_DIR_NAME.
 * Derived from the cm_type.h bases only, never from caller input.
 *
 * @return the fixed staging directory path
 */
const char *CmCloudStoreTmpDirPath(void);

/*
 * Remove the staging directory with everything inside it; a directory that
 * does not exist is also success (the steady state between syncs).
 *
 * @return CM_SUCCESS when nothing is left staged; CMR_ERROR when the
 *         directory exists and cannot be fully removed
 */
int32_t CmCloudStoreCleanupTmpDir(void);

/*
 * Publish srcPath into the forceCheck directory as destName with the given
 * mode, atomically: the bytes are copied to "<dest>.tmp", flushed and fsynced,
 * closed, chmod'ed and renamed over the published path, the atomic pattern
 * of cert_manager_status.c WriteAndPublishPolicyFile. A failed call leaves
 * the published file and no "<dest>.tmp" behind.
 *
 * destName must be a plain file name (no '/'): the only path inputs are
 * this name appended to the fixed FORCE_CHECK_POLICY_DIR, so nothing can
 * publish outside the directory. The source file is left in place; the
 * caller owns its lifecycle (normally the staging directory cleanup).
 * The forceCheck directory is not created here; a missing directory fails
 * the publish. Callers serialize writers; the fixed tmp name cannot take
 * two publishers.
 *
 * @param srcPath existing file whose content becomes the published entry
 * @param destName plain file name inside FORCE_CHECK_POLICY_DIR
 * @param mode the mode pinned on the published file
 * @return CM_SUCCESS when destName holds the source bytes; CMR_ERROR for
 *         a missing destination directory, an unreadable source, or any
 *         copy/publish failure; CMR_ERROR_INVALID_ARGUMENT for an empty
 *         source path or a destName that is null, empty, or contains '/'
 */
int32_t CmCloudStorePublishFile(const std::string &srcPath,
    const char *destName, mode_t mode);

#endif /* CM_CLOUD_POLICY_STORE_H */
