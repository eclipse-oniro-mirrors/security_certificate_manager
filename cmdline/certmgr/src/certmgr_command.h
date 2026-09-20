/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef CERTMGR_COMMAND_H
#define CERTMGR_COMMAND_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cm_type.h"

namespace CertMgr {

// Error codes for cmdline tool
constexpr int32_t CM_CMD_ERR_PARAM_INVALID = 29700006;
constexpr int32_t CM_CMD_ERR_PERMISSION_DENIED = 29700005;
constexpr int32_t CM_CMD_ERR_USER_CANCELLED = 29700002;

// ============================================================
// Shared utility functions
// ============================================================

// Read a file into a CmBlob (caller must free with CmFree)
int32_t ReadFileData(const std::string &filePath, struct CmBlob &outBlob);

// Read from stdin pipe into a CmBlob (caller must free with CmFree)
int32_t ReadPipeData(struct CmBlob &outBlob);

// Check if stdin has pipe data available
bool HasPipeInput();

// Check if the current user is allowed to install global user CA
int32_t CheckGlobalUserCaPermission(int32_t userId);

// Convert CM error code to user-readable message
std::string ConvertErrCodeToMsg(int32_t errCode);

// Authenticate current user via IAM BeginWidgetAuth (PIN/Face/Fingerprint)
// Returns CM_SUCCESS on success, CM_CMD_ERR_USER_CANCELLED if user cancels,
// or other error codes on failure.
int32_t AuthenticateUser(int32_t userId);

// Authenticate admin via AcquireAuthorization (privilege: manage_device_certificate)
// Returns CM_SUCCESS on success, CM_CMD_ERR_USER_CANCELLED if user cancels,
// or other error codes on failure.
int32_t AuthenticateAdmin();

// ============================================================
// Base command
// ============================================================

class CertMgrCommand {
public:
    virtual ~CertMgrCommand() = default;

    // Parse args, validate, then run. Returns CM_SUCCESS (0) or error code.
    int32_t Execute(int argc, char *argv[]);

    // Factory: create command by name, or nullptr if unknown
    static std::unique_ptr<CertMgrCommand> Create(const std::string &name);

    // Shared utilities
    static void WriteStdErr(const std::string &msg);
    static void WriteStdOut(const std::string &msg);
    static int32_t GetUserId();

protected:
    // Step 1: parse arguments starting from argv[2], return 0 on success
    virtual int32_t ParseArgs(int argc, char *argv[]) = 0;

    // Step 2: validate parsed state, return 0 on success
    virtual int32_t Validate() = 0;

    // Step 3: execute the command logic, return 0 on success
    virtual int32_t Run() = 0;
};

// ============================================================
// InstallUserCA command
// ============================================================

class InstallUserCACommand final : public CertMgrCommand {
public:
    InstallUserCACommand() = default;

protected:
    int32_t ParseArgs(int argc, char *argv[]) override;
    int32_t Validate() override;
    int32_t Run() override;

private:
    int32_t ReadCertData(struct CmBlob &certBlob);
    int32_t AuthenticateAndCheckPermission(int32_t &userId);
    int32_t InstallPemDer(const struct CmBlob &certBlob, int32_t userId);
    int32_t InstallP7B(const struct CmBlob &certBlob, int32_t userId);

    bool hasG_ = false;
    CmCertFileFormat certFormat_ = PEM_DER;
    std::string certFilePath_;
    bool hasCertFile_ = false;
};

} // namespace CertMgr

#endif // CERTMGR_COMMAND_H
