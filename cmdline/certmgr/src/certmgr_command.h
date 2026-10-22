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
constexpr int32_t CM_CMD_SUCCESS = 0;
constexpr int32_t CM_CMD_ERR_PARAM_INVALID = 1;
constexpr int32_t CM_CMD_ERR_OPEN_FILE_FAIL = 2;
constexpr int32_t CM_CMD_ERR_INVALID_CERT_FORMAT = 3;
constexpr int32_t CM_CMD_ERR_MAX_CERT_COUNT_REACHED = 4;
constexpr int32_t CM_CMD_ERR_DEVICE_ENTER_ADVSECMODE = 5;
constexpr int32_t CM_CMD_ERR_PERMISSION_DENIED = 6;
constexpr int32_t CM_CMD_ERR_INTERNAL_ERROR = 7;
constexpr int32_t CM_CMD_ERR_USER_CANCELLED = 8;

int32_t MapSdkErrToCmdErr(int32_t sdkErr);

std::string GetErrName(int32_t errCode);

void SetCommandName(const std::string &name);

void WriteError(int32_t errCode, const std::string &detail);

int32_t ReadFileData(const std::string &filePath, struct CmBlob &outBlob);

int32_t ReadPipeData(struct CmBlob &outBlob);

bool HasPipeInput();

int32_t CheckGlobalUserCaPermission(int32_t userId);

#ifdef SUPPORT_USERIAM
int32_t AuthenticateUser(int32_t userId);
#endif

int32_t AuthenticateAdmin();

int32_t GetCertSha256Hex(const struct CmBlob &certData, std::string &sha256Hex);

int32_t GetCertPemString(const struct CmBlob &certData, std::string &pemStr);

int32_t GetCertHashStrings(const struct CmBlob &certData,
    std::string &sha256Hex, std::string &sha1Hex);

class CertMgrCommand {
public:
    virtual ~CertMgrCommand() = default;

    int32_t Execute(int argc, char *argv[]);

    static std::unique_ptr<CertMgrCommand> Create(const std::string &name);

    static void WriteStdErr(const std::string &msg);
    static void WriteStdOut(const std::string &msg);
    static int32_t GetUserId();

protected:
    virtual int32_t ParseArgs(int argc, char *argv[]) = 0;

    virtual int32_t Validate() = 0;

    virtual int32_t Run() = 0;
};

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

class FindUserCACommand final : public CertMgrCommand {
public:
    FindUserCACommand() = default;

protected:
    int32_t ParseArgs(int argc, char *argv[]) override;
    int32_t Validate() override;
    int32_t Run() override;

private:
    bool hasG_ = false;
    bool hasGU_ = false;
    std::string certName_;
    bool hasName_ = false;
    int32_t certCount_ = 0;
    bool printPem_ = false;
    bool printHash_ = false;
};

} // namespace CertMgr

#endif // CERTMGR_COMMAND_H
