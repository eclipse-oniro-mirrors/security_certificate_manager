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

int32_t ReadFileData(const std::string &filePath, struct CmBlob &outBlob);

int32_t ReadPipeData(struct CmBlob &outBlob);

bool HasPipeInput();

int32_t CheckGlobalUserCaPermission(int32_t userId);

std::string ConvertErrCodeToMsg(int32_t errCode);

int32_t AuthenticateUser(int32_t userId);

int32_t AuthenticateAdmin();

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

} // namespace CertMgr

#endif // CERTMGR_COMMAND_H
