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

#include "certmgr_command.h"
#include "certmgr_help.h"

static constexpr int MIN_ARG_COUNT = 2;

int main(int argc, char *argv[])
{
    if (argc < MIN_ARG_COUNT) {
        CertMgr::CertMgrCommand::WriteStdOut(CertMgr::HELP_MAIN);
        return 1;
    }

    std::string command = argv[1];

    if (command == "-h") {
        CertMgr::CertMgrCommand::WriteStdOut(CertMgr::HELP_MAIN);
        return 0;
    }

    auto cmd = CertMgr::CertMgrCommand::Create(command);
    if (cmd == nullptr) {
        CertMgr::CertMgrCommand::WriteStdErr("Unknown command: " + command + "\n");
        CertMgr::CertMgrCommand::WriteStdOut(CertMgr::HELP_MAIN);
        return CertMgr::CM_CMD_ERR_PARAM_INVALID;
    }

    int32_t ret = cmd->Execute(argc, argv);
    // -1 means help was printed, treat as success
    return (ret == -1) ? 0 : ret;
}
