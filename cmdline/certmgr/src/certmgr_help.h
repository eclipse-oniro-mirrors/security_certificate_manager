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

#ifndef CERTMGR_HELP_H
#define CERTMGR_HELP_H

#include <string>

namespace CertMgr {

const std::string HELP_MAIN =
    "Usage: certmgr [-h] [command] [opt ...]\n"
    "-h  Displays the help information about the certmgr command\n"
    "certmgr commands are:\n"
    "installUserCA     Install user CA certificate\n"
    "findUserCA        Find user CA certificates\n";

const std::string HELP_INSTALL =
    "Usage: certmgr installUserCA [-h] [-g] [-F certFileFormat] [certFile]\n"
    "-h                 Display help information\n"
    "-g                 Install to system-level (GlobalUser) directory, default is current user\n"
    "-F certFileFormat  certFileFormat=PEM_DER|P7B; default is PEM_DER\n"
    "certFile           CA certificate file to install (only one file allowed). "
    "Supports pipe input. Required if no pipe input\n";

const std::string HELP_FIND =
    "Usage: certmgr findUserCA [-h] [-g] [-gu] [-n name] [-c count] [-p] [-z]\n"
    "-h          Display help information\n"
    "-g          Find global user CA certificates\n"
    "-gu         Find both current and global user CA certificates\n"
    "-n name     Filter by certificate name (alias or subject)\n"
    "-c count    Maximum number of results (0 = all)\n"
    "-p          Print PEM encoding of certificates\n"
    "-z          Print SHA-256 and SHA-1 hash of certificates\n";

} // namespace CertMgr

#endif // CERTMGR_HELP_H
