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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <future>
#include <mutex>

#include "securec.h"
#include "cert_manager_api.h"
#include "cm_type.h"
#include "os_account_manager.h"
#include "user_auth_client.h"
#include "user_auth_client_callback.h"
#include "user_auth_client_defines.h"
#include "iam_common_defines.h"
#include "locale_config.h"
#include "locale_matcher.h"
#include "authorization_client.h"
#include "authorization_common.h"
#include "authorization_callback.h"

using namespace OHOS;

namespace CertMgr {

int32_t ReadFileData(const std::string &filePath, struct CmBlob &outBlob)
{
    FILE *fp = fopen(filePath.c_str(), "rb");
    if (fp == nullptr) {
        CertMgrCommand::WriteStdErr("Failed to open file: " + filePath + "\n");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    (void)fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    (void)fseek(fp, 0, SEEK_SET);

    if (fileSize <= 0 || static_cast<unsigned long>(fileSize) > MAX_LEN_CERTIFICATE_P7B) {
        CertMgrCommand::WriteStdErr("Invalid file size: " + std::to_string(fileSize) + "\n");
        (void)fclose(fp);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t size = static_cast<uint32_t>(fileSize);
    uint8_t *data = static_cast<uint8_t *>(malloc(size));
    if (data == nullptr) {
        CertMgrCommand::WriteStdErr("Failed to allocate memory for file data\n");
        (void)fclose(fp);
        return CMR_ERROR_MALLOC_FAIL;
    }

    size_t readSize = fread(data, 1, size, fp);
    (void)fclose(fp);
    if (readSize != size) {
        CertMgrCommand::WriteStdErr("Failed to read file data\n");
        free(data);
        return CMR_ERROR_READ_FILE_ERROR;
    }

    outBlob.data = data;
    outBlob.size = size;
    return CM_SUCCESS;
}

bool HasPipeInput()
{
    return !isatty(fileno(stdin));
}

int32_t ReadPipeData(struct CmBlob &outBlob)
{
    uint32_t capacity = MAX_LEN_CERTIFICATE_P7B;
    uint8_t *data = static_cast<uint8_t *>(malloc(capacity));
    if (data == nullptr) {
        CertMgrCommand::WriteStdErr("Failed to allocate memory for pipe data\n");
        return CMR_ERROR_MALLOC_FAIL;
    }

    uint32_t totalRead = 0;
    while (totalRead < capacity) {
        size_t n = fread(data + totalRead, 1, capacity - totalRead, stdin);
        if (n == 0) {
            break;
        }
        totalRead += static_cast<uint32_t>(n);
    }

    if (totalRead == 0) {
        CertMgrCommand::WriteStdErr("No data from pipe input\n");
        free(data);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    outBlob.data = data;
    outBlob.size = totalRead;
    return CM_SUCCESS;
}

static bool IsUserIdInList(const std::string &list, int32_t userId)
{
    std::string userIdStr = std::to_string(userId);
    size_t start = 0;
    while (start <= list.size()) {
        size_t end = list.find('|', start);
        if (end == std::string::npos) {
            end = list.size();
        }
        if (end > start) {
            std::string token = list.substr(start, end - start);
            if (token == userIdStr) {
                return true;
            }
        }
        start = end + 1;
    }
    return false;
}

struct GlobalCaConfig {
    std::string defaultConfig;
    std::string enableList;
    std::string disableList;
};

static int32_t QueryGlobalCaConfig(GlobalCaConfig &cfg)
{
    struct CertManagerConfig config = { 0, nullptr };
    int32_t ret = CmGetCertManagerConfig(NULL, &config);
    if (ret != CM_SUCCESS) {
        CertMgrCommand::WriteStdErr("Failed to query cert manager config\n");
        return ret;
    }

    cfg.defaultConfig = "enable";
    for (uint32_t i = 0; i < config.count; i++) {
        if (strcmp(config.configItems[i].key, "installGlobalUserCA_defaultConfig") == 0) {
            cfg.defaultConfig = config.configItems[i].value;
        } else if (strcmp(config.configItems[i].key, "enableInstallGlobalUserCA_userList") == 0) {
            cfg.enableList = config.configItems[i].value;
        } else if (strcmp(config.configItems[i].key, "disableInstallGlobalUserCA_userList") == 0) {
            cfg.disableList = config.configItems[i].value;
        }
    }
    CmFreeCertManagerConfig(&config);
    return CM_SUCCESS;
}

static constexpr const char *PERMISSION_DENIED_MSG =
    "The operation does not comply with the device security policy, "
    "the device does not allow users to manage the CA certificate of the global user\n";

int32_t CheckGlobalUserCaPermission(int32_t userId)
{
    GlobalCaConfig cfg;
    int32_t ret = QueryGlobalCaConfig(cfg);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (!cfg.disableList.empty() && IsUserIdInList(cfg.disableList, userId)) {
        CertMgrCommand::WriteStdErr(PERMISSION_DENIED_MSG);
        return CM_CMD_ERR_PERMISSION_DENIED;
    }

    bool inEnableList = !cfg.enableList.empty() && IsUserIdInList(cfg.enableList, userId);
    if (cfg.defaultConfig == "disable" && !inEnableList) {
        CertMgrCommand::WriteStdErr(PERMISSION_DENIED_MSG);
        return CM_CMD_ERR_PERMISSION_DENIED;
    }

    return CM_SUCCESS;
}

std::string ConvertErrCodeToMsg(int32_t errCode)
{
    switch (errCode) {
        case CMR_ERROR_PERMISSION_DENIED:
            return "Permission denied";
        case CMR_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case CMR_ERROR_NOT_SUPPORTED:
            return "Operation not supported";
        case CMR_ERROR_NOT_EXIST:
            return "Certificate does not exist";
        case CMR_ERROR_ALREADY_EXISTS:
            return "Certificate already exists";
        case CMR_ERROR_MAX_CERT_COUNT_REACHED:
            return "Maximum certificate count reached";
        case CMR_ERROR_INVALID_CERT_FORMAT:
            return "Invalid certificate format";
        case CMR_ERROR_DEVICE_ENTER_ADVSECMODE:
            return "Device is in advanced security mode";
        case CM_CMD_ERR_PERMISSION_DENIED:
            return "The operation does not comply with the device security policy, "
                   "the device does not allow users to manage the CA certificate of the global user";
        case CM_CMD_ERR_USER_CANCELLED:
            return "The user cancelled the operation";
        case CM_CMD_ERR_PARAM_INVALID:
            return "Invalid parameters";
        default:
            return "Error code: " + std::to_string(errCode);
    }
}

namespace {
using namespace OHOS::UserIam::UserAuth;

/* IAM authentication result codes */
static constexpr int32_t IAM_AUTH_SUCCESS = 0;
static constexpr int32_t IAM_ERR_NO_VALID_SOLUTION = 10;

struct LocaleTitleEntry {
    const char *locale;
    const char *title;
};

static const LocaleTitleEntry TITLE_MAP[] = {
    {"zh-CN", "您正在安装用户CA证书,请确认"},
    {"en-US", "You are installing a user CA certificate, please confirm"},
    {"zh-HK", "您正在安裝用戶CA證書,請確認"},
    {"zh-TW", "您正在安裝使用者CA憑證,請確認"},
    {"bo-CN", "ཁྱེད་ཀྱིས་སྤྱོད་མཁན་CAདཔང་ཡིག་སྒྲིག་སྦྱོར་བྱེད་བཞིན་ཡོད་པས་གཏན་འཁེལ་གནང་རོགས།"},
    {"ug-CN", "سىز ھازىر CA گۇۋاھنامىسىنى قاچىلاۋاتىسىز، جەزملەشتۈرۈڭ"}
};

static const std::vector<std::string> CANDIDATE_LOCALES = {"zh-CN", "en-US", "zh-HK", "zh-TW", "bo-CN", "ug-CN"};

static std::string GetLocalizedTitle()
{
    static const std::string defaultTitle = "You are installing a user CA certificate, please confirm";

    std::string currentLang = OHOS::Global::I18n::LocaleConfig::GetSimplifiedSystemLanguage();
    if (currentLang.empty()) {
        return defaultTitle;
    }

    std::string matchedLocale = OHOS::Global::I18n::LocaleMatcher::GetBestMatchedLocale(currentLang, CANDIDATE_LOCALES);
    if (matchedLocale.empty()) {
        return defaultTitle;
    }

    for (const auto &entry : TITLE_MAP) {
        if (matchedLocale == entry.locale) {
            return entry.title;
        }
    }
    return defaultTitle;
}

class AuthCallback final : public AuthenticationCallback {
public:
    AuthCallback(std::mutex &mutex, std::condition_variable &cv, int32_t &result, bool &done)
        : mutex_(mutex), cv_(cv), result_(result), done_(done) {}
    ~AuthCallback() = default;

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override {}

    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (done_) {
                return;
            }
            result_ = result;
            done_ = true;
        }
        cv_.notify_one();
    }

private:
    std::mutex &mutex_;
    std::condition_variable &cv_;
    int32_t &result_;
    bool &done_;
};
}

static constexpr size_t CHALLENGE_LEN = 8;

static std::vector<uint8_t> GenerateChallenge()
{
    std::vector<uint8_t> challenge(CHALLENGE_LEN);
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return {};
    }
    ssize_t n = read(fd, challenge.data(), challenge.size());
    close(fd);
    if (n != static_cast<ssize_t>(challenge.size())) {
        return {};
    }
    return challenge;
}

static int32_t MapAuthResult(int32_t authResult)
{
    if (authResult == IAM_AUTH_SUCCESS || authResult == IAM_ERR_NO_VALID_SOLUTION) {
        return CM_SUCCESS;
    }
    if (authResult == static_cast<int32_t>(ResultCode::CANCELED)) {
        CertMgrCommand::WriteStdErr("User cancelled authentication\n");
        return CM_CMD_ERR_USER_CANCELLED;
    }
    CertMgrCommand::WriteStdErr("User authentication failed\n");
    return CMR_ERROR_AUTH_CHECK_FAILED;
}

int32_t AuthenticateUser(int32_t userId)
{
    if (userId < 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    WidgetAuthParam authParam;
    authParam.userId = userId;
    authParam.challenge = GenerateChallenge();
    authParam.authTypes = { AuthType::PIN };
    authParam.authTrustLevel = AuthTrustLevel::ATL2;
    authParam.reuseUnlockResult.isReuse = false;

    WidgetParam widgetParam;
    widgetParam.title = GetLocalizedTitle();
    widgetParam.windowMode = WindowModeType::UNKNOWN_WINDOW_MODE;

    std::mutex authMutex;
    std::condition_variable authCv;
    int32_t authResult = -1;
    bool authDone = false;
    auto callback = std::make_shared<AuthCallback>(authMutex, authCv, authResult, authDone);

    UserAuthClient::GetInstance().BeginWidgetAuth(authParam, widgetParam, callback);

    {
        std::unique_lock<std::mutex> lock(authMutex);
        authCv.wait(lock, [&authDone] { return authDone; });
    }

    return MapAuthResult(authResult);
}

class AdminAuthCallback final : public AccountSA::AuthorizationCallback {
public:
    explicit AdminAuthCallback(std::shared_ptr<std::promise<int32_t>> promise) : promise_(promise) {}
    ~AdminAuthCallback() = default;

    ErrCode OnResult(int32_t resultCode, const AccountSA::AuthorizationResult &result) override
    {
        if (resultCode == 0 &&
            result.resultCode == AccountSA::AuthorizationResultCode::AUTHORIZATION_SUCCESS) {
            promise_->set_value(CM_SUCCESS);
        } else if (result.resultCode == AccountSA::AuthorizationResultCode::AUTHORIZATION_CANCELED) {
            promise_->set_value(CM_CMD_ERR_USER_CANCELLED);
        } else {
            promise_->set_value(CMR_ERROR_AUTH_CHECK_FAILED);
        }
        return 0;
    }

    ErrCode OnConnectAbility(const AccountSA::ConnectAbilityInfo &info,
        const sptr<IRemoteObject> &callback) override
    {
        /* CLI tool does not handle UI extension connections */
        return 0;
    }

private:
    std::shared_ptr<std::promise<int32_t>> promise_;
};

int32_t AuthenticateAdmin()
{
    int32_t userId = CertMgrCommand::GetUserId();
    if (userId < 0) {
        CertMgrCommand::WriteStdErr("Failed to get current user ID\n");
        return CMR_ERROR_INVALID_OPERATION;
    }

    /* Build authorization options */
    AccountSA::AcquireAuthorizationOptions options;
    options.challenge = GenerateChallenge();
    options.isReuseNeeded = false;
    options.isInteractionAllowed = true;

    /* SubjectInfo now lives inside options; only pid and uid are required */
    AccountSA::SubjectInfo subjectInfo;
    subjectInfo.pid = static_cast<int32_t>(getpid());
    subjectInfo.uid = static_cast<int32_t>(getuid());
    options.subjectInfo = std::make_optional(subjectInfo);

    /* Set up async callback with promise */
    auto promise = std::make_shared<std::promise<int32_t>>();
    std::future<int32_t> future = promise->get_future();
    auto callback = std::make_shared<AdminAuthCallback>(promise);

    ErrCode err = AccountSA::AuthorizationClient::GetInstance().AcquireAuthorization(
        "ohos.privilege.manage_global_scope_certificate", options, callback);
    if (err != 0) {
        CertMgrCommand::WriteStdErr("AcquireAuthorization failed, errCode: " + std::to_string(err) + "\n");
        return CMR_ERROR_AUTH_CHECK_FAILED;
    }

    /* Wait for authorization result */
    int32_t authResult = future.get();
    if (authResult == CM_SUCCESS) {
        return CM_SUCCESS;
    }
    if (authResult == CM_CMD_ERR_USER_CANCELLED) {
        CertMgrCommand::WriteStdErr("User cancelled admin authorization\n");
        return CM_CMD_ERR_USER_CANCELLED;
    }
    CertMgrCommand::WriteStdErr("Admin authorization failed\n");
    return CMR_ERROR_AUTH_CHECK_FAILED;
}

int32_t CertMgrCommand::Execute(int argc, char *argv[])
{
    int32_t ret = ParseArgs(argc, argv);
    if (ret != 0) {
        return ret;
    }
    ret = Validate();
    if (ret != 0) {
        return ret;
    }
    return Run();
}

std::unique_ptr<CertMgrCommand> CertMgrCommand::Create(const std::string &name)
{
    if (name == "installUserCA") {
        return std::make_unique<InstallUserCACommand>();
    }
    return nullptr;
}

void CertMgrCommand::WriteStdErr(const std::string &msg)
{
    (void)fwrite(msg.c_str(), 1, msg.size(), stderr);
    (void)fflush(stderr);
}

void CertMgrCommand::WriteStdOut(const std::string &msg)
{
    (void)fwrite(msg.c_str(), 1, msg.size(), stdout);
    (void)fflush(stdout);
}

int32_t CertMgrCommand::GetUserId()
{
    std::vector<int32_t> ids;
    int32_t err = OHOS::AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != 0 || ids.empty()) {
        return -1;
    }
    return ids[0];
}

int32_t InstallUserCACommand::ParseArgs(int argc, char *argv[])
{
    /* check for -h (highest priority, ignore other errors) */
    for (int i = 2; i < argc; i++) {
        if (std::string(argv[i]) == "-h") {
            WriteStdOut(HELP_INSTALL);
            return -1; // help requested, skip Validate/Run
        }
    }

    /* parse all other parameters */
    int i = 2;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "-g") {
            hasG_ = true;
        } else if (arg == "-F") {
            if (i + 1 >= argc) {
                WriteStdErr("Missing value for -F parameter\n");
                WriteStdOut(HELP_INSTALL);
                return CM_CMD_ERR_PARAM_INVALID;
            }
            i++;
            std::string formatStr = argv[i];
            if (formatStr == "PEM_DER") {
                certFormat_ = PEM_DER;
            } else if (formatStr == "P7B") {
                certFormat_ = P7B;
            } else {
                WriteStdErr("Invalid certFileFormat: " + formatStr + "\n");
                WriteStdOut(HELP_INSTALL);
                return CM_CMD_ERR_PARAM_INVALID;
            }
        } else if (arg[0] == '-') {
            WriteStdErr("Unknown parameter: " + arg + "\n");
            WriteStdOut(HELP_INSTALL);
            return CM_CMD_ERR_PARAM_INVALID;
        } else {
            if (hasCertFile_) {
                WriteStdErr("Multiple certificate files specified. Only one certificate file is allowed.\n");
                WriteStdOut(HELP_INSTALL);
                return CM_CMD_ERR_PARAM_INVALID;
            }
            certFilePath_ = arg;
            hasCertFile_ = true;
        }
        i++;
    }
    return 0;
}

int32_t InstallUserCACommand::Validate()
{
    if (!hasCertFile_ && !HasPipeInput()) {
        WriteStdErr("certFile is required when no pipe input\n");
        return CM_CMD_ERR_PARAM_INVALID;
    }
    return 0;
}

int32_t InstallUserCACommand::ReadCertData(struct CmBlob &certBlob)
{
    if (hasCertFile_) {
        return ReadFileData(certFilePath_, certBlob);
    }
    return ReadPipeData(certBlob);
}

int32_t InstallUserCACommand::AuthenticateAndCheckPermission(int32_t &userId)
{
    int32_t authUserId = GetUserId();
    if (authUserId < 0) {
        WriteStdErr("Failed to get current user ID\n");
        return CMR_ERROR_INVALID_OPERATION;
    }

    if (hasG_) {
        int32_t ret = CheckGlobalUserCaPermission(authUserId);
        if (ret != CM_SUCCESS) {
            return ret;
        }
        userId = 0;
        return AuthenticateAdmin();
    }

    userId = static_cast<int32_t>(INIT_INVALID_VALUE);
    return AuthenticateUser(authUserId);
}

int32_t InstallUserCACommand::InstallPemDer(const struct CmBlob &certBlob, int32_t userId)
{
    static const uint8_t emptyAlias[] = { '\0' };
    struct CmBlob aliasBlob = { 1, const_cast<uint8_t *>(emptyAlias) };
    uint8_t *uriBuf = static_cast<uint8_t *>(malloc(MAX_LEN_URI));
    if (uriBuf == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    struct CmBlob certUri = { MAX_LEN_URI, uriBuf };
    int32_t ret = CmInstallUserCACert(&certBlob, &aliasBlob,
        static_cast<uint32_t>(userId), true, &certUri);
    if (ret == CM_SUCCESS && certUri.size > 0) {
        WriteStdOut(std::string(reinterpret_cast<char *>(certUri.data), certUri.size) + "\n");
    }
    free(uriBuf);
    return ret;
}

int32_t InstallUserCACommand::InstallP7B(const struct CmBlob &certBlob, int32_t userId)
{
    static const uint8_t emptyAlias[] = { '\0' };
    struct CmBlob aliasBlob = { 1, const_cast<uint8_t *>(emptyAlias) };
    struct CmInstallCertInfo installInfo = {
        .userCert = &certBlob,
        .certAlias = &aliasBlob,
        .userId = static_cast<uint32_t>(userId)
    };

    struct CertUriList certUriList = { 0, nullptr };
    int32_t ret = CmInstallUserTrustedP7BCert(&installInfo, true, &certUriList);
    if (ret == CM_SUCCESS) {
        for (uint32_t i = 0; i < certUriList.certCount; i++) {
            if (certUriList.uriList[i].data != nullptr) {
                uint32_t uriLen = strnlen(reinterpret_cast<char *>(certUriList.uriList[i].data),
                    certUriList.uriList[i].size);
                WriteStdOut(std::string(reinterpret_cast<char *>(certUriList.uriList[i].data), uriLen) + "\n");
            }
        }
    }
    if (certUriList.uriList != nullptr) {
        free(certUriList.uriList);
    }
    return ret;
}

int32_t InstallUserCACommand::Run()
{
    struct CmBlob certBlob = { 0, nullptr };
    int32_t ret = ReadCertData(certBlob);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    int32_t userId;
    ret = AuthenticateAndCheckPermission(userId);
    if (ret != CM_SUCCESS) {
        free(certBlob.data);
        return ret;
    }

    if (certFormat_ == PEM_DER) {
        ret = InstallPemDer(certBlob, userId);
    } else {
        ret = InstallP7B(certBlob, userId);
    }

    free(certBlob.data);
    if (ret != CM_SUCCESS) {
        WriteStdErr("Install failed: " + ConvertErrCodeToMsg(ret) + "\n");
    }
    return ret;
}

} // namespace CertMgr
