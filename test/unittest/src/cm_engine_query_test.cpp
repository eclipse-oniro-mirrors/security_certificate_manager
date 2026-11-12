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

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <ftw.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_query.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_cert_data_user.h"
#include "cm_cert_property_rdb.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;
using namespace CertmanagerTest;

namespace {
constexpr uint32_t TEST_QUERY_USER = 8899;
constexpr uint32_t TEST_QUERY_UID1 = 889901;
constexpr uint32_t TEST_QUERY_UID2 = 889902;
constexpr int NFTW_MAX_OPEN_FDS = 16;

/* user CA cert file names (also the cert URIs) used by this suite */
const char *URI_WITH_CONF = "oh:t=c;o=enginequery;u=8899;a=889901";
const char *URI_WITHOUT_CONF = "oh:t=c;o=noconf;u=8899;a=889902";
const char *URI_RDB_ALIAS = "oh:t=c;o=rdbalias;u=8899;a=889901";
const char *URI_RDB_LEVEL = "oh:t=c;o=leveltest;u=8899;a=889901";

/* roots owned by the SA that are created here only when missing */
const std::vector<std::string> NEEDED_ROOTS = {
    USER_CA_STORE,
    CERT_BACKUP_CONFIG_ROOT_DIR,
    "/data/service/el1/public/cert_manager_service/rdb",
};
std::vector<std::string> g_createdRoots;

/* isolated user subtrees touched by the cases below */
std::vector<std::string> UserSubtrees()
{
    return {
        std::string(USER_CA_STORE) + std::to_string(TEST_QUERY_USER),
        std::string(CERT_BACKUP_CONFIG_ROOT_DIR) + "/" + std::to_string(TEST_QUERY_USER),
    };
}

/* RDB rows inserted by the cases below */
const std::vector<std::string> RDB_URIS = {
    URI_WITH_CONF,
    URI_RDB_ALIAS,
    URI_RDB_LEVEL,
};

int RemoveTreeEntry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return (type == FTW_DP) ? rmdir(path) : remove(path);
}

void RemoveTree(const std::string &root)
{
    if (root.empty()) {
        return;
    }
    (void)nftw(root.c_str(), RemoveTreeEntry, NFTW_MAX_OPEN_FDS, FTW_DEPTH | FTW_PHYS);
}

void MakeDirOrExists(const std::string &path)
{
    int32_t ret = CmMakeDir(path.c_str());
    ASSERT_TRUE(ret == CMR_OK || ret == CMR_ERROR_ALREADY_EXISTS) << "mkdir failed for " << path;
}

struct CmContext BuildContext(uint32_t userId, uint32_t uid)
{
    struct CmContext context;
    (void)memset_s(&context, sizeof(context), 0, sizeof(context));
    context.userId = userId;
    context.uid = uid;
    return context;
}

void DeleteRdbRowsQuietly()
{
    for (const auto &uri : RDB_URIS) {
        (void)DeleteCertProperty(uri.c_str());
    }
}

uint32_t UriIndexOf(const struct CertBlob *certBlob, uint32_t count, const char *uriStr)
{
    for (uint32_t i = 0; i < count; i++) {
        if (certBlob->uri[i].data != nullptr && strcmp((char *)certBlob->uri[i].data, uriStr) == 0) {
            return i;
        }
    }
    return count;
}

struct CertBlob *AllocZeroedCertBlob(void)
{
    struct CertBlob *certBlob = (struct CertBlob *)malloc(sizeof(struct CertBlob));
    if (certBlob != nullptr) {
        (void)memset_s(certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    }
    return certBlob;
}
} // namespace

class CmEngineQueryTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        CmTestCommon::SetTestEnvironment(GetSelfTokenID());
        if (CmIsDirExist(CERT_DIR) != CMR_OK) {
            (void)CmMakeDir(CERT_DIR);
            g_createdRoots.emplace_back(CERT_DIR);
        }
        for (const auto &root : NEEDED_ROOTS) {
            if (CmIsDirExist(root.c_str()) != CMR_OK) {
                (void)CmMakeDir(root.c_str());
                g_createdRoots.emplace_back(root);
            }
        }
        /* query.c consults the cert_property table for user store alias/level */
        ASSERT_EQ(CreateCertPropertyRdb(), CM_SUCCESS);
    }

    static void TearDownTestCase(void)
    {
        CmTestCommon::ResetTestEnvironment();
        /* best effort removal of the roots this suite created itself */
        for (const auto &root : g_createdRoots) {
            (void)rmdir(root.c_str());
        }
        g_createdRoots.clear();
    }

    void SetUp() {}

    void TearDown()
    {
        for (const auto &subtree : UserSubtrees()) {
            RemoveTree(subtree);
        }
        DeleteRdbRowsQuietly();
    }
};

/**
 * @tc.name: CmGetCertPathListEmptyStore_001
 * @tc.desc: empty user CA store for the isolated user returns an empty path list.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertPathListEmptyStore_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_QUERY_USER, TEST_QUERY_UID1);
    struct CmMutableBlob pathList = { 0, nullptr };

    int32_t ret = CmGetCertPathList(&context, CM_USER_TRUSTED_STORE, &pathList);
    EXPECT_EQ(ret, CM_SUCCESS);
    EXPECT_EQ(pathList.size, 0u);
    EXPECT_EQ(pathList.data, nullptr);
}

/**
 * @tc.name: CmGetCertPathListMultiUid_001
 * @tc.desc: one path entry is returned per uid directory under the user CA store.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertPathListMultiUid_001, TestSize.Level0)
{
    const std::string userIdDir = std::string(USER_CA_STORE) + std::to_string(TEST_QUERY_USER);
    MakeDirOrExists(userIdDir + "/" + std::to_string(TEST_QUERY_UID1));
    MakeDirOrExists(userIdDir + "/" + std::to_string(TEST_QUERY_UID2));

    struct CmContext context = BuildContext(TEST_QUERY_USER, TEST_QUERY_UID1);
    struct CmMutableBlob pathList = { 0, nullptr };

    ASSERT_EQ(CmGetCertPathList(&context, CM_USER_TRUSTED_STORE, &pathList), CM_SUCCESS);
    ASSERT_EQ(pathList.size, 2u);

    struct CmMutableBlob *paths = (struct CmMutableBlob *)pathList.data;
    bool seenUid1 = false;
    bool seenUid2 = false;
    for (uint32_t i = 0; i < pathList.size; i++) {
        ASSERT_NE(paths[i].data, nullptr);
        const std::string path((char *)paths[i].data);
        if (path.rfind("/" + std::to_string(TEST_QUERY_UID1)) == path.size() - std::to_string(TEST_QUERY_UID1).size()
            - 1) {
            seenUid1 = true;
        }
        if (path.rfind("/" + std::to_string(TEST_QUERY_UID2)) == path.size() - std::to_string(TEST_QUERY_UID2).size()
            - 1) {
            seenUid2 = true;
        }
    }
    EXPECT_TRUE(seenUid1);
    EXPECT_TRUE(seenUid2);
    CmFreePathList(paths, pathList.size);
}

/**
 * @tc.name: CmGetCertPathListUnsupportedStore_001
 * @tc.desc: system store is not a user level store and is rejected by the path list builder.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertPathListUnsupportedStore_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(TEST_QUERY_USER, TEST_QUERY_UID1);
    struct CmMutableBlob pathList = { 0, nullptr };

    EXPECT_EQ(CmGetCertPathList(&context, CM_SYSTEM_TRUSTED_STORE, &pathList),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
    EXPECT_EQ(pathList.data, nullptr);
}

/**
 * @tc.name: CmGetSysCertPathList_001
 * @tc.desc: system CA path list always contains the common algorithm store first.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetSysCertPathList_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(0, 0);
    struct CmMutableBlob pathList = { 0, nullptr };

    ASSERT_EQ(CmGetSysCertPathList(&context, &pathList), CM_SUCCESS);
    ASSERT_TRUE(pathList.size == SYSTEM_CA_PATH_COUNT_1 || pathList.size == SYSTEM_CA_PATH_COUNT_2);
    ASSERT_NE(pathList.data, nullptr);

    struct CmMutableBlob *paths = (struct CmMutableBlob *)pathList.data;
    ASSERT_NE(paths[SYSTEM_CA_PATH_INDEX].data, nullptr);
    EXPECT_EQ(strcmp((char *)paths[SYSTEM_CA_PATH_INDEX].data, SYSTEM_CA_STORE), 0);
    if (pathList.size == SYSTEM_CA_PATH_COUNT_2) {
        ASSERT_NE(paths[SYSTEM_CA_GM_PATH_INDEX].data, nullptr);
        EXPECT_EQ(strcmp((char *)paths[SYSTEM_CA_GM_PATH_INDEX].data, SYSTEM_CA_STORE_GM), 0);
    }
    CmFreePathList(paths, pathList.size);
}

/**
 * @tc.name: CreateCertFileListEmpty_001
 * @tc.desc: an empty path list produces no cert file entries.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CreateCertFileListEmpty_001, TestSize.Level0)
{
    struct CmMutableBlob pathList = { 0, nullptr };
    struct CmMutableBlob certFileList = { 0, nullptr };

    EXPECT_EQ(CreateCertFileList(&pathList, &certFileList), CM_SUCCESS);
    EXPECT_EQ(certFileList.size, 0u);
    EXPECT_EQ(certFileList.data, nullptr);
}

/**
 * @tc.name: SystemCertListSweep_001
 * @tc.desc: full enumeration of the preset system CA certificates through the query pipeline.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, SystemCertListSweep_001, TestSize.Level0)
{
    struct CmContext context = BuildContext(0, 0);
    struct CmMutableBlob pathList = { 0, nullptr };
    ASSERT_EQ(CmGetSysCertPathList(&context, &pathList), CM_SUCCESS);

    struct CmMutableBlob certFileList = { 0, nullptr };
    ASSERT_EQ(CreateCertFileList(&pathList, &certFileList), CM_SUCCESS);
    struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList.data;

    /* the system image ships the preset CA certificates; tolerate a stripped image */
    if (certFileList.size > 0) {
        struct CertBlob *certBlob = AllocZeroedCertBlob();
        ASSERT_NE(certBlob, nullptr);
        uint32_t status[MAX_COUNT_CERTIFICATE_ALL] = { 0 };

        ASSERT_EQ(CmGetCertListInfo(&context, CM_SYSTEM_TRUSTED_STORE, &certFileList, certBlob, status),
            CM_SUCCESS);

        uint32_t withUri = 0;
        for (uint32_t i = 0; i < certFileList.size; i++) {
            EXPECT_EQ(status[i], CERT_STATUS_ENABLED);
            if (certBlob->uri[i].data != nullptr && certBlob->uri[i].size > 0) {
                withUri++;
                EXPECT_NE(certBlob->certAlias[i].data, nullptr);
                EXPECT_GT(certBlob->certAlias[i].size, 0u);
                EXPECT_GT(certBlob->subjectName[i].size, 0u);
            }
        }
        EXPECT_GT(withUri, 0u);
        CmFreeCertBlob(certBlob);
        free(certBlob);
    }
    CmFreeCertFiles(cFileList, certFileList.size);
    CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
}

/**
 * @tc.name: UserCertListInfoRoundTrip_001
 * @tc.desc: user CA list pipeline: RDB alias, subject name, uri copy and enabled/disabled status.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, UserCertListInfoRoundTrip_001, TestSize.Level0)
{
    const std::string userIdDir = std::string(USER_CA_STORE) + std::to_string(TEST_QUERY_USER);
    const std::string uid1Dir = userIdDir + "/" + std::to_string(TEST_QUERY_UID1);
    const std::string uid2Dir = userIdDir + "/" + std::to_string(TEST_QUERY_UID2);
    MakeDirOrExists(uid1Dir);
    MakeDirOrExists(uid2Dir);

    const uint8_t *certData = (const uint8_t *)g_certData06;
    uint32_t certDataLen = strlen(g_certData06);
    ASSERT_EQ(CmFileWrite(uid1Dir.c_str(), URI_WITH_CONF, 0, const_cast<uint8_t *>(certData), certDataLen), CMR_OK);
    ASSERT_EQ(CmFileWrite(uid2Dir.c_str(), URI_WITHOUT_CONF, 0, const_cast<uint8_t *>(certData), certDataLen),
        CMR_OK);

    /* one cert gets an RDB alias row and an enabled config file, the other stays plain */
    (void)DeleteCertProperty(URI_WITH_CONF);
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    (void)strcpy_s(prop.uri, sizeof(prop.uri), URI_WITH_CONF);
    (void)strcpy_s(prop.alias, sizeof(prop.alias), "RdbAliasCert");
    (void)strcpy_s(prop.subjectName, sizeof(prop.subjectName), "subject");
    (void)strcpy_s(prop.certType, sizeof(prop.certType), "wlan_eap");
    prop.certStore = static_cast<int32_t>(CM_USER_TRUSTED_STORE);
    prop.userId = static_cast<int32_t>(TEST_QUERY_USER);
    prop.uid = static_cast<int32_t>(TEST_QUERY_UID1);
    prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(InsertCertProperty(&prop), CM_SUCCESS);

    char confUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ASSERT_EQ(CmGetCertConfUidDir(TEST_QUERY_USER, TEST_QUERY_UID1, confUidDir, sizeof(confUidDir)), CM_SUCCESS);
    const std::string confFile = std::string(confUidDir) + "/" + URI_WITH_CONF + CERT_CONFIG_FILE_SUFFIX;
    const uint8_t flag[] = "1";
    ASSERT_EQ(CmFileWrite(nullptr, confFile.c_str(), 0, const_cast<uint8_t *>(flag), sizeof(flag) - 1), CMR_OK);

    struct CmContext context = BuildContext(TEST_QUERY_USER, TEST_QUERY_UID1);
    struct CmMutableBlob pathList = { 0, nullptr };
    ASSERT_EQ(CmGetCertPathList(&context, CM_USER_TRUSTED_STORE, &pathList), CM_SUCCESS);
    ASSERT_EQ(pathList.size, 2u);

    struct CmMutableBlob certFileList = { 0, nullptr };
    ASSERT_EQ(CreateCertFileList(&pathList, &certFileList), CM_SUCCESS);
    ASSERT_EQ(certFileList.size, 2u);

    struct CertBlob *certBlob = AllocZeroedCertBlob();
    ASSERT_NE(certBlob, nullptr);
    uint32_t status[MAX_COUNT_CERTIFICATE_ALL] = { 0 };
    ASSERT_EQ(CmGetCertListInfo(&context, CM_USER_TRUSTED_STORE, &certFileList, certBlob, status), CM_SUCCESS);

    uint32_t idxWithConf = UriIndexOf(certBlob, certFileList.size, URI_WITH_CONF);
    uint32_t idxWithoutConf = UriIndexOf(certBlob, certFileList.size, URI_WITHOUT_CONF);
    ASSERT_NE(idxWithConf, certFileList.size);
    ASSERT_NE(idxWithoutConf, certFileList.size);

    /* alias prefers the RDB row when present and falls back to the uri object otherwise */
    EXPECT_EQ(strcmp((char *)certBlob->certAlias[idxWithConf].data, "RdbAliasCert"), 0);
    EXPECT_EQ(strcmp((char *)certBlob->certAlias[idxWithoutConf].data, "noconf"), 0);
    EXPECT_GT(certBlob->subjectName[idxWithConf].size, 0u);
    EXPECT_GT(certBlob->subjectName[idxWithoutConf].size, 0u);
    EXPECT_EQ(status[idxWithConf], CERT_STATUS_ENABLED);
    EXPECT_EQ(status[idxWithoutConf], CERT_STATUS_DISABLED);

    CmFreeCertBlob(certBlob);
    free(certBlob);
    CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
}

/**
 * @tc.name: CmGetCertListInfoUriDecodeFail_001
 * @tc.desc: a non uri file name in the user CA store aborts the list with a uri error.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertListInfoUriDecodeFail_001, TestSize.Level0)
{
    const std::string uid1Dir =
        std::string(USER_CA_STORE) + std::to_string(TEST_QUERY_USER) + "/" + std::to_string(TEST_QUERY_UID1);
    MakeDirOrExists(uid1Dir);

    const uint8_t payload[] = "notacert";
    ASSERT_EQ(CmFileWrite(uid1Dir.c_str(), "garbage.txt", 0, const_cast<uint8_t *>(payload), sizeof(payload) - 1),
        CMR_OK);

    struct CmContext context = BuildContext(TEST_QUERY_USER, TEST_QUERY_UID1);
    struct CmMutableBlob pathList = { 0, nullptr };
    ASSERT_EQ(CmGetCertPathList(&context, CM_USER_TRUSTED_STORE, &pathList), CM_SUCCESS);
    ASSERT_EQ(pathList.size, 1u);

    struct CmMutableBlob certFileList = { 0, nullptr };
    ASSERT_EQ(CreateCertFileList(&pathList, &certFileList), CM_SUCCESS);
    ASSERT_EQ(certFileList.size, 1u);

    struct CertBlob *certBlob = AllocZeroedCertBlob();
    ASSERT_NE(certBlob, nullptr);
    uint32_t status[MAX_COUNT_CERTIFICATE_ALL] = { 0 };
    EXPECT_EQ(CmGetCertListInfo(&context, CM_USER_TRUSTED_STORE, &certFileList, certBlob, status),
        CMR_ERROR_INVALID_ARGUMENT_URI);

    CmFreeCertBlob(certBlob);
    free(certBlob);
    CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
}

/**
 * @tc.name: CmGetMatchedCertIndex_001
 * @tc.desc: index lookup returns the match position, the list size on miss and 256 for empty lists.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetMatchedCertIndex_001, TestSize.Level0)
{
    struct CmMutableBlob emptyList = { 0, nullptr };
    uint8_t uriBuf[] = "uriB";
    struct CmBlob missUri = { sizeof(uriBuf) - 1, uriBuf };
    EXPECT_EQ(CmGetMatchedCertIndex(&emptyList, &missUri), MAX_COUNT_CERTIFICATE);

    struct CertFileInfo files[3] = {};
    uint8_t nameA[] = "uriA";
    uint8_t nameB[] = "uriB";
    files[0].fileName.data = nameA;
    files[0].fileName.size = sizeof(nameA) - 1;
    files[1].fileName.data = nameB;
    files[1].fileName.size = sizeof(nameB) - 1;
    /* files[2] keeps a null file name to exercise the corrupted entry branch */

    struct CmMutableBlob list = { 3, (uint8_t *)files };
    EXPECT_EQ(CmGetMatchedCertIndex(&list, &missUri), 1u);

    uint8_t missBuf[] = "uriC";
    struct CmBlob miss = { sizeof(missBuf) - 1, missBuf };
    EXPECT_EQ(CmGetMatchedCertIndex(&list, &miss), 3u);

    /* corrupted entry is skipped, match still found in later entries */
    files[0].fileName.data = nullptr;
    files[0].fileName.size = 0;
    EXPECT_EQ(CmGetMatchedCertIndex(&list, &missUri), 1u);
}

/**
 * @tc.name: CmGetCertAlias_001
 * @tc.desc: alias resolution for user store takes the RDB row when present.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertAlias_001, TestSize.Level0)
{
    (void)DeleteCertProperty(URI_RDB_ALIAS);
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    (void)strcpy_s(prop.uri, sizeof(prop.uri), URI_RDB_ALIAS);
    (void)strcpy_s(prop.alias, sizeof(prop.alias), "MyRdbAlias");
    (void)strcpy_s(prop.subjectName, sizeof(prop.subjectName), "subject");
    (void)strcpy_s(prop.certType, sizeof(prop.certType), "wlan_eap");
    prop.certStore = static_cast<int32_t>(CM_USER_TRUSTED_STORE);
    prop.userId = static_cast<int32_t>(TEST_QUERY_USER);
    prop.uid = static_cast<int32_t>(TEST_QUERY_UID1);
    prop.level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(InsertCertProperty(&prop), CM_SUCCESS);

    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob certData = { strlen(g_certData06), (uint8_t *)g_certData06 };

    ASSERT_EQ(CmGetCertAlias(CM_USER_TRUSTED_STORE, URI_RDB_ALIAS, &certData, &alias), CM_SUCCESS);
    EXPECT_EQ(strcmp((char *)alias.data, "MyRdbAlias"), 0);
    EXPECT_EQ(alias.size, strlen("MyRdbAlias") + 1);
}

/**
 * @tc.name: CmGetCertAliasFallback_001
 * @tc.desc: alias resolution for user store falls back to the uri object without an RDB row.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertAliasFallback_001, TestSize.Level0)
{
    (void)DeleteCertProperty(URI_WITHOUT_CONF);

    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob certData = { strlen(g_certData06), (uint8_t *)g_certData06 };

    ASSERT_EQ(CmGetCertAlias(CM_USER_TRUSTED_STORE, URI_WITHOUT_CONF, &certData, &alias), CM_SUCCESS);
    EXPECT_EQ(strcmp((char *)alias.data, "noconf"), 0);
    EXPECT_EQ(alias.size, strlen("noconf") + 1);
}

/**
 * @tc.name: CmGetCertAliasSystemStore_001
 * @tc.desc: alias resolution for the system store extracts the subject O/CN from the certificate.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertAliasSystemStore_001, TestSize.Level0)
{
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob certData = { strlen(g_certData06), (uint8_t *)g_certData06 };

    ASSERT_EQ(CmGetCertAlias(CM_SYSTEM_TRUSTED_STORE, "ignored", &certData, &alias), CM_SUCCESS);
    EXPECT_GT(alias.size, 1u);
    EXPECT_GT(strlen((char *)alias.data), 0u);

    uint8_t garbage[] = "garbage";
    struct CmBlob badCert = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmGetCertAlias(CM_SYSTEM_TRUSTED_STORE, "ignored", &badCert, &alias),
        CMR_ERROR_INVALID_CERT_FORMAT);

    /* unsupported store */
    EXPECT_EQ(CmGetCertAlias(CM_CREDENTIAL_STORE, URI_WITHOUT_CONF, &certData, &alias),
        CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE);
}

/**
 * @tc.name: CmGetCertAliasInvalidUri_001
 * @tc.desc: invalid uri input is rejected before any alias resolution.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetCertAliasInvalidUri_001, TestSize.Level0)
{
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob certData = { strlen(g_certData06), (uint8_t *)g_certData06 };

    /* not a uri at all */
    EXPECT_EQ(CmGetCertAlias(CM_USER_TRUSTED_STORE, "garbage", &certData, &alias),
        CMR_ERROR_INVALID_ARGUMENT_URI);
    /* valid uri shape but empty object */
    EXPECT_EQ(CmGetCertAlias(CM_USER_TRUSTED_STORE, "oh:t=c;o=;u=8899;a=889901", &certData, &alias),
        CMR_ERROR_INVALID_ARGUMENT_URI);
}

/**
 * @tc.name: CmGetAliasFromSubjectName_001
 * @tc.desc: alias from subject name takes the first subject item of the certificate.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmGetAliasFromSubjectName_001, TestSize.Level0)
{
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob alias = { sizeof(aliasBuf), aliasBuf };
    struct CmBlob certData = { strlen(g_certData06), (uint8_t *)g_certData06 };

    ASSERT_EQ(CmGetAliasFromSubjectName(&certData, &alias), CM_SUCCESS);
    EXPECT_GT(alias.size, 0u);

    uint8_t garbage[] = "garbage";
    struct CmBlob badCert = { sizeof(garbage) - 1, garbage };
    EXPECT_EQ(CmGetAliasFromSubjectName(&badCert, &alias), CMR_ERROR_INVALID_CERT_FORMAT);
}

/**
 * @tc.name: GetRdbAuthStorageLevel_001
 * @tc.desc: auth storage level query returns the RDB level, or ERROR_LEVEL when no row exists.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, GetRdbAuthStorageLevel_001, TestSize.Level0)
{
    uint8_t uriBuf[MAX_LEN_URI] = { 0 };
    (void)strcpy_s((char *)uriBuf, sizeof(uriBuf), URI_RDB_LEVEL);
    struct CmBlob keyUri = { sizeof(uriBuf), uriBuf };
    enum CmAuthStorageLevel level = CM_AUTH_STORAGE_LEVEL_EL1;

    EXPECT_EQ(GetRdbAuthStorageLevel(nullptr, &level), CMR_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(GetRdbAuthStorageLevel(&keyUri, nullptr), CMR_ERROR_INVALID_ARGUMENT);

    /* no RDB row for this uri -> level stays the ERROR_LEVEL preset */
    (void)DeleteCertProperty(URI_RDB_LEVEL);
    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, ERROR_LEVEL);

    /* insert a row and observe the stored level */
    struct CertProperty prop;
    (void)memset_s(&prop, sizeof(prop), 0, sizeof(prop));
    (void)strcpy_s(prop.uri, sizeof(prop.uri), URI_RDB_LEVEL);
    (void)strcpy_s(prop.alias, sizeof(prop.alias), "levelcert");
    (void)strcpy_s(prop.subjectName, sizeof(prop.subjectName), "subject");
    (void)strcpy_s(prop.certType, sizeof(prop.certType), "wlan_eap");
    prop.certStore = static_cast<int32_t>(CM_USER_TRUSTED_STORE);
    prop.userId = static_cast<int32_t>(TEST_QUERY_USER);
    prop.uid = static_cast<int32_t>(TEST_QUERY_UID1);
    prop.level = CM_AUTH_STORAGE_LEVEL_EL2;
    ASSERT_EQ(InsertCertProperty(&prop), CM_SUCCESS);

    level = CM_AUTH_STORAGE_LEVEL_EL1;
    ASSERT_EQ(GetRdbAuthStorageLevel(&keyUri, &level), CM_SUCCESS);
    EXPECT_EQ(level, CM_AUTH_STORAGE_LEVEL_EL2);
}

/**
 * @tc.name: CmFreeHelpers_001
 * @tc.desc: free helpers tolerate null input without crashing.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineQueryTest, CmFreeHelpers_001, TestSize.Level0)
{
    CmFreePathList(nullptr, 0);
    CmFreeCertFiles(nullptr, 0);
    CmFreeCertBlob(nullptr);
}
