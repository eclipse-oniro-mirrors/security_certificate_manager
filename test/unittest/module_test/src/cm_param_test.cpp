/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "securec.h"

#include "cm_param.h"
#include "cm_type.h"

using namespace testing::ext;
namespace {
class CmParamTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CmParamTest::SetUpTestCase(void)
{
}

void CmParamTest::TearDownTestCase(void)
{
}

void CmParamTest::SetUp()
{
}

void CmParamTest::TearDown()
{
}

/**
* @tc.name: CmParamTest001
* @tc.desc: test CmInitParamSet nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest001, TestSize.Level0)
{
    int32_t ret = CmInitParamSet(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest002
* @tc.desc: test CmAddParams paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest002, TestSize.Level0)
{
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CmAddParams(nullptr, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest003
* @tc.desc: test CmAddParams param is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest003, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmAddParams(paramSet, nullptr, 0);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest004
* @tc.desc: test CmAddParams paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest004, TestSize.Level0)
{
    struct CmParamSet paramSet = { CM_PARAM_SET_MAX_SIZE + 1, 0 };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CmAddParams(&paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest005
* @tc.desc: test CmAddParams param cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest005, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(paramSet, param, CM_DEFAULT_PARAM_CNT + 1);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest006
* @tc.desc: test CmAddParams paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest006, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
    paramSet->paramsCnt = CM_DEFAULT_PARAM_CNT;

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest007
* @tc.desc: test CmAddParams param tag blob.data is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest007, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmBlob tempBlob = { 0, nullptr };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest008
* @tc.desc: test CmAddParams param tag blob.size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest008, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test";
    struct CmBlob tempBlob = { UINT32_MAX, tempBuf };
    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CmAddParams(paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest009
* @tc.desc: test CmGetParam paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest009, TestSize.Level0)
{
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(nullptr, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest010
* @tc.desc: test CmGetParam out param is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest010, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmGetParam(paramSet, CM_TAG_PARAM0_BUFFER, nullptr);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest011
* @tc.desc: test CmGetParam paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest011, TestSize.Level0)
{
    struct CmParamSet paramSet = {CM_PARAM_SET_MAX_SIZE + 1, 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest012
* @tc.desc: test CmGetParam paramSet size is invalid (smaller than struct size)
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest012, TestSize.Level0)
{
    struct CmParamSet paramSet = { sizeof(struct CmParamSet) - 1, 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

/**
* @tc.name: CmParamTest013
* @tc.desc: test CmGetParam paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest013, TestSize.Level0)
{
    struct CmParamSet paramSet = { sizeof(struct CmParamSet), 1 };
    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(&paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);
}

static void ConstrutParamSet(struct CmParamSet **paramSet)
{
    int32_t ret = CmInitParamSet(paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    struct CmParam param[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CmAddParams(*paramSet, param, sizeof(param) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);
}

/**
* @tc.name: CmParamTest014
* @tc.desc: test CmGetParam normal testcase
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest014, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(paramSet, CM_TAG_PARAM0_BOOL, &param);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest015
* @tc.desc: test CmGetParam param not exist
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest015, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    struct CmParam *param = nullptr;
    int32_t ret = CmGetParam(paramSet, CM_TAG_PARAM0_BUFFER, &param);
    EXPECT_EQ(ret, CMR_ERROR_PARAM_NOT_EXIST);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest017
* @tc.desc: test CmBuildParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest017, TestSize.Level0)
{
    int32_t ret = CmBuildParamSet(nullptr);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);

    /* test CmFreeParamSet paramSet is nullptr */
    CmFreeParamSet(nullptr);
}

/**
* @tc.name: CmParamTest018
* @tc.desc: test CmBuildParamSet *paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest018, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
* @tc.name: CmParamTest019
* @tc.desc: test CmBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest019, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    paramSet->paramSetSize = sizeof(struct CmParamSet) - 1;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest020
* @tc.desc: test CmBuildParamSet param tag blob size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest020, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test020";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM1_BUFFER;
    paramSet->params[0].blob.size = UINT32_MAX;
    paramSet->params[0].blob.data = tempBuf;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest021
* @tc.desc: test CmBuildParamSet param tag blob data is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest021, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test021";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = nullptr;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest022
* @tc.desc: test CmBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest022, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test022";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf) + 1; /* invalid size */
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest023
* @tc.desc: test CmGetParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest023, TestSize.Level0)
{
    struct CmParamSet *outParamSet = nullptr;
    int32_t ret = CmGetParamSet(nullptr, 0, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_NULL_POINTER);
}

/**
* @tc.name: CmParamTest024
* @tc.desc: test CmGetParamSet normal testcase
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest024, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);
    ASSERT_TRUE(paramSet != nullptr);

    struct CmParamSet *outParamSet = nullptr;
    int32_t ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest025
* @tc.desc: test CmGetParamSet param tag blob size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest025, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test025";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM1_BUFFER;
    paramSet->params[0].blob.size = UINT32_MAX;
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest026
* @tc.desc: test CmGetParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest026, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test026";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf) + 1; /* invalid size */
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest027
* @tc.desc: test CmGetParamSet normal testcase tag include blob
* @tc.type: FUNC
* @tc.require: AR000H0MIA /SR000H09NA
*/
HWTEST_F(CmParamTest, CmParamTest027, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test027";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest028
* @tc.desc: test CmBuildParamSet size > CM_DEFAULT_PARAM_SET_SIZE (triggers realloc path)
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest028, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    /* Add a large blob param so that total paramSet size exceeds CM_DEFAULT_PARAM_SET_SIZE (512) */
    uint32_t blobSize = 600;
    uint8_t *largeBuf = (uint8_t *)malloc(blobSize);
    ASSERT_NE(largeBuf, nullptr);
    (void)memset_s(largeBuf, largeBuf, 'A', blobSize);
    struct CmParam param = {
        .tag = CM_TAG_PARAM0_BUFFER,
        .blob = { blobSize, largeBuf }
    };
    ret = CmAddParams(paramSet, &param, 1);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    free(largeBuf);
}

/**
* @tc.name: CmParamTest029
* @tc.desc: test CmGetParamSet with FreshParamSet offset > size (malformed paramSet)
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest029, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    /* Create a malformed paramSet: paramsCnt > 0 but paramSetSize only accounts for header
       so FreshParamSet will detect offset > size */
    paramSet->paramsCnt = 2;
    paramSet->paramSetSize = sizeof(struct CmParamSet) + sizeof(struct CmParam); /* too small for 2 params */

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest030
* @tc.desc: test CmGetParamSet with FreshParamSet blob.size overflow (offset + blob.size overflow)
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest030, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "this is for test030";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(struct CmParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CM_TAG_PARAM0_BUFFER;
    /* Set blob.size to a value that would cause offset + blob.size to overflow uint32_t */
    paramSet->params[0].blob.size = UINT32_MAX - 10;
    paramSet->params[0].blob.data = tempBuf;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest031
* @tc.desc: test CmAddParams with blob.size that would overflow paramSetSize
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest031, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "overflow test";
    struct CmParam param = {
        .tag = CM_TAG_PARAM0_BUFFER,
        .blob = { UINT32_MAX, tempBuf }
    };
    ret = CmAddParams(paramSet, &param, 1);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest032
* @tc.desc: test CmBuildParamSet with FreshParamSet offset > size (malformed)
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest032, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    /* Malformed: paramsCnt > 0 but paramSetSize only has room for header + 1 param,
       but we claim 2 params -> FreshParamSet offset > size */
    paramSet->paramsCnt = 2;
    paramSet->paramSetSize = sizeof(struct CmParamSet) + sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM0_BOOL;
    paramSet->params[0].boolParam = true;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest033
* @tc.desc: test CmBuildParamSet with blob param that triggers memcpy_s copy path (isCopy=true)
*           This covers the isCopy && memcpy_s branch at L89 in CmFreshParamSet.
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest033, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t tempBuf[] = "test blob for copy path";
    struct CmParam param = {
        .tag = CM_TAG_PARAM0_BUFFER,
        .blob = { sizeof(tempBuf), tempBuf }
    };
    ret = CmAddParams(paramSet, &param, 1);
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest034
* @tc.desc: test CmBuildParamSet with multiple blob params (isCopy=true, multiple memcpy_s)
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest034, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    uint8_t buf1[] = "first blob";
    uint8_t buf2[] = "second blob data";
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = { sizeof(buf1), buf1 } },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = { sizeof(buf2), buf2 } },
    };
    ret = CmAddParams(paramSet, params, sizeof(params) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest035
* @tc.desc: test CmBuildParamSet with non-blob params only (no memcpy_s copy path)
*           This covers the case where CmGetTagType != CM_TAG_TYPE_BYTES for all params.
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest035, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BOOL, .boolParam = true },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = 42 },
    };
    ret = CmAddParams(paramSet, params, sizeof(params) / sizeof(struct CmParam));
    EXPECT_EQ(ret, CM_SUCCESS);

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest036
* @tc.desc: test CmGetParamSet with invalid paramSet (size mismatch)
*           This covers FreshParamSet error path where paramSetSize != offset.
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest036, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    /* Set up a paramSet with a non-BYTES param but with paramSetSize that doesn't match offset */
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize = sizeof(struct CmParamSet) + sizeof(struct CmParam) + 10; /* extra 10 bytes */
    paramSet->params[0].tag = CM_TAG_PARAM0_BOOL;
    paramSet->params[0].boolParam = true;

    struct CmParamSet *outParamSet = nullptr;
    ret = CmGetParamSet(paramSet, paramSet->paramSetSize, &outParamSet);
    /* FreshParamSet will detect paramSetSize != offset */
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
    CmFreeParamSet(&outParamSet);
}

/**
* @tc.name: CmParamTest037
* @tc.desc: test CmBuildParamSet with invalid paramSet (CmFreshParamSet ret != CM_SUCCESS)
*           This covers the L70 branch in CmFreshParamSet.
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest037, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    /* Set paramSetSize to a value that will fail CmCheckParamSet in CmFreshParamSet */
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize = sizeof(struct CmParamSet) + sizeof(struct CmParam);
    paramSet->params[0].tag = CM_TAG_PARAM0_BOOL;
    /* Now corrupt the paramSetSize so CmCheckParamSet fails in CmFreshParamSet */
    paramSet->paramSetSize = CM_PARAM_SET_MAX_SIZE + 1;

    ret = CmBuildParamSet(&paramSet);
    EXPECT_EQ(ret, CMR_ERROR_INVALID_PARAMSET_ARG);

    CmFreeParamSet(&paramSet);
}

/**
* @tc.name: CmParamTest038
* @tc.desc: test CmFreeParamSet with valid paramSet
* @tc.type: FUNC
*/
HWTEST_F(CmParamTest, CmParamTest038, TestSize.Level0)
{
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = CmInitParamSet(&paramSet);
    ASSERT_EQ(ret, CM_SUCCESS);

    CmFreeParamSet(&paramSet);
    EXPECT_EQ(paramSet, nullptr);
}
} // end of namespace
