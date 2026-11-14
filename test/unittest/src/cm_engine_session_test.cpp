/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Direct engine tests for the sign/verify session table
 * (cert_manager_session_mgr.c). The session APIs only touch the in-process
 * list; the synthetic handles only make the cleanup HksAbort call fail
 * harmlessly, so neither HUKS state nor caller permissions are needed. */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "cert_manager_session_mgr.h"
#include "cm_type.h"
#include "securec.h"

using namespace testing::ext;

namespace {
constexpr uint32_t TEST_SESSION_USER_A = 7788; /* exclusive user ids keep the shared list tidy */
constexpr uint32_t TEST_SESSION_USER_B = 7789;
constexpr uint32_t TEST_SESSION_UID_A1 = 778801;
constexpr uint32_t TEST_SESSION_UID_A2 = 778802;
constexpr uint32_t TEST_SESSION_UID_B1 = 778901;
constexpr uint32_t TEST_SESSION_LIMIT = 15; /* MAX_OPERATIONS_COUNT */
constexpr uint32_t TEST_SESSION_GUARD_INDEX = TEST_SESSION_LIMIT + 2; /* highest handle index ever used */
constexpr uint64_t TEST_SESSION_HANDLE_BASE = 0x7788000000000000ULL;

struct CmSessionNodeInfo BuildNodeInfo(uint32_t userId, uint32_t uid, uint8_t *uriData,
    uint32_t uriSize)
{
    struct CmSessionNodeInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.userId = userId;
    info.uid = uid;
    info.uri.data = uriData;
    info.uri.size = uriSize;
    return info;
}

/* the value must outlive the returned blob: callers keep it in a local */
struct CmBlob MakeHandleBlob(uint64_t *value)
{
    struct CmBlob handle;
    handle.size = sizeof(*value);
    handle.data = reinterpret_cast<uint8_t *>(value);
    return handle;
}

uint64_t HandleValue(uint32_t index)
{
    return TEST_SESSION_HANDLE_BASE + index;
}

/* copy a uri literal into a fixed buffer; the caller asserts the result so a
   failed copy fails the case instead of feeding the engine a stale buffer */
bool CopyUriTo(uint8_t *buf, uint32_t bufSize, const char *uri)
{
    size_t len = strlen(uri) + 1;
    return (len <= bufSize) && (memcpy_s(buf, bufSize, uri, len) == EOK);
}

void DeleteSessions(uint32_t from, uint32_t to)
{
    for (uint32_t i = from; i <= to; ++i) {
        uint64_t value = HandleValue(i);
        struct CmBlob handle = MakeHandleBlob(&value);
        CmReleaseSession(&handle, false); /* idempotent: unknown handles are ignored */
    }
}

void CreateSessions(uint32_t from, uint32_t to, const struct CmSessionNodeInfo *info, bool abortable)
{
    for (uint32_t i = from; i <= to; ++i) {
        uint64_t value = HandleValue(i);
        struct CmBlob handle = MakeHandleBlob(&value);
        ASSERT_EQ(CmCreateSession(info, &handle, abortable), CM_SUCCESS) << "index " << i;
    }
}

/* presence check rebuilt on the claim/release primitives: a successful claim
   means the session exists for this caller; the claim is immediately
   released keeping the node, so later operations still find it. Cases are
   single threaded, so a failed claim means the session is absent, never
   busy (busy would indicate an unpaired claim inside the test itself). */
bool SessionExists(const struct CmSessionNodeInfo *info, const struct CmBlob *handle)
{
    bool busy = false;
    if (CmClaimSession(info, handle, &busy) != CM_SUCCESS) {
        return false;
    }
    CmReleaseSession(handle, true);
    return true;
}
} // namespace

class CmEngineSessionTest : public testing::Test {
public:
    void SetUp() override
    {
        DeleteSessions(0, TEST_SESSION_GUARD_INDEX); /* start from a clean shared list */
    }

    void TearDown() override
    {
        DeleteSessions(0, TEST_SESSION_GUARD_INDEX);
    }

protected:
    uint8_t uriA_[MAX_LEN_URI] = { 0 };
    uint8_t uriB_[MAX_LEN_URI] = { 0 };
    uint8_t uriC_[MAX_LEN_URI] = { 0 };
};

/**
 * @tc.name: CmEngineSessionCreateDelete_001
 * @tc.desc: sessions can be created, claimed by caller plus handle and deleted.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionCreateDelete_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    struct CmSessionNodeInfo info = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);
    uint64_t value = HandleValue(0);
    struct CmBlob handle = MakeHandleBlob(&value);

    ASSERT_EQ(CmCreateSession(&info, &handle, true), CM_SUCCESS);
    EXPECT_TRUE(SessionExists(&info, &handle));

    /* deleting the handle removes exactly the matching session */
    CmReleaseSession(&handle, false);
    EXPECT_FALSE(SessionExists(&info, &handle));

    /* deleting an unknown handle stays a no-op and the slot can be reused */
    CmReleaseSession(&handle, false);
    ASSERT_EQ(CmCreateSession(&info, &handle, true), CM_SUCCESS);
    EXPECT_TRUE(SessionExists(&info, &handle));
}

/**
 * @tc.name: CmEngineSessionClaimMismatch_001
 * @tc.desc: claim only matches on handle blob and caller identity together.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionClaimMismatch_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    struct CmSessionNodeInfo info = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);
    uint64_t value = HandleValue(0);
    struct CmBlob handle = MakeHandleBlob(&value);
    ASSERT_EQ(CmCreateSession(&info, &handle, true), CM_SUCCESS);

    /* same handle bytes but a shorter size does not match */
    struct CmBlob shortHandle;
    shortHandle.size = sizeof(uint32_t);
    shortHandle.data = handle.data;
    EXPECT_FALSE(SessionExists(&info, &shortHandle));

    /* same size but different handle content does not match */
    uint64_t otherValue = HandleValue(99);
    struct CmBlob otherHandle = MakeHandleBlob(&otherValue);
    EXPECT_FALSE(SessionExists(&info, &otherHandle));

    /* matching handle with a different caller does not match */
    struct CmSessionNodeInfo otherUid = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A2,
        uriA_, info.uri.size);
    EXPECT_FALSE(SessionExists(&otherUid, &handle));
    struct CmSessionNodeInfo otherUser = BuildNodeInfo(TEST_SESSION_USER_B, TEST_SESSION_UID_A1,
        uriA_, info.uri.size);
    EXPECT_FALSE(SessionExists(&otherUser, &handle));

    /* the original pair still resolves */
    EXPECT_TRUE(SessionExists(&info, &handle));
}

/**
 * @tc.name: CmEngineSessionClaimBusy_001
 * @tc.desc: a claimed session rejects a second claim as busy until released.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionClaimBusy_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    struct CmSessionNodeInfo info = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);
    uint64_t value = HandleValue(0);
    struct CmBlob handle = MakeHandleBlob(&value);
    ASSERT_EQ(CmCreateSession(&info, &handle, true), CM_SUCCESS);

    /* first claim takes the session */
    bool busy = false;
    ASSERT_EQ(CmClaimSession(&info, &handle, &busy), CM_SUCCESS);
    EXPECT_FALSE(busy);

    /* a second claim on the in-flight session fails as busy */
    bool secondBusy = false;
    EXPECT_EQ(CmClaimSession(&info, &handle, &secondBusy), CMR_ERROR_NOT_EXIST);
    EXPECT_TRUE(secondBusy);

    /* a foreign caller fails as absent, not busy: the claim is not theirs */
    struct CmSessionNodeInfo otherUid = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A2,
        uriA_, info.uri.size);
    bool foreignBusy = true;
    EXPECT_EQ(CmClaimSession(&otherUid, &handle, &foreignBusy), CMR_ERROR_NOT_EXIST);
    EXPECT_FALSE(foreignBusy);

    /* releasing with keep clears the in-flight mark: claimable again */
    CmReleaseSession(&handle, true);
    ASSERT_EQ(CmClaimSession(&info, &handle, &busy), CM_SUCCESS);
    EXPECT_FALSE(busy);

    /* releasing without keep removes the node: claims fail as absent */
    CmReleaseSession(&handle, false);
    bool absentBusy = true;
    EXPECT_EQ(CmClaimSession(&info, &handle, &absentBusy), CMR_ERROR_NOT_EXIST);
    EXPECT_FALSE(absentBusy);
}

/**
 * @tc.name: CmEngineSessionLimitNonAbortable_001
 * @tc.desc: fifteen non abortable sessions reject a sixteenth with the limit error.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionLimitNonAbortable_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    struct CmSessionNodeInfo info = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);

    CreateSessions(0, TEST_SESSION_LIMIT - 1, &info, false);

    /* every slot is taken by a non abortable session: no victim to evict */
    uint64_t extraValue = HandleValue(TEST_SESSION_LIMIT);
    struct CmBlob extra = MakeHandleBlob(&extraValue);
    EXPECT_EQ(CmCreateSession(&info, &extra, false), CMR_ERROR_SESSION_REACHED_LIMIT);

    /* freeing one slot makes room again */
    uint64_t freedValue = HandleValue(0);
    struct CmBlob freed = MakeHandleBlob(&freedValue);
    CmReleaseSession(&freed, false);
    uint64_t recycledValue = HandleValue(TEST_SESSION_LIMIT + 1);
    struct CmBlob recycled = MakeHandleBlob(&recycledValue);
    ASSERT_EQ(CmCreateSession(&info, &recycled, false), CM_SUCCESS);
    EXPECT_TRUE(SessionExists(&info, &recycled));
}

/**
 * @tc.name: CmEngineSessionEvictOldestAbortable_001
 * @tc.desc: a sixteenth session evicts the oldest abortable session first.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionEvictOldestAbortable_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    struct CmSessionNodeInfo info = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);

    CreateSessions(0, TEST_SESSION_LIMIT - 1, &info, true);

    /* the oldest session is present before the table is full */
    uint64_t oldestValue = HandleValue(0);
    struct CmBlob oldest = MakeHandleBlob(&oldestValue);
    ASSERT_TRUE(SessionExists(&info, &oldest));

    /* one more abortable session is accepted and evicts the oldest one */
    uint64_t extraValue = HandleValue(TEST_SESSION_LIMIT);
    struct CmBlob extra = MakeHandleBlob(&extraValue);
    ASSERT_EQ(CmCreateSession(&info, &extra, true), CM_SUCCESS);
    EXPECT_FALSE(SessionExists(&info, &oldest));
    EXPECT_TRUE(SessionExists(&info, &extra));

    /* the second oldest survived the eviction */
    uint64_t secondValue = HandleValue(1);
    struct CmBlob second = MakeHandleBlob(&secondValue);
    EXPECT_TRUE(SessionExists(&info, &second));
}

/**
 * @tc.name: CmEngineSessionDeleteByNodeInfo_001
 * @tc.desc: bulk deletion filters by user id, uid, uri and the full identity.
 * @tc.type: FUNC
 */
HWTEST_F(CmEngineSessionTest, CmEngineSessionDeleteByNodeInfo_001, TestSize.Level0)
{
    ASSERT_TRUE(CopyUriTo(uriA_, sizeof(uriA_), "oh:t=ak;o=sesA;u=7788;a=778801"));
    ASSERT_TRUE(CopyUriTo(uriB_, sizeof(uriB_), "oh:t=ak;o=sesB;u=7788;a=778802"));
    ASSERT_TRUE(CopyUriTo(uriC_, sizeof(uriC_), "oh:t=ak;o=sesC;u=7789;a=778901"));
    struct CmSessionNodeInfo infoA = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriA_, strlen(reinterpret_cast<char *>(uriA_)) + 1);
    struct CmSessionNodeInfo infoB = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A2,
        uriB_, strlen(reinterpret_cast<char *>(uriB_)) + 1);
    struct CmSessionNodeInfo infoC = BuildNodeInfo(TEST_SESSION_USER_B, TEST_SESSION_UID_B1,
        uriC_, strlen(reinterpret_cast<char *>(uriC_)) + 1);

    uint64_t valueA = HandleValue(0);
    uint64_t valueB = HandleValue(1);
    uint64_t valueC = HandleValue(2);
    struct CmBlob handleA = MakeHandleBlob(&valueA);
    struct CmBlob handleB = MakeHandleBlob(&valueB);
    struct CmBlob handleC = MakeHandleBlob(&valueC);
    ASSERT_EQ(CmCreateSession(&infoA, &handleA, false), CM_SUCCESS);
    ASSERT_EQ(CmCreateSession(&infoB, &handleB, false), CM_SUCCESS);
    ASSERT_EQ(CmCreateSession(&infoC, &handleC, false), CM_SUCCESS);

    /* an unknown delete type deletes nothing */
    enum CmSessionDeleteType badType = static_cast<enum CmSessionDeleteType>(TEST_SESSION_LIMIT);
    CmDeleteSessionByNodeInfo(badType, &infoA);
    EXPECT_TRUE(SessionExists(&infoA, &handleA));
    EXPECT_TRUE(SessionExists(&infoB, &handleB));
    EXPECT_TRUE(SessionExists(&infoC, &handleC));

    /* by user id: only the sessions of that user disappear */
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_USERID, &infoC);
    EXPECT_FALSE(SessionExists(&infoC, &handleC));
    EXPECT_TRUE(SessionExists(&infoA, &handleA));
    EXPECT_TRUE(SessionExists(&infoB, &handleB));

    /* by uid: the user id must match too, a foreign user id keeps the session */
    struct CmSessionNodeInfo foreignUser = BuildNodeInfo(TEST_SESSION_USER_B, TEST_SESSION_UID_A2,
        uriB_, infoB.uri.size);
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_UID, &foreignUser);
    EXPECT_TRUE(SessionExists(&infoB, &handleB));

    /* by uid with the exact caller identity */
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_UID, &infoB);
    EXPECT_FALSE(SessionExists(&infoB, &handleB));

    /* by uri: an unrelated uri deletes nothing */
    struct CmSessionNodeInfo otherUri = BuildNodeInfo(TEST_SESSION_USER_A, TEST_SESSION_UID_A1,
        uriB_, infoA.uri.size);
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_URI, &otherUri);
    EXPECT_TRUE(SessionExists(&infoA, &handleA));

    /* by uri with the session uri */
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_URI, &infoA);
    EXPECT_FALSE(SessionExists(&infoA, &handleA));

    /* by all: caller identity and uri must both match */
    ASSERT_EQ(CmCreateSession(&infoA, &handleA, false), CM_SUCCESS);
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_ALL, &otherUri);
    EXPECT_TRUE(SessionExists(&infoA, &handleA));
    CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_ALL, &infoA);
    EXPECT_FALSE(SessionExists(&infoA, &handleA));
}
