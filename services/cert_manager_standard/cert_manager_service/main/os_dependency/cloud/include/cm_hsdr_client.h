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

#ifndef CM_HSDR_CLIENT_H
#define CM_HSDR_CLIENT_H

#include <cstdint>

#include "cm_hsdr_protocol.h"

/* how long one fetch waits for the asynchronous OnAbilityConnectDone
 * before giving up: the design suggestion window, upper edge */
constexpr uint32_t CM_HSDR_CONNECT_TIMEOUT_MS = 10000;

/* how long one fetch waits for the service's asynchronous callback after
 * the request was sent: the SA unload window (60 s) is renewed at the
 * round's entry and exit, and the connect wait above already spends up to
 * 10 s of it, so 30 s keeps the worst-case round (connect + callback
 * wait) inside the window with margin */
constexpr uint32_t CM_HSDR_CALLBACK_TIMEOUT_MS = 30000;

/*
 * Fetch the scene's cloud config zip: connect the scene's service
 * extension (the cm_system_dialog_connection.cpp skeleton: Want with the
 * scene's bundle/ability, connect under the SA identity), then forward
 * one asynchronous cmdId request through the HSDR proxy -- the request
 * parcel's interface token is the proxy's own descriptor (the fixed
 * OHOS.Security.HSDR identity the service's permission check keys on),
 * and it carries a callback stub as the reply channel, because the HSDR
 * service answers asynchronously only -- and wait for the callback to
 * deliver the zip fd, read through CmHsdrParseReply.
 *
 * One shot per call: a connect failure or timeout, a send failure, a
 * callback timeout or a rejected callback ends the fetch with a negative
 * code and no retry (the next SA start re-runs the whole sync). The stub
 * is abandoned before the fetch gives up waiting, so a callback landing
 * after the timeout is parsed and discarded safely. The connection is
 * torn down (DisconnectAbility) on every exit after the connect call was
 * issued. On success zipOut holds the CmMalloc'd archive bytes and the
 * caller releases them with CM_FREE_BLOB; on failure zipOut is unchanged
 * (pass it in zeroed). Every failure path logs a CM_LOG_E carrying the
 * cmdId and the scene bundle name.
 *
 * @param scene the cloud-push scene to fetch
 * @param zipOut receives the archive bytes on success
 * @return CM_SUCCESS; CMR_ERROR_INVALID_ARGUMENT for a scene without a
 *         bundle or ability name; CMR_ERROR on connect, timeout, request
 *         or reply failures
 */
int32_t CmHsdrFetchCloudZip(const CloudResourceScene &scene, struct CmBlob &zipOut);

#endif /* CM_HSDR_CLIENT_H */
