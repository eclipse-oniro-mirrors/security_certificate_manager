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

/*
 * Fetch the scene's cloud config zip: connect the scene's service
 * extension (the cm_system_dialog_connection.cpp skeleton: Want with the
 * scene's bundle/ability, connect under the SA identity), then send one
 * cmdId request over the connected remote and read the zip fd out of the
 * reply through CmHsdrParseReply.
 *
 * One shot per call: a connect failure or timeout, or a rejected reply,
 * ends the fetch with a negative code and no retry (the next SA start
 * re-runs the whole sync). The connection is torn down (DisconnectAbility)
 * on every exit after the connect call was issued. On success zipOut
 * holds the CmMalloc'd archive bytes and the caller releases them with
 * CM_FREE_BLOB; on failure zipOut is unchanged (pass it in zeroed).
 * Every failure path logs a CM_LOG_E carrying the cmdId and the scene
 * bundle name. The interface token is the remote's own descriptor, so no
 * service identity is hard-coded here.
 *
 * @param scene the cloud-push scene to fetch
 * @param zipOut receives the archive bytes on success
 * @return CM_SUCCESS; CMR_ERROR_INVALID_ARGUMENT for a scene without a
 *         bundle or ability name; CMR_ERROR on connect, timeout, request
 *         or reply failures
 */
int32_t CmHsdrFetchCloudZip(const CloudResourceScene &scene, struct CmBlob &zipOut);

#endif /* CM_HSDR_CLIENT_H */
