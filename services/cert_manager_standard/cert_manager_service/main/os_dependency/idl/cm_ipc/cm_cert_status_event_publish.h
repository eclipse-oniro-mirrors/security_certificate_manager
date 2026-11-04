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

#ifndef CM_CERT_STATUS_EVENT_PUBLISH_H
#define CM_CERT_STATUS_EVENT_PUBLISH_H

#include <string>
#include <vector>

#include "want.h"

/*
 * Internal seam between the event construction logic and the common event
 * service innerkit. The production implementation lives in
 * cm_cert_status_event_publish.cpp; unit tests substitute their own
 * definition via link-time replacement.
 */
bool CmPublishCommonEventToCes(const OHOS::AAFwk::Want &want,
    const std::vector<std::string> &subscriberPermissions);

#endif /* CM_CERT_STATUS_EVENT_PUBLISH_H */
