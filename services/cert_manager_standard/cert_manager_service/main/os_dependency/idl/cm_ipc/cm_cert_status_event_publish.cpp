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

#include "cm_cert_status_event_publish.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_publish_info.h"

#include "cm_log.h"

bool CmPublishCommonEventToCes(const OHOS::AAFwk::Want &want,
    const std::vector<std::string> &subscriberPermissions)
{
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    OHOS::EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions(subscriberPermissions);

    bool published = OHOS::EventFwk::CommonEventManager::PublishCommonEvent(eventData, publishInfo);
    if (!published) {
        CM_LOG_E("publish common event to ces failed");
    }
    return published;
}
