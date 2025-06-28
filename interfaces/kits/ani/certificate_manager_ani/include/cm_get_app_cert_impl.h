/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_GET_APP_PRIVATE_CERT_H
#define CM_GET_APP_PRIVATE_CERT_H

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cm_log.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
class CmGetAppCertImpl : public CertManagerAniImpl {
private:
    ani_string aniKeyuri;
    CmBlob keyuri = { 0 };
    Credential *credential = nullptr;
    uint32_t store = -1;
public:
    CmGetAppCertImpl(ani_env *env, ani_string aniKeyuri, uint32_t store);
    ~CmGetAppCertImpl() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
};

class CmGetAppPrivateCertImpl : public CmGetAppCertImpl {
public:
    CmGetAppPrivateCertImpl(ani_env *env, ani_string aniKeyuri)
        : CmGetAppCertImpl(env, aniKeyuri, APPLICATION_PRIVATE_CERTIFICATE_STORE) {}
};

class CmGetAppPublicCertImpl : public CmGetAppCertImpl {
public:
    CmGetAppPublicCertImpl(ani_env *env, ani_string aniKeyuri)
        : CmGetAppCertImpl(env, aniKeyuri, APPLICATION_CERTIFICATE_STORE) {}
};
}
#endif // CM_GET_APP_PRIVATE_CERT_H