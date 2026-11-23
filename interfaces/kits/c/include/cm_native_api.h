/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

/**
 * @addtogroup CertManager
 * @{
 *
 * @brief Describes the OpenHarmony Certificate Manager capabilities, including certificate and credential management
 *    operations, provided for applications.
 *
 * @since 22
 */

 /**
 * @file native_cm_api.h
 *
 * @brief Defines the Certificate APIs.
 *
 * @library libohcert_manager.z.so
 * @kit DeviceCertificateKit
 * @syscap SystemCapability.Security.CertificateManager
 * @since 22
 */

#ifndef CM_NATIVE_API_H
#define CM_NATIVE_API_H

#include "cm_native_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the detail of USB key certificate.
 *
 * @param keyUri Indicates the USB key certificate uri.
 * @param ukeyInfo Indicates the USB key certificate attribute information.
 * @param certificateList Indicates the detail to a information of USB key certificate.
 * @return {@link OH_CM_ErrCode#OH_CM_SUCCESS} 0 - The operation is successful.
 *         {@link OH_CM_ErrCode#OH_CM_HAS_NO_PERMISSION} 201 - Permission verification failed
 *         {@link OH_CM_ErrCode#OH_CM_CAPABILITY_NOT_SUPPORTED} 801 - Capability not supported.
 *         {@link OH_CM_ErrCode#OH_CM_PARAMETER_VALIDATION_FAILED} 1700011 - Indicates that the input parameters
 *             validation failed. for example, the parameter format is incorrect or the value range is invalid.
 *         {@link OH_CM_ErrCode#OH_CM_INNER_FAILURE} 17500001 - Internal error. Possible causes:
 *             1. IPC communication failed. 2. Memory operation error; 3. File operation error.
 *         {@link OH_CM_ErrCode#OH_CM_NOT_FOUND} 17500002 - Indicates that the certificate does not exist.
 *         {@link OH_CM_ErrCode#OH_CM_ACCESS_UKEY_SERVICE_FAILED} 17500010 - Indicates that access USB key
 *             service failed.
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @since 22
 */
int32_t OH_CertManager_GetUkeyCertificate(const OH_CM_Blob *keyUri,
    const OH_CM_UkeyInfo *ukeyInfo, OH_CM_CredentialDetailList *certificateList);

/**
 * @brief Get the detail of application private certificate.
 *
 * @param keyUri Indicates the private certificate uri.
 * @param certificate Indicates the detail information of private certificate.
 * @return {@link OH_CM_ErrCode#OH_CM_SUCCESS} 0 - The operation is successful.
 *         {@link OH_CM_ErrCode#OH_CM_HAS_NO_PERMISSION} 201 - Permission verification failed
 *         {@link OH_CM_ErrCode#OH_CM_PARAMETER_VALIDATION_FAILED} 1700011 - Indicates that the input parameters
 *             validation failed. for example, the parameter format is incorrect or the value range is invalid.
 *         {@link OH_CM_ErrCode#OH_CM_INNER_FAILURE} 17500001 - Internal error. Possible causes:
 *             1. IPC communication failed. 2. Memory operation error; 3. File operation error.
 *         {@link OH_CM_ErrCode#OH_CM_NOT_FOUND} 17500002 - Indicates that the certificate does not exist.
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @since 22
 */
int32_t OH_CertManager_GetPrivateCertificate(const OH_CM_Blob *keyUri, OH_CM_Credential *certificate);

/**
 * @brief Get the detail of user public certificate.
 *
 * @param keyUri Indicates the public certificate uri.
 * @param certificate Indicates the detail information of public certificate.
 * @return {@link OH_CM_ErrCode#OH_CM_SUCCESS} 0 - The operation is successful.
 *         {@link OH_CM_ErrCode#OH_CM_HAS_NO_PERMISSION} 201 - Permission verification failed
 *         {@link OH_CM_ErrCode#OH_CM_PARAMETER_VALIDATION_FAILED} 1700011 - Indicates that the input parameters
 *             validation failed. for example, the parameter format is incorrect or the value range is invalid.
 *         {@link OH_CM_ErrCode#OH_CM_INNER_FAILURE} 17500001 - Internal error. Possible causes:
 *             1. IPC communication failed. 2. Memory operation error; 3. File operation error.
 *         {@link OH_CM_ErrCode#OH_CM_NOT_FOUND} 17500002 - Indicates that the certificate does not exist.
 *         {@link OH_CM_ErrCode#OH_CM_NO_AUTHORIZATION} 17500005 - The application is not authorized by the user.
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @since 22
 */
int32_t OH_CertManager_GetPublicCertificate(const OH_CM_Blob *keyUri, OH_CM_Credential *certificate);

/**
 * @brief Destroys a credential detail list.
 *
 * @param certificateList Indicates the pointer to the credential detail list to destroy.
 * @since 22
 */
void OH_CertManager_FreeUkeyCertificate(OH_CM_CredentialDetailList *certificateList);

/**
 * @brief Destroys a credential detail.
 *
 * @param certificate Indicates the pointer to the credential detail to destroy.
 * @since 22
 */
void OH_CertManager_FreeCredential(OH_CM_Credential *certificate);

/**
 * @brief This interface is used to query the USB key certificate credential list. After the call is complete, call
 * OH_CertManager_FreeUkeyCertificate to release the certificateList memory.
 *
 * @param ukeyProvider [Input parameter] USB key vendor name.
 * @param ukeyInfo [Input parameter] USB certificate credential attribute information.
 * @param certificateList [Output parameter] Obtained USB certificate credential list.
 * @return Certificate management error code. For the definition of the error code, see
 * {@link OH_CM_ErrCode}.<ul>
 *     <li>{@link OH_CM_SUCCESS}: Operation succeeded. </li>
 *     <li>{@link OH_CM_HAS_NO_PERMISSION}: Permission verification failed. </li>
 *     <li>{@link OH_CM_CAPABILITY_NOT_SUPPORTED}: The device does not support this function. </li>
 *     <li>{@link OH_CM_INNER_FAILURE}: Internal error. Possible causes:
 *     <br>1. The IPC communication fails.
 *     <br>2. Memory operation error.
 *     <br>3. File operation error. </li>
 *     <li>{@link OH_CM_ACCESS_UKEY_SERVICE_FAILED}: Failed to access the USB certificate credential. </li>
 *     <li>{@link OH_CM_PARAMETER_VALIDATION_FAILED}: Input parameter validation failed. Possible causes:
 *     <br>1. The parameter format is incorrect.
 *     <br>2. The parameter range is invalid. </li>
 *     </ul>
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @since 26.1.0
 */
int32_t OH_CertManager_GetUkeyCertificateList(const OH_CM_Blob *ukeyProvider,
    const OH_CM_UkeyInfo *ukeyInfo, OH_CM_CredentialDetailList *certificateList);

/**
 * @brief Import the certificate to the USB key device.
 *
 * @param keyUri [Input parameter] Unique identifier of the USB certificate (character string format).
 * @param cert [Input parameter] Certificate file to be imported.
 * @param ukeyInfo [Input parameter] USB certificate credential attribute information.
 * @return Certificate management error code. For details about the error code definition, see
 * {@link OH_CM_ErrCode}.<ul>
 *     <li>{@link OH_CM_SUCCESS}: Operation succeeded. </li>
 *     <li>{@link OH_CM_HAS_NO_PERMISSION}: Permission verification failed. </li>
 *     <li>{@link OH_CM_CAPABILITY_NOT_SUPPORTED}: The device does not support this function. </li>
 *     <li>{@link OH_CM_INNER_FAILURE}: Internal error. Possible causes:
 *     <br>1. The IPC communication fails.
 *     <br>2. Memory operation error.
 *     <br>3. File operation error. </li>
 *     <li>{@link OH_CM_NOT_FOUND}: The certificate credential specified by keyUri does not exist. </li>
 *     <li>{@link OH_CM_ACCESS_UKEY_SERVICE_FAILED}: Failed to access the USB certificate credentials. </li>
 *     <li>{@link OH_CM_PARAMETER_VALIDATION_FAILED}: Input parameter validation failed. Possible causes:
 *     <br>1. The parameter format is incorrect.
 *     <br>2. The parameter range is invalid. </li>
 *     </ul>
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @since 26.1.0
 */
int32_t OH_CertManager_ImportUkeyCert(const OH_CM_Blob *keyUri,
    const OH_CM_Blob *cert, const OH_CM_UkeyInfo *ukeyInfo);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* CM_NATIVE_API_H */