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

#ifndef CM_CERT_DATA_ED448_H
#define CM_CERT_DATA_ED448_H

/* Self-signed ED448 certificate (subject CN=ed448cm) plus its PKCS#8 PEM
 * private key. The key pair is valid and self-consistent (EVP_PKEY_cmp
 * matches) but ED448 is not an importable key type for the credential
 * store, so installs are expected to stop at the unsupported-key branch. */

static char g_ed448PEMCertChain[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBhDCCAQSgAwIBAgIUeww36fOEw7hwYi6NOqd93lG4E9IwBQYDK2VxMBIxEDAO\r\n"
    "BgNVBAMMB2VkNDQ4Y20wHhcNMjYxMTEyMDkyOTI3WhcNMzYxMTA5MDkyOTI3WjAS\r\n"
    "MRAwDgYDVQQDDAdlZDQ0OGNtMEMwBQYDK2VxAzoA218MS81d4kuI5zyAvyIHy+Hz\r\n"
    "EZSgv+kqzxeP5u/LlQJlmkKvdEfd8RnVSmhxMxsSfnaTby8/c2qAo1MwUTAdBgNV\r\n"
    "HQ4EFgQUJbT70VpKSXSDUwMRjw+hPwBpInYwHwYDVR0jBBgwFoAUJbT70VpKSXSD\r\n"
    "UwMRjw+hPwBpInYwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXEDcwDkx5j180KJMxhn\r\n"
    "GkxA+9/zXN1E3WvOZCD5mtEzKImJUtEf25fW4epVcsY84mXmz55aiXTpoZJbvQAU\r\n"
    "BDYWXjfunlp1BfmmKXcrUj64Cn1LTwiwkRguquk+yUZB3urYihYGoNJKqPLzmBl1\r\n"
    "D7n3aCj5JwA=\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_ed448PEMPrivKey[] =
    "-----BEGIN PRIVATE KEY-----\r\n"
    "MEcCAQAwBQYDK2VxBDsEOTeMhck4A+ryUP+KDX0eBeIJ4HcfSJrSPMWFM8YlcX1s\r\n"
    "QHsFhzaehcwytg2VYGsY7GHqCGo3aoaqtg==\r\n"
    "-----END PRIVATE KEY-----\r\n";

#endif // CM_CERT_DATA_ED448_H
