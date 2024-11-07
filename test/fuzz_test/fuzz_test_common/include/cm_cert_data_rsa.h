/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CM_CERT_DATA_RSA_H
#define CM_CERT_DATA_RSA_H

static const uint8_t g_certPwd[] = "123456";
static const uint8_t g_rsa2048P12CertInfo[] = {
    0x30, 0x82, 0x0b, 0xc1, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0b, 0x87, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x0b, 0x78, 0x04, 0x82, 0x0b, 0x74, 0x30, 0x82,
    0x0b, 0x70, 0x30, 0x82, 0x06, 0x27, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07,
    0x06, 0xa0, 0x82, 0x06, 0x18, 0x30, 0x82, 0x06, 0x14, 0x02, 0x01, 0x00, 0x30, 0x82, 0x06, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x30, 0x1c, 0x06, 0x0a, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0e, 0x04, 0x08, 0x1a, 0x8f, 0xc1,
    0xd1, 0xda, 0x6c, 0xd1, 0xa9, 0x02, 0x02, 0x08, 0x00, 0x80, 0x82, 0x05, 0xe0, 0xd0, 0x2f, 0x2d,
    0x52, 0x09, 0x86, 0x55, 0x53, 0xf0, 0x49, 0x8f, 0x00, 0xa1, 0x4d, 0x21, 0xc8, 0xb4, 0xad, 0x27,
    0x12, 0x44, 0xab, 0x4d, 0x10, 0x14, 0xe3, 0x3c, 0x9a, 0x05, 0x77, 0x51, 0x90, 0x4a, 0x3a, 0x8a,
    0x09, 0xa9, 0x4b, 0x36, 0x50, 0x60, 0x22, 0x4b, 0x77, 0x12, 0x5c, 0x2f, 0x60, 0xd3, 0xd9, 0x30,
    0x94, 0x4d, 0x9e, 0x81, 0xc3, 0xe9, 0x9d, 0xd9, 0x47, 0xb3, 0x54, 0xa2, 0x9a, 0x8f, 0xe7, 0x58,
    0x95, 0xd7, 0x48, 0x87, 0xc4, 0x40, 0xad, 0x9a, 0x42, 0x1d, 0x36, 0xb7, 0x48, 0xbc, 0x70, 0x8c,
    0x84, 0xcb, 0x3c, 0x02, 0x25, 0x9f, 0xfe, 0x2c, 0x4a, 0x76, 0xb1, 0x27, 0x94, 0x8f, 0xb0, 0x07,
    0xf0, 0xc0, 0x00, 0x3a, 0x69, 0x16, 0xe1, 0x63, 0x0c, 0xe5, 0x92, 0xc2, 0x7d, 0x99, 0xd9, 0x11,
    0x40, 0xd8, 0x64, 0xab, 0x13, 0xda, 0x73, 0x7b, 0x12, 0x53, 0xb1, 0x0b, 0x0c, 0x67, 0x81, 0xe1,
    0xf5, 0x59, 0x3a, 0xc7, 0xe0, 0xe9, 0xda, 0x12, 0xc7, 0x2b, 0xab, 0x3d, 0xbc, 0x10, 0x3d, 0x1a,
    0x88, 0xc7, 0x1d, 0x31, 0x5f, 0x39, 0x63, 0x51, 0x8b, 0x11, 0x99, 0x05, 0xf9, 0x40, 0x42, 0x27,
    0xad, 0x75, 0x6f, 0xe2, 0x2d, 0x66, 0x28, 0x97, 0x7c, 0x6f, 0xf4, 0xfc, 0x95, 0xaa, 0x67, 0x81,
    0xd8, 0x15, 0x3c, 0xf4, 0x7b, 0x97, 0x08, 0x7b, 0x1b, 0x8c, 0xd3, 0x45, 0x8b, 0x96, 0x54, 0x2c,
    0xb1, 0x00, 0x87, 0x59, 0x5c, 0x94, 0x78, 0x29, 0xaa, 0x7b, 0x9c, 0x5c, 0x61, 0xff, 0xcc, 0x32,
    0x14, 0x4e, 0xc3, 0x1b, 0x96, 0xad, 0x4c, 0xde, 0x49, 0xe4, 0x8e, 0x63, 0x52, 0x5d, 0x24, 0x9c,
    0xd3, 0x45, 0xed, 0x98, 0xe1, 0x6e, 0x15, 0xcd, 0x76, 0xa1, 0x0b, 0x67, 0x84, 0x79, 0xbc, 0xb0,
    0x9c, 0x3e, 0xff, 0x48, 0xf9, 0xc1, 0xab, 0x76, 0xc4, 0xe4, 0x61, 0x84, 0x7a, 0xb0, 0x88, 0xa2,
    0x14, 0x0a, 0xdc, 0x01, 0x47, 0xff, 0xf6, 0x27, 0x46, 0x1e, 0x37, 0xe5, 0x5e, 0x9a, 0x55, 0x49,
    0x67, 0x7b, 0x04, 0xba, 0xef, 0x89, 0x32, 0x8a, 0x2b, 0x72, 0x8c, 0xb9, 0xba, 0x19, 0xfa, 0x09,
    0x7f, 0x24, 0xea, 0xbd, 0xcc, 0xa5, 0x3c, 0xa8, 0xc6, 0x30, 0x0f, 0xcf, 0xd2, 0xf3, 0x10, 0xed,
    0x5c, 0x7d, 0xbb, 0x0a, 0x6a, 0x27, 0x60, 0x32, 0x9a, 0xa2, 0xfb, 0x2c, 0x38, 0xd2, 0x62, 0x92,
    0x5d, 0x77, 0xe8, 0xb8, 0x3a, 0x64, 0xfe, 0xb8, 0x2f, 0x69, 0xc4, 0xdd, 0x78, 0xdd, 0x92, 0xeb,
    0xc3, 0x08, 0xc2, 0x05, 0xef, 0xa6, 0x9c, 0x12, 0xd5, 0x48, 0x27, 0xfb, 0x19, 0x66, 0x66, 0x24,
    0x52, 0x47, 0xf1, 0x7c, 0xad, 0xc9, 0xb8, 0x1a, 0xd0, 0x2d, 0x40, 0xe9, 0x36, 0xce, 0x9e, 0x07,
    0x06, 0xd0, 0xe3, 0x5d, 0x98, 0xfb, 0x67, 0x1a, 0xd1, 0x62, 0x35, 0x03, 0xe8, 0x34, 0xf0, 0xfd,
    0x24, 0xe4, 0x06, 0x52, 0x03, 0xda, 0x8e, 0x68, 0x6d, 0x74, 0xfd, 0xda, 0x9b, 0xca, 0x8e, 0x52,
    0x71, 0x9c, 0x14, 0x05, 0x10, 0x61, 0x63, 0xa4, 0x53, 0x72, 0x4a, 0xda, 0x15, 0xf8, 0x0a, 0x56,
    0x89, 0x00, 0xdd, 0x87, 0xf5, 0xdd, 0x69, 0xd6, 0x6c, 0x89, 0x15, 0x1a, 0x1f, 0x48, 0xd6, 0x2c,
    0x1e, 0x4f, 0x23, 0x06, 0x6e, 0x34, 0x0d, 0x4e, 0xe3, 0x17, 0x40, 0x22, 0x7a, 0x68, 0x37, 0xad,
    0x05, 0xdb, 0x99, 0xde, 0x1a, 0x47, 0x2f, 0xb1, 0x9e, 0x7e, 0xdb, 0xad, 0x69, 0x06, 0x25, 0xd5,
    0xd9, 0x8e, 0xaf, 0xe2, 0xaa, 0x5a, 0x9a, 0x79, 0xd6, 0xeb, 0x02, 0x10, 0xf8, 0x72, 0x78, 0x4e,
    0x51, 0x2a, 0x53, 0x55, 0xb9, 0xd3, 0x7c, 0x31, 0x42, 0xff, 0x59, 0x39, 0x92, 0xd6, 0xec, 0x46,
    0x2d, 0x4f, 0xea, 0xf1, 0x0e, 0x83, 0x57, 0x55, 0x7b, 0xf1, 0x43, 0x47, 0x82, 0x10, 0x0d, 0x72,
    0xa2, 0x40, 0x2e, 0xf7, 0x2d, 0xcb, 0x80, 0x5b, 0x8a, 0x02, 0x5b, 0x71, 0xd9, 0xa5, 0x55, 0xea,
    0x41, 0x3f, 0x15, 0x9b, 0xee, 0x92, 0x4a, 0x3e, 0x87, 0x2e, 0xc3, 0xba, 0x71, 0x81, 0x57, 0xb9,
    0x7e, 0xb3, 0xd7, 0x52, 0x05, 0x91, 0x57, 0x87, 0x16, 0x48, 0x36, 0xdb, 0x4b, 0x45, 0x32, 0xaf,
    0x22, 0xc0, 0x3b, 0xc8, 0x90, 0xce, 0x53, 0xf3, 0x85, 0x64, 0xa3, 0x04, 0xe7, 0xfc, 0xa8, 0xc1,
    0x12, 0x77, 0x4a, 0x22, 0xd6, 0xfb, 0x01, 0x8f, 0x78, 0xd3, 0x2d, 0x33, 0x4c, 0xc8, 0x9d, 0x89,
    0xd7, 0x1f, 0xf2, 0x50, 0xf7, 0x94, 0x13, 0xe7, 0x3b, 0x4e, 0x36, 0x56, 0x93, 0x1a, 0xc7, 0x7e,
    0x4f, 0x92, 0xa2, 0xae, 0x4d, 0x9d, 0xbc, 0x03, 0xd4, 0x07, 0x76, 0x38, 0xc1, 0x59, 0x59, 0x3d,
    0xc9, 0xcf, 0xdd, 0x43, 0xcc, 0x82, 0xdb, 0xc1, 0x85, 0xbe, 0x3e, 0xab, 0x18, 0xd7, 0x7d, 0x17,
    0xc9, 0x9c, 0x9c, 0x81, 0x5b, 0xa8, 0x03, 0x04, 0x62, 0xc4, 0xd8, 0x78, 0x95, 0xd0, 0xfa, 0x8e,
    0x71, 0x43, 0x30, 0x3b, 0xdd, 0x64, 0x54, 0xb5, 0xd2, 0xa6, 0x0d, 0x8a, 0x73, 0x97, 0x46, 0x81,
    0xd6, 0x61, 0x61, 0x41, 0x07, 0xed, 0x23, 0x32, 0xd2, 0x20, 0x18, 0x27, 0x2b, 0x89, 0x8e, 0x3b,
    0xd7, 0x6e, 0xed, 0x50, 0x3f, 0xcb, 0x27, 0xab, 0xb5, 0x26, 0x9b, 0x9e, 0xe4, 0xe3, 0x2a, 0x88,
    0xf5, 0x4f, 0xf7, 0xb8, 0xc4, 0x11, 0xb0, 0x0c, 0xd7, 0x85, 0x3a, 0xc9, 0x65, 0x06, 0x43, 0xbf,
    0x66, 0x19, 0xf2, 0x2a, 0xed, 0x36, 0xf0, 0xf6, 0x39, 0x78, 0xd2, 0x4b, 0xe6, 0x20, 0x64, 0x66,
    0xe2, 0x87, 0x73, 0x5d, 0x09, 0x98, 0xe5, 0x06, 0xc1, 0xc7, 0xdf, 0x47, 0x12, 0x3a, 0xe0, 0xd6,
    0x7f, 0xb4, 0x29, 0x46, 0x3e, 0x49, 0x8f, 0x3d, 0xea, 0xd6, 0x0b, 0x36, 0xa3, 0xd2, 0xa3, 0x6b,
    0x9c, 0x0c, 0xe0, 0x47, 0x58, 0xbf, 0xfd, 0x42, 0xa2, 0x94, 0xe9, 0xd1, 0xfd, 0xc4, 0xcc, 0x68,
    0x32, 0x3a, 0x1e, 0xd2, 0x6f, 0x6b, 0x48, 0xe1, 0x48, 0xe0, 0x20, 0x23, 0xfc, 0x7c, 0xf9, 0x30,
    0xb1, 0xb0, 0x0e, 0x3c, 0x14, 0xf6, 0x73, 0x17, 0x1c, 0x71, 0x4c, 0xd9, 0x1d, 0x16, 0xcf, 0x31,
    0x6d, 0x79, 0xd6, 0x99, 0x66, 0xd5, 0x7f, 0xe7, 0xc2, 0x0d, 0xb8, 0xcb, 0xdb, 0x5e, 0x26, 0x95,
    0x35, 0xf1, 0x57, 0x5c, 0xec, 0xcd, 0xf0, 0xdb, 0xb4, 0x18, 0x7f, 0x04, 0x22, 0x50, 0xbe, 0xb3,
    0x04, 0x5c, 0xcd, 0x3a, 0x62, 0xe2, 0x3b, 0x5f, 0xa1, 0xa0, 0xd8, 0xd1, 0xf0, 0x45, 0x43, 0xf4,
    0xee, 0x27, 0x4f, 0x45, 0xb7, 0x06, 0x46, 0x53, 0x65, 0x49, 0xca, 0x4c, 0x12, 0xc9, 0x5b, 0x05,
    0xb6, 0xf6, 0x26, 0x5d, 0x90, 0x4a, 0x9b, 0x50, 0xaf, 0x65, 0x92, 0x13, 0xfc, 0xc2, 0x47, 0xff,
    0xe8, 0xb6, 0x4e, 0xd2, 0xa7, 0x48, 0x8c, 0xbe, 0x3a, 0x13, 0x2e, 0xe6, 0xb9, 0xb7, 0x29, 0x2d,
    0x30, 0xaa, 0x80, 0xcf, 0x74, 0x77, 0x14, 0xb2, 0x78, 0x52, 0x25, 0xf6, 0x97, 0x99, 0x40, 0x9a,
    0xea, 0xce, 0x92, 0x68, 0xb9, 0x5c, 0x9e, 0xf4, 0xbf, 0xd9, 0xd4, 0x43, 0x7d, 0xf6, 0x10, 0x05,
    0x9d, 0xa4, 0xe2, 0x8f, 0x8e, 0x2e, 0xce, 0x07, 0x57, 0x7b, 0xa2, 0xb2, 0x90, 0xd7, 0xd5, 0x66,
    0x12, 0xaa, 0x27, 0xce, 0xcb, 0x0a, 0xe9, 0x59, 0x47, 0xbd, 0x3e, 0x65, 0xd9, 0x83, 0xa2, 0x65,
    0x27, 0x06, 0x7f, 0x04, 0xc3, 0x35, 0xba, 0x55, 0x3d, 0x68, 0xc7, 0x0c, 0xa2, 0x50, 0xc3, 0xb1,
    0x66, 0x65, 0x7f, 0x74, 0xda, 0x05, 0x11, 0x89, 0xaf, 0xf2, 0x04, 0x8b, 0x60, 0x1d, 0xbf, 0x06,
    0x84, 0x7c, 0x1d, 0xcd, 0xcb, 0x5e, 0xf3, 0xfa, 0xfd, 0x1a, 0xb0, 0x1f, 0xc1, 0x6e, 0x91, 0x67,
    0xaa, 0x05, 0x9e, 0x2d, 0x6f, 0x4c, 0xdb, 0xab, 0x99, 0x83, 0x81, 0x80, 0x21, 0xbd, 0x17, 0x50,
    0x59, 0x3b, 0x16, 0x3a, 0x66, 0x2b, 0xd9, 0xab, 0x3f, 0x4a, 0xb1, 0xa3, 0x56, 0x9e, 0xbd, 0xd3,
    0x4a, 0x85, 0x63, 0x58, 0xa5, 0xbb, 0xdf, 0x64, 0x79, 0x43, 0x8d, 0x78, 0xa3, 0x88, 0x8e, 0x0d,
    0xbe, 0x1a, 0x14, 0xc2, 0xcf, 0x48, 0x0c, 0x55, 0xa8, 0xd6, 0xea, 0xdb, 0x5d, 0x50, 0x90, 0x84,
    0xfd, 0xe9, 0xd1, 0x90, 0xfe, 0xeb, 0xd8, 0xd1, 0x9c, 0xbe, 0xd5, 0x92, 0xd8, 0x71, 0x58, 0x58,
    0xc1, 0xbf, 0x4c, 0xe2, 0xa9, 0xd5, 0xc1, 0xce, 0x4a, 0xec, 0xde, 0xb3, 0x0a, 0xa2, 0xc0, 0x00,
    0xa2, 0xfa, 0x6a, 0x83, 0x9b, 0xae, 0x6e, 0x1f, 0x35, 0x8b, 0xcf, 0xcc, 0x3f, 0xdc, 0xac, 0x68,
    0x2a, 0x50, 0x65, 0x56, 0xb8, 0x2c, 0x92, 0xff, 0xc2, 0x1a, 0xd4, 0x4e, 0x12, 0x3d, 0x40, 0x67,
    0x62, 0x75, 0xcd, 0x4f, 0x1b, 0x45, 0xff, 0xbf, 0x46, 0xf8, 0xa2, 0xd1, 0xd2, 0xc9, 0xe6, 0xb6,
    0x26, 0x55, 0xd9, 0x55, 0xc9, 0x7b, 0xe4, 0xa9, 0x69, 0x43, 0x13, 0xdb, 0x7d, 0x8f, 0xaa, 0x02,
    0x15, 0x24, 0x6d, 0x80, 0x1f, 0x42, 0x7b, 0x32, 0x76, 0xbd, 0x0c, 0xcd, 0x3c, 0x5e, 0x55, 0x4f,
    0x49, 0xf1, 0x28, 0x6d, 0xc1, 0x36, 0x39, 0x93, 0x57, 0xf5, 0x83, 0xc2, 0x9e, 0xbb, 0x7b, 0x05,
    0xbe, 0x89, 0xab, 0x80, 0x93, 0xf0, 0x9c, 0xc3, 0x97, 0xcf, 0x03, 0x25, 0xb5, 0x2e, 0x6b, 0x18,
    0xe8, 0x72, 0x46, 0x0c, 0x8f, 0xc0, 0x27, 0x52, 0x31, 0x2c, 0x20, 0x96, 0x30, 0x29, 0x66, 0xa5,
    0x70, 0x9f, 0xbf, 0xfa, 0xb3, 0x4c, 0xfd, 0xd1, 0x73, 0xf4, 0x3c, 0x29, 0x74, 0xac, 0xa9, 0xc0,
    0xb4, 0x16, 0x72, 0x4a, 0x7f, 0x07, 0xe3, 0xfe, 0xd5, 0xa0, 0x3f, 0x47, 0x86, 0x59, 0x10, 0xbc,
    0xff, 0x0d, 0x0e, 0xdc, 0xc9, 0x6d, 0x8f, 0xb0, 0xc7, 0x78, 0xd7, 0xa2, 0x79, 0xdd, 0x6b, 0x10,
    0x8b, 0x9f, 0x3c, 0xba, 0x14, 0xe5, 0x3a, 0xf1, 0x1f, 0xb5, 0x84, 0xc1, 0x6a, 0xd5, 0xad, 0x59,
    0xe8, 0x15, 0x22, 0x33, 0xb6, 0x79, 0x6d, 0xe1, 0x59, 0xb9, 0xa7, 0x0f, 0x4c, 0xcc, 0x5f, 0x2a,
    0xbd, 0xab, 0x0e, 0x45, 0x47, 0x0c, 0x8d, 0x8a, 0xe3, 0xfb, 0x61, 0x64, 0x51, 0x36, 0x87, 0x04,
    0xc7, 0xd8, 0x16, 0x46, 0x9f, 0xa4, 0x35, 0xd0, 0xa6, 0x1a, 0x85, 0xf0, 0x91, 0x34, 0xfe, 0xe7,
    0x0b, 0xd2, 0xd7, 0x91, 0x46, 0xd0, 0xfe, 0xa9, 0xfb, 0xd7, 0xf7, 0x4d, 0x81, 0x95, 0x1b, 0x96,
    0x51, 0x21, 0xa5, 0xdc, 0xee, 0x25, 0xbe, 0xb2, 0x7d, 0x3f, 0x7b, 0x35, 0x05, 0x92, 0x30, 0x5d,
    0x2d, 0x57, 0x53, 0x45, 0xa7, 0x51, 0xab, 0x09, 0x71, 0xe0, 0x01, 0x96, 0x1c, 0x9b, 0xa5, 0x2d,
    0xcf, 0xff, 0x0e, 0x80, 0xf5, 0xa4, 0x3c, 0x52, 0xa6, 0xf3, 0x16, 0x96, 0xa6, 0x64, 0xac, 0x7e,
    0xaf, 0xb7, 0xc6, 0x34, 0xfd, 0xf7, 0x0a, 0x10, 0xe6, 0x2b, 0xda, 0x10, 0xdd, 0xb2, 0x44, 0x8d,
    0x95, 0x71, 0xbf, 0xb1, 0xf3, 0x91, 0xac, 0xc6, 0x93, 0xe1, 0x91, 0x62, 0x05, 0x90, 0x38, 0x33,
    0xcf, 0x36, 0xff, 0xa5, 0x82, 0x4e, 0x14, 0x78, 0x33, 0x40, 0x18, 0x22, 0xd6, 0x60, 0x6b, 0x0b,
    0x97, 0x4f, 0x2d, 0xd0, 0x36, 0x82, 0xb3, 0x1a, 0xe8, 0xd7, 0x93, 0xff, 0x19, 0xd1, 0x74, 0xd2,
    0x29, 0xe1, 0x97, 0x60, 0x09, 0x48, 0xef, 0xc9, 0x61, 0xae, 0x3b, 0x4f, 0xd4, 0x30, 0x82, 0x05,
    0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x82, 0x05, 0x32,
    0x04, 0x82, 0x05, 0x2e, 0x30, 0x82, 0x05, 0x2a, 0x30, 0x82, 0x05, 0x26, 0x06, 0x0b, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02, 0xa0, 0x82, 0x04, 0xee, 0x30, 0x82, 0x04,
    0xea, 0x30, 0x1c, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30,
    0x0e, 0x04, 0x08, 0x2b, 0xef, 0x2d, 0x9b, 0x33, 0xf6, 0x82, 0x62, 0x02, 0x02, 0x08, 0x00, 0x04,
    0x82, 0x04, 0xc8, 0x59, 0x60, 0xea, 0x6e, 0x23, 0x9e, 0x82, 0x1c, 0x0a, 0x8e, 0xbd, 0x09, 0x94,
    0x98, 0x5e, 0x1a, 0x1b, 0x4a, 0xfe, 0x86, 0x2d, 0xf4, 0x54, 0xaa, 0x17, 0xba, 0xf1, 0xf1, 0x58,
    0x12, 0xa2, 0x81, 0x1c, 0x29, 0xe7, 0x94, 0x78, 0xbc, 0x68, 0x07, 0x8f, 0xdb, 0x3f, 0xab, 0xa7,
    0xa7, 0x73, 0x6d, 0xea, 0x25, 0x6f, 0x97, 0xc8, 0xba, 0x73, 0xcc, 0x1e, 0xa0, 0x73, 0x18, 0x14,
    0xe8, 0xae, 0xe0, 0x5d, 0x3c, 0x9b, 0x9e, 0xad, 0xf4, 0x46, 0xeb, 0xa4, 0x73, 0xe2, 0xb5, 0x16,
    0x8f, 0x70, 0x35, 0xe7, 0x84, 0x2d, 0x02, 0xc7, 0xc3, 0x9d, 0x1e, 0x91, 0xba, 0x47, 0xfe, 0xf2,
    0x43, 0xc2, 0x9e, 0xeb, 0x68, 0x87, 0xeb, 0x3b, 0x9a, 0x59, 0x87, 0xf6, 0x2a, 0x1e, 0xf0, 0x07,
    0x13, 0xd0, 0xc0, 0x0f, 0xe7, 0x41, 0xb7, 0x5e, 0xb2, 0x2d, 0x12, 0xd2, 0x99, 0x6f, 0x90, 0x29,
    0xf2, 0x96, 0x9e, 0xfc, 0x00, 0x75, 0xab, 0x2f, 0x87, 0x49, 0x0e, 0xe6, 0xaf, 0x46, 0xe2, 0x69,
    0x88, 0x8f, 0xd3, 0x45, 0xda, 0xcc, 0x4c, 0xf6, 0xfd, 0xaa, 0xda, 0x83, 0x77, 0xee, 0xf9, 0x4a,
    0xa9, 0x31, 0x50, 0x8d, 0x8d, 0x86, 0x89, 0xb2, 0xf3, 0xcf, 0x9b, 0xba, 0xef, 0xa2, 0x09, 0x7c,
    0x72, 0x49, 0xf2, 0xf3, 0x86, 0xa2, 0x78, 0x3e, 0xbf, 0x61, 0x2a, 0x18, 0x96, 0xa2, 0x17, 0xe2,
    0x63, 0x75, 0xfd, 0xf0, 0x82, 0xd6, 0x36, 0x5b, 0x44, 0xf3, 0x9a, 0x96, 0x29, 0x1c, 0x50, 0x91,
    0x20, 0xbb, 0x7b, 0x2d, 0x96, 0xe1, 0x0e, 0xc6, 0xce, 0x01, 0x40, 0xe8, 0x22, 0xc5, 0xac, 0x3f,
    0xfa, 0xd0, 0xac, 0xc9, 0x4e, 0x1e, 0x20, 0x8a, 0xc6, 0x40, 0xed, 0x6b, 0xb6, 0xc4, 0xc1, 0x43,
    0xec, 0x3c, 0xfe, 0xb7, 0x50, 0x19, 0x09, 0x1b, 0x21, 0x83, 0x63, 0x93, 0x18, 0xbd, 0x73, 0x42,
    0x73, 0x25, 0x4f, 0xda, 0xdb, 0x4f, 0xf9, 0xba, 0x11, 0xf3, 0x91, 0xc0, 0x5b, 0x9d, 0x93, 0xfd,
    0x94, 0x89, 0xb6, 0xea, 0x90, 0x15, 0xe5, 0xf0, 0xe8, 0xd8, 0x31, 0x2c, 0xe0, 0x92, 0x6a, 0xb7,
    0xe3, 0x43, 0x51, 0xfc, 0xa0, 0x20, 0x2b, 0x5c, 0xbb, 0xf0, 0x22, 0x2b, 0xa5, 0x00, 0x40, 0xe9,
    0x0d, 0x64, 0xf0, 0xe7, 0xca, 0x29, 0x85, 0xfc, 0x89, 0x38, 0x03, 0xaa, 0x0c, 0xad, 0x71, 0xe6,
    0xc9, 0xde, 0x42, 0x5e, 0x97, 0x74, 0x35, 0x6a, 0x88, 0x94, 0x99, 0xd5, 0xbd, 0x91, 0xa5, 0x92,
    0x35, 0x1d, 0xf4, 0x11, 0xf7, 0x7e, 0x47, 0x96, 0xe4, 0x2f, 0x85, 0x75, 0x3a, 0x16, 0x2a, 0x45,
    0x96, 0xd7, 0xb1, 0x8f, 0xd5, 0x64, 0x87, 0x5d, 0xd0, 0x44, 0x1e, 0xd6, 0x67, 0x0c, 0xc6, 0xdb,
    0xb4, 0x0a, 0xe4, 0x18, 0x0c, 0x12, 0x73, 0xb5, 0x4f, 0x44, 0xc8, 0xd6, 0x97, 0x8b, 0x99, 0x19,
    0x66, 0x55, 0x08, 0xcb, 0xa0, 0xca, 0x9e, 0x09, 0x0f, 0xe1, 0x8b, 0xd7, 0xa1, 0x12, 0x54, 0x46,
    0x2d, 0x09, 0x44, 0x27, 0x30, 0xcd, 0x02, 0xcc, 0x88, 0x8f, 0x69, 0x22, 0xed, 0x31, 0x25, 0x14,
    0x5f, 0x37, 0x5f, 0xce, 0x91, 0x95, 0x30, 0x07, 0x32, 0xaa, 0x2e, 0x55, 0x9a, 0xc4, 0x33, 0xab,
    0xd0, 0x55, 0x3d, 0x04, 0xe3, 0x84, 0x0c, 0xf1, 0xe4, 0xe6, 0x52, 0x39, 0x0e, 0x22, 0x8b, 0x4f,
    0xf3, 0x5c, 0xc2, 0xc7, 0xc3, 0xd4, 0xc1, 0x5c, 0x45, 0x83, 0xee, 0x37, 0x3e, 0xa7, 0xd9, 0xa2,
    0x9c, 0x5b, 0x4b, 0x6b, 0xdf, 0xc5, 0x5c, 0x50, 0x12, 0x1d, 0x6c, 0x73, 0xea, 0xf4, 0xdc, 0x70,
    0x3f, 0x11, 0x70, 0x0e, 0x3d, 0x4d, 0x8c, 0x69, 0xaf, 0x8b, 0x6a, 0x20, 0x75, 0x55, 0xeb, 0x6e,
    0x27, 0x21, 0x5d, 0x9c, 0xdb, 0xbb, 0xf7, 0xf9, 0x3e, 0x81, 0x2f, 0x4f, 0x96, 0xcb, 0x2e, 0xb1,
    0xc3, 0x01, 0x1f, 0xa7, 0x87, 0x43, 0xc8, 0x89, 0xec, 0x5b, 0x41, 0x42, 0x2e, 0x19, 0x0b, 0xdf,
    0x3a, 0x90, 0xaa, 0x98, 0x2f, 0xe9, 0xad, 0x02, 0xf9, 0x96, 0x40, 0x51, 0xdd, 0x4b, 0x8b, 0xe5,
    0xca, 0x84, 0xe2, 0x93, 0xdd, 0xad, 0x43, 0x37, 0x62, 0x14, 0xa1, 0x07, 0x17, 0x5d, 0x71, 0x73,
    0xc0, 0xd8, 0x02, 0x0f, 0x44, 0xcf, 0x5e, 0x6f, 0x55, 0x44, 0x70, 0xa6, 0x22, 0xe7, 0x2d, 0xc3,
    0x2c, 0x44, 0xc3, 0x0e, 0xf1, 0xda, 0x02, 0x57, 0x40, 0x24, 0x36, 0xc8, 0xf9, 0x4f, 0x17, 0x0b,
    0x9b, 0x2a, 0xa8, 0x0d, 0x84, 0xf1, 0x49, 0x3b, 0x6d, 0x23, 0xb9, 0x97, 0x47, 0x2a, 0x0b, 0xc3,
    0x80, 0xe5, 0xdf, 0x4e, 0x1f, 0x94, 0xd1, 0x0e, 0x69, 0xb5, 0xb0, 0xf8, 0xa5, 0x7d, 0x9c, 0x9f,
    0x68, 0x7d, 0x04, 0x18, 0x42, 0x32, 0x72, 0xdc, 0xab, 0xdc, 0xe6, 0xba, 0x09, 0xe8, 0xd4, 0x27,
    0x53, 0x95, 0x9c, 0x39, 0xd5, 0x70, 0x0d, 0x1e, 0xb5, 0xb7, 0x2b, 0x0a, 0x79, 0xc7, 0xd6, 0x0b,
    0xee, 0xea, 0xf8, 0x6f, 0x6a, 0xb1, 0xfc, 0x90, 0x35, 0xce, 0x46, 0x99, 0xfa, 0x88, 0x01, 0x48,
    0xd5, 0x70, 0x26, 0x4c, 0x08, 0x2a, 0x13, 0x60, 0xb0, 0x96, 0x91, 0xa7, 0xc5, 0x05, 0xd3, 0xcd,
    0x5e, 0xcb, 0x9f, 0xa4, 0x5c, 0x29, 0x98, 0xbc, 0xd6, 0x2e, 0x6a, 0xeb, 0xc8, 0xfa, 0x58, 0x45,
    0x79, 0x15, 0x30, 0x98, 0x59, 0x65, 0x30, 0x7f, 0x14, 0x14, 0xbd, 0x27, 0xd1, 0x0c, 0xbc, 0x52,
    0xda, 0x42, 0x09, 0xc5, 0xc4, 0x58, 0xdb, 0x04, 0x22, 0xbd, 0x7a, 0xac, 0x55, 0x94, 0x52, 0x46,
    0x51, 0x32, 0x84, 0x9a, 0xeb, 0xe1, 0xd3, 0x9e, 0x9d, 0x48, 0x3d, 0xd2, 0x21, 0xfa, 0x7d, 0x10,
    0x04, 0x50, 0x06, 0xf0, 0x84, 0xcb, 0x9f, 0x39, 0xbe, 0xec, 0x03, 0x7d, 0x86, 0x85, 0xf5, 0x06,
    0x8c, 0x51, 0x74, 0x13, 0xf1, 0xfa, 0x50, 0xe1, 0x69, 0x23, 0xf6, 0x3e, 0x13, 0xd2, 0xc7, 0x52,
    0x80, 0xe6, 0x41, 0x86, 0x1d, 0x8a, 0xda, 0x3c, 0x3f, 0x90, 0x5c, 0x82, 0x85, 0x8d, 0x8c, 0x64,
    0x2a, 0xeb, 0xb9, 0x23, 0x6c, 0x0a, 0xd3, 0x2b, 0x35, 0xbe, 0xb0, 0x66, 0xd8, 0x1b, 0x45, 0xa1,
    0xb6, 0x67, 0x2d, 0xa6, 0xd6, 0xcd, 0x69, 0x88, 0x57, 0x70, 0xe6, 0xaa, 0x02, 0x3b, 0x84, 0x6a,
    0xb6, 0xa5, 0x91, 0x4a, 0x69, 0x20, 0x01, 0xd7, 0x5d, 0xf2, 0x7b, 0x3e, 0xf2, 0xbb, 0xe4, 0x9e,
    0x3a, 0xc0, 0xaa, 0x72, 0x2d, 0xa6, 0x47, 0x09, 0x2e, 0x0f, 0xf6, 0x9b, 0x8e, 0x7c, 0x41, 0xa6,
    0xc6, 0x10, 0x29, 0xcc, 0x4e, 0xcf, 0x01, 0xd5, 0x93, 0x75, 0x51, 0xb8, 0xd4, 0xec, 0xee, 0x6a,
    0x2f, 0x8b, 0x45, 0x65, 0xe8, 0xf5, 0x3e, 0xbc, 0xf4, 0x59, 0xec, 0x3e, 0x20, 0x18, 0x85, 0x31,
    0x8e, 0x25, 0x59, 0x16, 0x0f, 0xf0, 0x6e, 0xb1, 0x1e, 0x58, 0x83, 0x33, 0x10, 0x0d, 0x52, 0xc3,
    0x8f, 0x7e, 0x09, 0x27, 0xba, 0xd7, 0xf5, 0x8d, 0x79, 0xcf, 0x60, 0x52, 0xa2, 0x03, 0x46, 0xf5,
    0xf8, 0x9d, 0x6d, 0x5f, 0x23, 0x68, 0x7a, 0xb0, 0x2a, 0x55, 0x44, 0xd9, 0x58, 0xfd, 0xd1, 0x2d,
    0xcc, 0x75, 0xa2, 0x90, 0x8e, 0x7f, 0x91, 0x56, 0xa5, 0x3f, 0x62, 0x1a, 0x67, 0xd5, 0xb2, 0xc8,
    0x06, 0x66, 0xa7, 0xf7, 0xeb, 0x0c, 0xe0, 0xb0, 0xb5, 0x28, 0x8d, 0xda, 0x75, 0xd5, 0x03, 0x3e,
    0xc4, 0x4e, 0xd7, 0x6c, 0x7b, 0x28, 0x92, 0x7c, 0xeb, 0xb8, 0x67, 0x1a, 0x0c, 0xc4, 0xed, 0x5f,
    0x50, 0x5a, 0xb6, 0x52, 0xba, 0x9b, 0xe5, 0xcc, 0xb6, 0x78, 0x76, 0x9a, 0xcd, 0x2d, 0x43, 0x56,
    0xa4, 0xe7, 0x97, 0x6c, 0xdc, 0xb2, 0x2c, 0xb4, 0x2c, 0x30, 0x23, 0x1c, 0x51, 0x96, 0xca, 0x0d,
    0xbd, 0xf9, 0x2d, 0x97, 0x3c, 0x84, 0x45, 0x16, 0xcb, 0x25, 0xe2, 0x73, 0x9c, 0x4b, 0xbe, 0x36,
    0x12, 0xb3, 0xd0, 0x76, 0x9e, 0x5c, 0x40, 0xb9, 0x6f, 0x4e, 0x55, 0x1c, 0x87, 0xc4, 0x8d, 0x5a,
    0xda, 0x1b, 0xec, 0xd5, 0x03, 0x7f, 0x58, 0x78, 0xcc, 0xfa, 0xae, 0x0a, 0xb4, 0x3c, 0x50, 0xcd,
    0xa8, 0x7e, 0xfc, 0x17, 0x31, 0xd8, 0xe9, 0x86, 0x60, 0xa9, 0x0b, 0x11, 0x6b, 0xda, 0xfb, 0x6e,
    0x44, 0x62, 0xd8, 0x96, 0x4f, 0x61, 0xdb, 0x62, 0x0d, 0x03, 0xa6, 0x2f, 0x11, 0x91, 0x95, 0x38,
    0xf3, 0x49, 0x94, 0xf0, 0x93, 0x0e, 0xaf, 0xff, 0x28, 0xe6, 0x24, 0xbc, 0xc4, 0x1d, 0x0d, 0xfb,
    0x00, 0xc4, 0x5b, 0xef, 0xda, 0x55, 0x76, 0xbf, 0x52, 0xf9, 0x00, 0xab, 0xd5, 0xef, 0xa5, 0x31,
    0x37, 0x60, 0xcf, 0xad, 0x79, 0x45, 0xef, 0x0f, 0x97, 0xc8, 0x0e, 0x88, 0x61, 0x56, 0x58, 0x3b,
    0xd5, 0x1c, 0xe8, 0xb0, 0x93, 0x02, 0xdf, 0xa5, 0x6c, 0xaf, 0x4b, 0x5e, 0x66, 0x7d, 0xfe, 0xaa,
    0xaf, 0xa0, 0xd4, 0x35, 0xcd, 0x81, 0xa0, 0x71, 0xe4, 0x45, 0x12, 0x24, 0x1e, 0x0d, 0x06, 0x96,
    0x1e, 0x23, 0xa3, 0x39, 0xd8, 0xcc, 0x72, 0xd7, 0xac, 0x72, 0x5c, 0x8c, 0xdf, 0x6c, 0xb4, 0xc4,
    0x2b, 0xbc, 0x1c, 0xeb, 0xbe, 0x1b, 0xbb, 0xf3, 0xbc, 0x45, 0x34, 0xe9, 0x5a, 0x7f, 0x11, 0x61,
    0xd7, 0x61, 0x15, 0x18, 0x0e, 0xf8, 0x8b, 0x23, 0x97, 0xa7, 0x46, 0x31, 0x25, 0x30, 0x23, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15, 0x31, 0x16, 0x04, 0x14, 0x8b, 0x4e,
    0x13, 0x2a, 0xf1, 0x4d, 0xa3, 0xe9, 0x31, 0x5c, 0x6d, 0xce, 0x5a, 0x09, 0x93, 0x0a, 0xf4, 0x12,
    0x19, 0x7b, 0x30, 0x31, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14, 0x00, 0x3b, 0x70, 0x95, 0x68, 0xd3, 0xd8, 0x4f, 0x71, 0xd0, 0x7d, 0x41, 0x49,
    0x48, 0xef, 0x88, 0x6d, 0xe0, 0x9d, 0x53, 0x04, 0x08, 0x0e, 0x46, 0xa3, 0xb5, 0x73, 0x88, 0x7c,
    0x22, 0x02, 0x02, 0x08, 0x00
};
#endif /* CM_CERT_DATA_RSA_H */