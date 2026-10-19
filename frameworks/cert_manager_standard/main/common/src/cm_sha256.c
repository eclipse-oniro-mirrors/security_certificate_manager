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

#include "cm_sha256.h"

#include <stddef.h>

#define CM_SHA256_BLOCK_SIZE 64
#define CM_SHA256_WORD_NUM 8
#define CM_SHA256_ROUND_NUM 64

/* Round constants: first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes (FIPS 180-4 section 4.2.2). */
static const uint32_t g_sha256K[CM_SHA256_ROUND_NUM] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t CmSha256RotateRight(uint32_t value, uint32_t bits)
{
    return (value >> bits) | (value << (32 - bits));
}

static uint32_t CmSha256LoadBe32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
        (uint32_t)bytes[3];
}

static void CmSha256StoreBe32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

/* Compression function for one 64-byte block. The uint32 additions below
 * wrap modulo 2^32 by design (FIPS 180-4); the function name is covered by
 * the platform integer-overflow blocklist (fun:*Compress*). */
static void CmSha256Compress(uint32_t state[CM_SHA256_WORD_NUM], const uint8_t block[CM_SHA256_BLOCK_SIZE])
{
    uint32_t w[CM_SHA256_ROUND_NUM];
    for (uint32_t i = 0; i < 16; ++i) {
        w[i] = CmSha256LoadBe32(block + i * sizeof(uint32_t));
    }
    for (uint32_t i = 16; i < CM_SHA256_ROUND_NUM; ++i) {
        uint32_t s0 = CmSha256RotateRight(w[i - 15], 7) ^ CmSha256RotateRight(w[i - 15], 18) ^
            (w[i - 15] >> 3);
        uint32_t s1 = CmSha256RotateRight(w[i - 2], 17) ^ CmSha256RotateRight(w[i - 2], 19) ^
            (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (uint32_t i = 0; i < CM_SHA256_ROUND_NUM; ++i) {
        uint32_t bigS1 = CmSha256RotateRight(e, 6) ^ CmSha256RotateRight(e, 11) ^ CmSha256RotateRight(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t temp1 = h + bigS1 + choose + g_sha256K[i] + w[i];
        uint32_t bigS0 = CmSha256RotateRight(a, 2) ^ CmSha256RotateRight(a, 13) ^ CmSha256RotateRight(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = bigS0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

int32_t CmSha256(const uint8_t *data, uint32_t dataLen, uint8_t hash[CM_SHA256_HASH_LEN])
{
    if (hash == NULL || (data == NULL && dataLen != 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* Initial hash value: first 32 bits of the fractional parts of the
     * square roots of the first 8 primes (FIPS 180-4 section 5.3.3). */
    uint32_t state[CM_SHA256_WORD_NUM] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    uint32_t offset = 0;
    while (dataLen - offset >= CM_SHA256_BLOCK_SIZE) {
        CmSha256Compress(state, data + offset);
        offset += CM_SHA256_BLOCK_SIZE;
    }

    /* Padding: 0x80, zero fill, then the 64-bit big-endian bit length. */
    uint8_t tail[2 * CM_SHA256_BLOCK_SIZE] = {0};
    uint32_t tailLen = dataLen - offset;
    for (uint32_t i = 0; i < tailLen; ++i) {
        tail[i] = data[offset + i];
    }
    tail[tailLen] = 0x80;

    uint64_t bitLen = (uint64_t)dataLen * 8; /* 32-bit length keeps this within 2^35 bits */
    uint32_t paddedLen = (tailLen + 1 + sizeof(uint64_t) <= CM_SHA256_BLOCK_SIZE)
        ? CM_SHA256_BLOCK_SIZE
        : 2 * CM_SHA256_BLOCK_SIZE;
    for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
        tail[paddedLen - 1 - i] = (uint8_t)(bitLen >> (i * 8));
    }

    for (uint32_t i = 0; i < paddedLen; i += CM_SHA256_BLOCK_SIZE) {
        CmSha256Compress(state, tail + i);
    }

    for (uint32_t i = 0; i < CM_SHA256_WORD_NUM; ++i) {
        CmSha256StoreBe32(hash + i * sizeof(uint32_t), state[i]);
    }
    return CM_SUCCESS;
}
