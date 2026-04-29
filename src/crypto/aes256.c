/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "aes256.h"

#include <string.h>

#define ZF_AES_BLOCK_LEN 16U
#define ZF_AES_KEY_LEN 32U
#define ZF_AES_ROUND_KEY_LEN 240U
#define ZF_AES_NB 4U
#define ZF_AES_NK 8U
#define ZF_AES_NR 14U

static const uint8_t zf_aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
    0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
    0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
    0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
    0x16,
};

static const uint8_t zf_aes_rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
    0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde,
    0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
    0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c,
    0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
    0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7,
    0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
    0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
    0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
    0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
    0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
    0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
    0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
    0x7d,
};

static const uint8_t zf_aes_rcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
};

static void zf_aes_secure_zero(void *data, size_t size) {
    volatile uint8_t *ptr = data;

    if (!ptr) {
        return;
    }
    while (size-- > 0U) {
        *ptr++ = 0;
    }
}

static uint8_t zf_aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1U) ^ (((x >> 7U) & 1U) * 0x1BU));
}

static uint8_t zf_aes_multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;

    while (y != 0U) {
        if (y & 1U) {
            result ^= x;
        }
        x = zf_aes_xtime(x);
        y >>= 1U;
    }
    return result;
}

static void zf_aes_key_expansion(const uint8_t key[ZF_AES_KEY_LEN],
                                 uint8_t round_key[ZF_AES_ROUND_KEY_LEN]) {
    uint8_t temp[4];
    unsigned i = 0;

    memcpy(round_key, key, ZF_AES_KEY_LEN);
    for (i = ZF_AES_NK; i < ZF_AES_NB * (ZF_AES_NR + 1U); ++i) {
        temp[0] = round_key[(i - 1U) * 4U + 0U];
        temp[1] = round_key[(i - 1U) * 4U + 1U];
        temp[2] = round_key[(i - 1U) * 4U + 2U];
        temp[3] = round_key[(i - 1U) * 4U + 3U];

        if ((i % ZF_AES_NK) == 0U) {
            uint8_t first = temp[0];
            temp[0] = (uint8_t)(zf_aes_sbox[temp[1]] ^ zf_aes_rcon[i / ZF_AES_NK]);
            temp[1] = zf_aes_sbox[temp[2]];
            temp[2] = zf_aes_sbox[temp[3]];
            temp[3] = zf_aes_sbox[first];
        } else if ((i % ZF_AES_NK) == 4U) {
            temp[0] = zf_aes_sbox[temp[0]];
            temp[1] = zf_aes_sbox[temp[1]];
            temp[2] = zf_aes_sbox[temp[2]];
            temp[3] = zf_aes_sbox[temp[3]];
        }

        round_key[i * 4U + 0U] = (uint8_t)(round_key[(i - ZF_AES_NK) * 4U + 0U] ^ temp[0]);
        round_key[i * 4U + 1U] = (uint8_t)(round_key[(i - ZF_AES_NK) * 4U + 1U] ^ temp[1]);
        round_key[i * 4U + 2U] = (uint8_t)(round_key[(i - ZF_AES_NK) * 4U + 2U] ^ temp[2]);
        round_key[i * 4U + 3U] = (uint8_t)(round_key[(i - ZF_AES_NK) * 4U + 3U] ^ temp[3]);
    }
}

static void zf_aes_add_round_key(uint8_t state[ZF_AES_BLOCK_LEN],
                                 const uint8_t round_key[ZF_AES_ROUND_KEY_LEN], unsigned round) {
    for (unsigned i = 0; i < ZF_AES_BLOCK_LEN; ++i) {
        state[i] ^= round_key[round * ZF_AES_BLOCK_LEN + i];
    }
}

static void zf_aes_sub_bytes(uint8_t state[ZF_AES_BLOCK_LEN]) {
    for (unsigned i = 0; i < ZF_AES_BLOCK_LEN; ++i) {
        state[i] = zf_aes_sbox[state[i]];
    }
}

static void zf_aes_inv_sub_bytes(uint8_t state[ZF_AES_BLOCK_LEN]) {
    for (unsigned i = 0; i < ZF_AES_BLOCK_LEN; ++i) {
        state[i] = zf_aes_rsbox[state[i]];
    }
}

static void zf_aes_shift_rows(uint8_t state[ZF_AES_BLOCK_LEN]) {
    uint8_t tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

static void zf_aes_inv_shift_rows(uint8_t state[ZF_AES_BLOCK_LEN]) {
    uint8_t tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;

    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;

    tmp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

static void zf_aes_mix_columns(uint8_t state[ZF_AES_BLOCK_LEN]) {
    for (unsigned i = 0; i < 4U; ++i) {
        uint8_t *col = state + i * 4U;
        uint8_t t = col[0];
        uint8_t u = (uint8_t)(col[0] ^ col[1] ^ col[2] ^ col[3]);

        col[0] ^= u ^ zf_aes_xtime((uint8_t)(col[0] ^ col[1]));
        col[1] ^= u ^ zf_aes_xtime((uint8_t)(col[1] ^ col[2]));
        col[2] ^= u ^ zf_aes_xtime((uint8_t)(col[2] ^ col[3]));
        col[3] ^= u ^ zf_aes_xtime((uint8_t)(col[3] ^ t));
    }
}

static void zf_aes_inv_mix_columns(uint8_t state[ZF_AES_BLOCK_LEN]) {
    for (unsigned i = 0; i < 4U; ++i) {
        uint8_t *col = state + i * 4U;
        uint8_t a = col[0];
        uint8_t b = col[1];
        uint8_t c = col[2];
        uint8_t d = col[3];

        col[0] = (uint8_t)(zf_aes_multiply(a, 0x0e) ^ zf_aes_multiply(b, 0x0b) ^
                           zf_aes_multiply(c, 0x0d) ^ zf_aes_multiply(d, 0x09));
        col[1] = (uint8_t)(zf_aes_multiply(a, 0x09) ^ zf_aes_multiply(b, 0x0e) ^
                           zf_aes_multiply(c, 0x0b) ^ zf_aes_multiply(d, 0x0d));
        col[2] = (uint8_t)(zf_aes_multiply(a, 0x0d) ^ zf_aes_multiply(b, 0x09) ^
                           zf_aes_multiply(c, 0x0e) ^ zf_aes_multiply(d, 0x0b));
        col[3] = (uint8_t)(zf_aes_multiply(a, 0x0b) ^ zf_aes_multiply(b, 0x0d) ^
                           zf_aes_multiply(c, 0x09) ^ zf_aes_multiply(d, 0x0e));
    }
}

static void zf_aes_encrypt_block(const uint8_t round_key[ZF_AES_ROUND_KEY_LEN],
                                 uint8_t block[ZF_AES_BLOCK_LEN]) {
    zf_aes_add_round_key(block, round_key, 0);
    for (unsigned round = 1; round < ZF_AES_NR; ++round) {
        zf_aes_sub_bytes(block);
        zf_aes_shift_rows(block);
        zf_aes_mix_columns(block);
        zf_aes_add_round_key(block, round_key, round);
    }
    zf_aes_sub_bytes(block);
    zf_aes_shift_rows(block);
    zf_aes_add_round_key(block, round_key, ZF_AES_NR);
}

static void zf_aes_decrypt_block(const uint8_t round_key[ZF_AES_ROUND_KEY_LEN],
                                 uint8_t block[ZF_AES_BLOCK_LEN]) {
    zf_aes_add_round_key(block, round_key, ZF_AES_NR);
    for (unsigned round = ZF_AES_NR - 1U; round > 0U; --round) {
        zf_aes_inv_shift_rows(block);
        zf_aes_inv_sub_bytes(block);
        zf_aes_add_round_key(block, round_key, round);
        zf_aes_inv_mix_columns(block);
    }
    zf_aes_inv_shift_rows(block);
    zf_aes_inv_sub_bytes(block);
    zf_aes_add_round_key(block, round_key, 0);
}

bool zf_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                                  const uint8_t *input, uint8_t *output, size_t size) {
    uint8_t round_key[ZF_AES_ROUND_KEY_LEN];
    uint8_t chain[ZF_AES_BLOCK_LEN];
    uint8_t block[ZF_AES_BLOCK_LEN];
    bool ok = false;

    if (!key || !iv || !input || !output || size == 0 || (size % ZF_AES_BLOCK_LEN) != 0U) {
        return false;
    }

    zf_aes_key_expansion(key, round_key);
    memcpy(chain, iv, sizeof(chain));
    for (size_t offset = 0; offset < size; offset += ZF_AES_BLOCK_LEN) {
        memcpy(block, input + offset, sizeof(block));
        for (size_t i = 0; i < sizeof(block); ++i) {
            block[i] ^= chain[i];
        }
        zf_aes_encrypt_block(round_key, block);
        memcpy(output + offset, block, sizeof(block));
        memcpy(chain, block, sizeof(chain));
    }
    ok = true;

    zf_aes_secure_zero(round_key, sizeof(round_key));
    zf_aes_secure_zero(chain, sizeof(chain));
    zf_aes_secure_zero(block, sizeof(block));
    return ok;
}

bool zf_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                                  const uint8_t *input, uint8_t *output, size_t size) {
    uint8_t round_key[ZF_AES_ROUND_KEY_LEN];
    uint8_t chain[ZF_AES_BLOCK_LEN];
    uint8_t cipher_block[ZF_AES_BLOCK_LEN];
    uint8_t block[ZF_AES_BLOCK_LEN];
    bool ok = false;

    if (!key || !iv || !input || !output || size == 0 || (size % ZF_AES_BLOCK_LEN) != 0U) {
        return false;
    }

    zf_aes_key_expansion(key, round_key);
    memcpy(chain, iv, sizeof(chain));
    for (size_t offset = 0; offset < size; offset += ZF_AES_BLOCK_LEN) {
        memcpy(cipher_block, input + offset, sizeof(cipher_block));
        memcpy(block, cipher_block, sizeof(block));
        zf_aes_decrypt_block(round_key, block);
        for (size_t i = 0; i < sizeof(block); ++i) {
            output[offset + i] = (uint8_t)(block[i] ^ chain[i]);
        }
        memcpy(chain, cipher_block, sizeof(chain));
    }
    ok = true;

    zf_aes_secure_zero(round_key, sizeof(round_key));
    zf_aes_secure_zero(chain, sizeof(chain));
    zf_aes_secure_zero(cipher_block, sizeof(cipher_block));
    zf_aes_secure_zero(block, sizeof(block));
    return ok;
}

bool zf_aes256_cbc_zero_iv_encrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};
    return zf_aes256_cbc_encrypt(key, iv, input, output, size);
}

bool zf_aes256_cbc_zero_iv_decrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};
    return zf_aes256_cbc_decrypt(key, iv, input, output, size);
}
