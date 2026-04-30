/*
 * ZeroFIDO
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 */

#include "aes256.h"

#include <furi_hal_crypto.h>
#include <string.h>

#define ZF_AES_BLOCK_LEN 16U

static void zf_aes_secure_zero(void *data, size_t size) {
    volatile uint8_t *ptr = data;

    if (!ptr) {
        return;
    }
    while (size-- > 0U) {
        *ptr++ = 0;
    }
}

static bool zf_aes256_cbc_crypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *input,
                                uint8_t *output, size_t size, bool decrypt) {
    uint8_t iv_copy[ZF_AES_BLOCK_LEN];
    bool loaded = false;
    bool ok = false;

    if (!key || !iv || !input || !output || size == 0U || (size % ZF_AES_BLOCK_LEN) != 0U) {
        return false;
    }

    memcpy(iv_copy, iv, sizeof(iv_copy));
    loaded = furi_hal_crypto_load_key(key, iv_copy);
    if (loaded) {
        ok = decrypt ? furi_hal_crypto_decrypt(input, output, size) :
                       furi_hal_crypto_encrypt(input, output, size);
        (void)furi_hal_crypto_unload_key();
    }
    zf_aes_secure_zero(iv_copy, sizeof(iv_copy));
    return loaded && ok;
}

bool zf_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *input,
                           uint8_t *output, size_t size) {
    return zf_aes256_cbc_crypt(key, iv, input, output, size, false);
}

bool zf_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *input,
                           uint8_t *output, size_t size) {
    return zf_aes256_cbc_crypt(key, iv, input, output, size, true);
}

bool zf_aes256_cbc_zero_iv_encrypt(const uint8_t key[32], const uint8_t *input, uint8_t *output,
                                   size_t size) {
    const uint8_t iv[ZF_AES_BLOCK_LEN] = {0};
    return zf_aes256_cbc_encrypt(key, iv, input, output, size);
}

bool zf_aes256_cbc_zero_iv_decrypt(const uint8_t key[32], const uint8_t *input, uint8_t *output,
                                   size_t size) {
    const uint8_t iv[ZF_AES_BLOCK_LEN] = {0};
    return zf_aes256_cbc_decrypt(key, iv, input, output, size);
}
