/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// cppcheck-suppress-file variableScope
// cppcheck-suppress-file unreadVariable

#include <furi.h>
#include "persistence.h"
#include <furi_hal.h>
#include <storage/storage.h>
#include <furi_hal_random.h>
#include <flipper_format/flipper_format.h>
#include <mbedtls/ecp.h>
#include <stdlib.h>
#include "../zerofido_crypto.h"
#include "../zerofido_types.h"

#define TAG "U2f"

#if !ZF_RELEASE_DIAGNOSTICS
#undef FURI_LOG_E
#undef FURI_LOG_I
#define FURI_LOG_E(...) ((void)0)
#define FURI_LOG_I(...) ((void)0)
#endif

#define U2F_DATA_FOLDER ZF_APP_DATA_DIR "/u2f"
#define U2F_ASSETS_FOLDER U2F_DATA_FOLDER "/assets"
#define U2F_CERT_FILE U2F_DATA_FOLDER "/assets/cert.der"
#define U2F_CERT_FILE_TMP U2F_DATA_FOLDER "/assets/cert.der.tmp"
#define U2F_CERT_KEY_FILE U2F_DATA_FOLDER "/assets/cert_key.u2f"
#define U2F_CERT_KEY_FILE_TMP U2F_DATA_FOLDER "/assets/cert_key.u2f.tmp"
#define U2F_KEY_FILE U2F_DATA_FOLDER "/key.u2f"
#define U2F_KEY_FILE_TMP U2F_DATA_FOLDER "/key.u2f.tmp"
#define U2F_CNT_FILE U2F_DATA_FOLDER "/cnt.u2f"
#define U2F_CNT_FILE_TMP U2F_DATA_FOLDER "/cnt.u2f.tmp"

#define U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_FACTORY 2
#define U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT

#define U2F_CERT_STOCK 0 // Stock certificate, private key is encrypted with factory key
#define U2F_CERT_USER 1  // User certificate, private key is encrypted with unique key
#define U2F_CERT_USER_UNENCRYPTED                                                                  \
    2 // Unencrypted user certificate, will be encrypted after first load

#define U2F_CERT_KEY_FILE_TYPE "Flipper U2F Certificate Key File"
#define U2F_CERT_KEY_VERSION 1

#define U2F_DEVICE_KEY_FILE_TYPE "Flipper U2F Device Key File"
#define U2F_DEVICE_KEY_VERSION 1

#define U2F_COUNTER_FILE_TYPE "Flipper U2F Counter File"
#define U2F_COUNTER_VERSION 1
#define U2F_CERT_MAX_SIZE 1024

#define U2F_COUNTER_CONTROL_VAL 0xAA5500FF

typedef struct {
    uint32_t counter;
    uint8_t random_salt[24];
    uint32_t control;
} FURI_PACKED U2fCounterData;

static uint32_t u2f_data_counter_high_water(uint32_t counter) {
    uint32_t available = UINT32_MAX - counter;

    if (available < ZF_COUNTER_RESERVATION_WINDOW) {
        return UINT32_MAX;
    }
    return counter + ZF_COUNTER_RESERVATION_WINDOW;
}

static int u2f_data_random_cb(void *context, unsigned char *output, size_t output_len) {
    UNUSED(context);
    furi_hal_random_fill_buf(output, output_len);
    return 0;
}

static bool u2f_data_parse_der_length(const uint8_t *input, size_t input_len, size_t *header_len,
                                      size_t *value_len) {
    if (!input || input_len < 2 || !header_len || !value_len) {
        return false;
    }

    if ((input[1] & 0x80U) == 0) {
        *header_len = 2;
        *value_len = input[1];
        return *value_len <= input_len - *header_len;
    }

    size_t length_octets = input[1] & 0x7FU;
    if (length_octets == 0 || length_octets > sizeof(size_t) || 2 + length_octets > input_len) {
        return false;
    }

    size_t length = 0;
    for (size_t i = 0; i < length_octets; ++i) {
        length = (length << 8) | input[2 + i];
    }

    *header_len = 2 + length_octets;
    *value_len = length;
    return *value_len <= input_len - *header_len;
}

static bool u2f_data_read_der_element(const uint8_t *input, size_t input_len, uint8_t expected_tag,
                                      const uint8_t **value, size_t *value_len,
                                      size_t *element_len) {
    size_t header_len = 0;

    if (!input || input_len < 2 || !value || !value_len || !element_len ||
        input[0] != expected_tag) {
        return false;
    }
    if (!u2f_data_parse_der_length(input, input_len, &header_len, value_len)) {
        return false;
    }

    *value = input + header_len;
    if (*value_len > SIZE_MAX - header_len) {
        return false;
    }
    *element_len = header_len + *value_len;
    return true;
}

static bool u2f_data_extract_cert_public_key(const uint8_t *cert, size_t cert_len,
                                             uint8_t public_key[65]) {
    const uint8_t *certificate_value = NULL;
    const uint8_t *tbs_value = NULL;
    const uint8_t *spki_value = NULL;
    const uint8_t *element_value = NULL;
    const uint8_t *bit_string_value = NULL;
    size_t certificate_value_len = 0;
    size_t tbs_value_len = 0;
    size_t spki_value_len = 0;
    size_t element_value_len = 0;
    size_t bit_string_value_len = 0;
    size_t element_len = 0;
    size_t offset = 0;

    if (!u2f_data_read_der_element(cert, cert_len, 0x30, &certificate_value, &certificate_value_len,
                                   &element_len) ||
        element_len != cert_len) {
        return false;
    }
    if (!u2f_data_read_der_element(certificate_value, certificate_value_len, 0x30, &tbs_value,
                                   &tbs_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(certificate_value + offset, certificate_value_len - offset, 0x30,
                                   &element_value, &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(certificate_value + offset, certificate_value_len - offset, 0x03,
                                   &bit_string_value, &bit_string_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (offset != certificate_value_len) {
        return false;
    }

    offset = 0;
    if (offset < tbs_value_len && tbs_value[offset] == 0xA0) {
        if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0xA0,
                                       &element_value, &element_value_len, &element_len)) {
            return false;
        }
        offset += element_len;
    }
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x02, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x30, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x30, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x30, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x30, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(tbs_value + offset, tbs_value_len - offset, 0x30, &spki_value,
                                   &spki_value_len, &element_len)) {
        return false;
    }

    offset = 0;
    if (!u2f_data_read_der_element(spki_value, spki_value_len, 0x30, &element_value,
                                   &element_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (!u2f_data_read_der_element(spki_value + offset, spki_value_len - offset, 0x03,
                                   &bit_string_value, &bit_string_value_len, &element_len)) {
        return false;
    }
    offset += element_len;
    if (offset != spki_value_len || bit_string_value_len != 66 || bit_string_value[0] != 0x00 ||
        bit_string_value[1] != 0x04) {
        return false;
    }

    memcpy(public_key, bit_string_value + 1, 65);
    return true;
}

static bool u2f_data_file_exists(const char *path) {
    bool exists = false;
    Storage *storage = furi_record_open(RECORD_STORAGE);
    File *file = storage_file_alloc(storage);

    if (!file) {
        furi_record_close(RECORD_STORAGE);
        return false;
    }
    exists = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING);
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return exists;
}

static bool u2f_data_ensure_directories(Storage *storage) {
    if (!storage) {
        return false;
    }
    if (!storage_dir_exists(storage, ZF_APP_DATA_ROOT) &&
        !storage_simply_mkdir(storage, ZF_APP_DATA_ROOT)) {
        return false;
    }
    if (!storage_dir_exists(storage, ZF_APP_DATA_DIR) &&
        !storage_simply_mkdir(storage, ZF_APP_DATA_DIR)) {
        return false;
    }
    if (!storage_dir_exists(storage, U2F_DATA_FOLDER) &&
        !storage_simply_mkdir(storage, U2F_DATA_FOLDER)) {
        return false;
    }
    if (!storage_dir_exists(storage, U2F_ASSETS_FOLDER) &&
        !storage_simply_mkdir(storage, U2F_ASSETS_FOLDER)) {
        return false;
    }
    return true;
}

static bool u2f_data_write_file_atomic(Storage *storage, const char *path, const char *temp_path,
                                       const uint8_t *data, size_t size) {
    bool ok = false;
    File *file = NULL;

    if (!storage || !path || !temp_path || !data || size == 0) {
        return false;
    }

    file = storage_file_alloc(storage);
    if (!file) {
        return false;
    }

    storage_common_remove(storage, temp_path);
    if (storage_file_open(file, temp_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        size_t written = storage_file_write(file, data, size);
        storage_file_close(file);
        ok = written == size && (storage_common_rename(storage, temp_path, path) == FSE_OK);
    }
    storage_common_remove(storage, temp_path);
    storage_file_free(file);
    return ok;
}

bool u2f_data_key_exists(void) {
    return u2f_data_file_exists(U2F_KEY_FILE);
}

bool u2f_data_cnt_exists(void) {
    return u2f_data_file_exists(U2F_CNT_FILE);
}

bool u2f_data_check(bool cert_only) {
    bool state = false;
    Storage *fs_api = furi_record_open(RECORD_STORAGE);
    File *file = storage_file_alloc(fs_api);

    if (!file) {
        furi_record_close(RECORD_STORAGE);
        return false;
    }
    do {
        if (!storage_file_open(file, U2F_CERT_FILE, FSAM_READ, FSOM_OPEN_EXISTING))
            break;
        storage_file_close(file);
        if (!storage_file_open(file, U2F_CERT_KEY_FILE, FSAM_READ, FSOM_OPEN_EXISTING))
            break;
        if (cert_only) {
            state = true;
            break;
        }
        storage_file_close(file);
        if (!storage_file_open(file, U2F_KEY_FILE, FSAM_READ, FSOM_OPEN_EXISTING))
            break;
        storage_file_close(file);
        if (!storage_file_open(file, U2F_CNT_FILE, FSAM_READ, FSOM_OPEN_EXISTING))
            break;
        state = true;
    } while (0);

    storage_file_close(file);
    storage_file_free(file);

    furi_record_close(RECORD_STORAGE);

    return state;
}

static bool u2f_data_cert_public_key_load(uint8_t public_key[65]) {
    uint8_t *cert = malloc(U2F_CERT_MAX_SIZE);
    uint32_t cert_len = 0;
    bool ok = false;

    if (!cert) {
        return false;
    }

    cert_len = u2f_data_cert_load(cert, U2F_CERT_MAX_SIZE);
    if (cert_len > 0) {
        ok = u2f_data_extract_cert_public_key(cert, cert_len, public_key);
    }

    zf_crypto_secure_zero(cert, U2F_CERT_MAX_SIZE);
    free(cert);
    return ok;
}

bool u2f_data_cert_check(void) {
    uint8_t public_key[65];

    return u2f_data_cert_public_key_load(public_key);
}

uint32_t u2f_data_cert_load(uint8_t *cert, size_t capacity) {
    furi_assert(cert);

    Storage *fs_api = furi_record_open(RECORD_STORAGE);
    File *file = storage_file_alloc(fs_api);
    uint32_t len_cur = 0;

    if (!file) {
        furi_record_close(RECORD_STORAGE);
        return 0;
    }
    if (storage_file_open(file, U2F_CERT_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t file_size = storage_file_size(file);
        if (file_size <= capacity) {
            len_cur = storage_file_read(file, cert, file_size);
        }
        if (len_cur != file_size) {
            len_cur = 0;
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    return len_cur;
}

static bool u2f_data_cert_key_encrypt(uint8_t *cert_key) {
    furi_assert(cert_key);

    bool state = false;
    bool key_loaded = false;
    bool wrote_temp = false;
    uint8_t iv[16];
    uint8_t key[48];
    uint32_t cert_type = U2F_CERT_USER;

    FURI_LOG_I(TAG, "Encrypting user cert key");

    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE)) {
        FURI_LOG_E(TAG, "Unable to ensure encryption key");
        return false;
    }

    // Generate random IV
    furi_hal_random_fill_buf(iv, 16);

    if (!furi_hal_crypto_enclave_load_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE, iv)) {
        FURI_LOG_E(TAG, "Unable to load encryption key");
        return false;
    }
    key_loaded = true;

    if (!furi_hal_crypto_encrypt(cert_key, key, 32)) {
        FURI_LOG_E(TAG, "Encryption failed");
        goto cleanup;
    }
    furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    key_loaded = false;

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!flipper_format || !u2f_data_ensure_directories(storage)) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        goto cleanup;
    }
    zf_crypto_secure_zero(key + 32, sizeof(key) - 32);
    storage_common_remove(storage, U2F_CERT_KEY_FILE_TMP);
    if (flipper_format_file_open_always(flipper_format, U2F_CERT_KEY_FILE_TMP)) {
        do {
            if (!flipper_format_write_header_cstr(flipper_format, U2F_CERT_KEY_FILE_TYPE,
                                                  U2F_CERT_KEY_VERSION))
                break;
            if (!flipper_format_write_uint32(flipper_format, "Type", &cert_type, 1))
                break;
            if (!flipper_format_write_hex(flipper_format, "IV", iv, 16))
                break;
            if (!flipper_format_write_hex(flipper_format, "Data", key, 48))
                break;
            wrote_temp = true;
        } while (0);
    }
    flipper_format_free(flipper_format);
    if (wrote_temp) {
        state = storage_common_rename(storage, U2F_CERT_KEY_FILE_TMP, U2F_CERT_KEY_FILE) == FSE_OK;
    }
    storage_common_remove(storage, U2F_CERT_KEY_FILE_TMP);
    furi_record_close(RECORD_STORAGE);

cleanup:
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(key, sizeof(key));
    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    }
    return state;
}

bool u2f_data_cert_key_load(uint8_t *cert_key) {
    furi_assert(cert_key);

    bool state = false;
    bool key_loaded = false;
    uint8_t iv[16];
    uint8_t key[48];
    uint32_t cert_type = 0;
    uint8_t key_slot = 0;
    uint32_t version = 0;

    // Check if unique key exists in secure eclave and generate it if missing
    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE))
        return false;

    zf_crypto_secure_zero(cert_key, 32);

    FuriString *filetype;
    filetype = furi_string_alloc();

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!filetype || !flipper_format) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        if (filetype) {
            furi_string_free(filetype);
        }
        return false;
    }

    if (flipper_format_file_open_existing(flipper_format, U2F_CERT_KEY_FILE)) {
        do {
            if (!flipper_format_read_header(flipper_format, filetype, &version)) {
                FURI_LOG_E(TAG, "Missing or incorrect header");
                break;
            }

            if (strcmp(furi_string_get_cstr(filetype), U2F_CERT_KEY_FILE_TYPE) != 0 ||
                version != U2F_CERT_KEY_VERSION) {
                FURI_LOG_E(TAG, "Type or version mismatch");
                break;
            }

            if (!flipper_format_read_uint32(flipper_format, "Type", &cert_type, 1)) {
                FURI_LOG_E(TAG, "Missing cert type");
                break;
            }

            if (cert_type == U2F_CERT_STOCK) {
                key_slot = U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_FACTORY;
            } else if (cert_type == U2F_CERT_USER) {
                key_slot = U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE;
            } else if (cert_type == U2F_CERT_USER_UNENCRYPTED) {
                key_slot = 0;
            } else {
                FURI_LOG_E(TAG, "Unknown cert type");
                break;
            }
            if (key_slot != 0) {
                if (!flipper_format_read_hex(flipper_format, "IV", iv, 16)) {
                    FURI_LOG_E(TAG, "Missing IV");
                    break;
                }

                if (!flipper_format_read_hex(flipper_format, "Data", key, 48)) {
                    FURI_LOG_E(TAG, "Missing data");
                    break;
                }

                if (!furi_hal_crypto_enclave_load_key(key_slot, iv)) {
                    FURI_LOG_E(TAG, "Unable to load encryption key");
                    break;
                }
                key_loaded = true;
                zf_crypto_secure_zero(cert_key, 32);

                if (!furi_hal_crypto_decrypt(key, cert_key, 32)) {
                    zf_crypto_secure_zero(cert_key, 32);
                    FURI_LOG_E(TAG, "Decryption failed");
                    break;
                }
                furi_hal_crypto_enclave_unload_key(key_slot);
                key_loaded = false;
            } else {
                if (!flipper_format_read_hex(flipper_format, "Data", cert_key, 32)) {
                    FURI_LOG_E(TAG, "Missing data");
                    break;
                }
            }
            state = true;
        } while (0);
    }

    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(filetype);

    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(key_slot);
    }

    if (state && cert_type == U2F_CERT_USER_UNENCRYPTED) {
        state = u2f_data_cert_key_encrypt(cert_key);
    }
    if (!state) {
        zf_crypto_secure_zero(cert_key, 32);
    }

    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(key, sizeof(key));
    return state;
}

bool u2f_data_cert_key_matches(const uint8_t *cert_key) {
    bool state = false;
    uint8_t cert_public_key[65];
    uint8_t derived_public_key[65];
    mbedtls_ecp_group group;
    mbedtls_ecp_point derived;
    mbedtls_mpi private_key;
    size_t derived_public_key_len = 0;

    if (!cert_key || !u2f_data_cert_public_key_load(cert_public_key)) {
        return false;
    }

    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&derived);
    mbedtls_mpi_init(&private_key);

    do {
        if (mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            FURI_LOG_E(TAG, "Unable to load P-256 group");
            break;
        }
        if (mbedtls_mpi_read_binary(&private_key, cert_key, 32) != 0) {
            FURI_LOG_E(TAG, "Unable to read attestation private key");
            break;
        }
        if (mbedtls_ecp_mul(&group, &derived, &private_key, &group.G, u2f_data_random_cb, NULL) !=
            0) {
            FURI_LOG_E(TAG, "Unable to derive attestation public key");
            break;
        }
        if (mbedtls_ecp_point_write_binary(&group, &derived, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &derived_public_key_len, derived_public_key,
                                           sizeof(derived_public_key)) != 0) {
            FURI_LOG_E(TAG, "Unable to encode attestation public key");
            break;
        }
        if (derived_public_key_len != sizeof(derived_public_key)) {
            FURI_LOG_E(TAG, "Unexpected attestation public key length");
            break;
        }
        if (memcmp(derived_public_key, cert_public_key, sizeof(derived_public_key)) != 0) {
            FURI_LOG_E(TAG, "Certificate/public key mismatch");
            break;
        }

        state = true;
    } while (0);

    mbedtls_mpi_free(&private_key);
    mbedtls_ecp_point_free(&derived);
    mbedtls_ecp_group_free(&group);
    return state;
}

bool u2f_data_bootstrap_attestation_assets(const uint8_t *cert, size_t cert_len,
                                           const uint8_t *cert_key, size_t cert_key_len) {
    bool ok = false;
    uint8_t cert_key_copy[32];
    Storage *storage = NULL;

    if (!cert || !cert_key || cert_len == 0 || cert_len > U2F_CERT_MAX_SIZE || cert_key_len != 32) {
        return false;
    }

    storage = furi_record_open(RECORD_STORAGE);
    if (!storage) {
        return false;
    }

    do {
        if (!u2f_data_ensure_directories(storage)) {
            break;
        }
        if (!u2f_data_write_file_atomic(storage, U2F_CERT_FILE, U2F_CERT_FILE_TMP, cert,
                                        cert_len)) {
            break;
        }
        memcpy(cert_key_copy, cert_key, sizeof(cert_key_copy));
        if (!u2f_data_cert_key_encrypt(cert_key_copy)) {
            zf_crypto_secure_zero(cert_key_copy, sizeof(cert_key_copy));
            storage_common_remove(storage, U2F_CERT_FILE);
            break;
        }
        zf_crypto_secure_zero(cert_key_copy, sizeof(cert_key_copy));
        ok = true;
    } while (false);

    furi_record_close(RECORD_STORAGE);
    return ok;
}

bool u2f_data_key_load(uint8_t *device_key) {
    furi_assert(device_key);

    bool state = false;
    bool key_loaded = false;
    uint8_t iv[16];
    uint8_t key[48];
    uint32_t version = 0;

    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE)) {
        return false;
    }

    FuriString *filetype;
    filetype = furi_string_alloc();

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!filetype || !flipper_format) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        if (filetype) {
            furi_string_free(filetype);
        }
        return false;
    }

    if (flipper_format_file_open_existing(flipper_format, U2F_KEY_FILE)) {
        do {
            if (!flipper_format_read_header(flipper_format, filetype, &version)) {
                FURI_LOG_E(TAG, "Missing or incorrect header");
                break;
            }
            if (strcmp(furi_string_get_cstr(filetype), U2F_DEVICE_KEY_FILE_TYPE) != 0 ||
                version != U2F_DEVICE_KEY_VERSION) {
                FURI_LOG_E(TAG, "Type or version mismatch");
                break;
            }
            if (!flipper_format_read_hex(flipper_format, "IV", iv, 16)) {
                FURI_LOG_E(TAG, "Missing IV");
                break;
            }
            if (!flipper_format_read_hex(flipper_format, "Data", key, 48)) {
                FURI_LOG_E(TAG, "Missing data");
                break;
            }
            if (!furi_hal_crypto_enclave_load_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE, iv)) {
                FURI_LOG_E(TAG, "Unable to load encryption key");
                break;
            }
            key_loaded = true;
            zf_crypto_secure_zero(device_key, 32);
            if (!furi_hal_crypto_decrypt(key, device_key, 32)) {
                zf_crypto_secure_zero(device_key, 32);
                FURI_LOG_E(TAG, "Decryption failed");
                break;
            }
            furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
            key_loaded = false;
            state = true;
        } while (0);
    }
    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    }
    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(filetype);
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(key, sizeof(key));
    return state;
}

bool u2f_data_key_generate(uint8_t *device_key) {
    furi_assert(device_key);

    bool state = false;
    bool key_loaded = false;
    bool wrote_temp = false;
    uint8_t iv[16];
    uint8_t key[32];
    uint8_t key_encrypted[48];

    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE)) {
        FURI_LOG_E(TAG, "Unable to ensure encryption key");
        return false;
    }

    // Generate random IV and key
    furi_hal_random_fill_buf(iv, 16);
    furi_hal_random_fill_buf(key, 32);

    if (!furi_hal_crypto_enclave_load_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE, iv)) {
        FURI_LOG_E(TAG, "Unable to load encryption key");
        goto cleanup;
    }
    key_loaded = true;

    if (!furi_hal_crypto_encrypt(key, key_encrypted, 32)) {
        FURI_LOG_E(TAG, "Encryption failed");
        goto cleanup;
    }
    furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    key_loaded = false;

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!flipper_format || !u2f_data_ensure_directories(storage)) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        goto cleanup;
    }
    zf_crypto_secure_zero(key_encrypted + 32, sizeof(key_encrypted) - 32);
    storage_common_remove(storage, U2F_KEY_FILE_TMP);
    if (flipper_format_file_open_always(flipper_format, U2F_KEY_FILE_TMP)) {
        do {
            if (!flipper_format_write_header_cstr(flipper_format, U2F_DEVICE_KEY_FILE_TYPE,
                                                  U2F_DEVICE_KEY_VERSION))
                break;
            if (!flipper_format_write_hex(flipper_format, "IV", iv, 16))
                break;
            if (!flipper_format_write_hex(flipper_format, "Data", key_encrypted, 48))
                break;
            wrote_temp = true;
        } while (0);
    }
    flipper_format_free(flipper_format);
    if (wrote_temp) {
        state = storage_common_rename(storage, U2F_KEY_FILE_TMP, U2F_KEY_FILE) == FSE_OK;
    }
    if (state) {
        memcpy(device_key, key, 32);
    }
    storage_common_remove(storage, U2F_KEY_FILE_TMP);
    furi_record_close(RECORD_STORAGE);

cleanup:
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(key, sizeof(key));
    zf_crypto_secure_zero(key_encrypted, sizeof(key_encrypted));
    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    }
    return state;
}

bool u2f_data_cnt_read(uint32_t *cnt_val) {
    furi_assert(cnt_val);

    bool state = false;
    bool key_loaded = false;
    uint8_t iv[16];
    U2fCounterData cnt;
    uint8_t cnt_encr[48];
    uint32_t version = 0;

    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE)) {
        return false;
    }

    FuriString *filetype;
    filetype = furi_string_alloc();

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!filetype || !flipper_format) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        if (filetype) {
            furi_string_free(filetype);
        }
        return false;
    }

    if (flipper_format_file_open_existing(flipper_format, U2F_CNT_FILE)) {
        do {
            if (!flipper_format_read_header(flipper_format, filetype, &version)) {
                FURI_LOG_E(TAG, "Missing or incorrect header");
                break;
            }
            if (strcmp(furi_string_get_cstr(filetype), U2F_COUNTER_FILE_TYPE) != 0) {
                FURI_LOG_E(TAG, "Type mismatch");
                break;
            }
            if (version != U2F_COUNTER_VERSION) {
                FURI_LOG_E(TAG, "Version mismatch");
                break;
            }
            if (!flipper_format_read_hex(flipper_format, "IV", iv, 16)) {
                FURI_LOG_E(TAG, "Missing IV");
                break;
            }
            if (!flipper_format_read_hex(flipper_format, "Data", cnt_encr, 48)) {
                FURI_LOG_E(TAG, "Missing data");
                break;
            }
            if (!furi_hal_crypto_enclave_load_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE, iv)) {
                FURI_LOG_E(TAG, "Unable to load encryption key");
                break;
            }
            key_loaded = true;
            zf_crypto_secure_zero(&cnt, sizeof(cnt));
            if (!furi_hal_crypto_decrypt(cnt_encr, (uint8_t *)&cnt, sizeof(U2fCounterData))) {
                zf_crypto_secure_zero(&cnt, sizeof(cnt));
                FURI_LOG_E(TAG, "Decryption failed");
                break;
            }
            furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
            key_loaded = false;
            if (cnt.control == U2F_COUNTER_CONTROL_VAL) {
                *cnt_val = cnt.counter;
                state = true;
            }
        } while (0);
    }
    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    }
    flipper_format_free(flipper_format);
    furi_record_close(RECORD_STORAGE);
    furi_string_free(filetype);
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(&cnt, sizeof(cnt));
    zf_crypto_secure_zero(cnt_encr, sizeof(cnt_encr));

    return state;
}

bool u2f_data_cnt_write(uint32_t cnt_val) {
    bool state = false;
    bool key_loaded = false;
    bool wrote_temp = false;
    uint8_t iv[16];
    U2fCounterData cnt;
    uint8_t cnt_encr[48];

    if (!furi_hal_crypto_enclave_ensure_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE)) {
        FURI_LOG_E(TAG, "Unable to ensure encryption key");
        return false;
    }

    // Generate random IV and key
    furi_hal_random_fill_buf(iv, 16);
    furi_hal_random_fill_buf(cnt.random_salt, 24);
    cnt.control = U2F_COUNTER_CONTROL_VAL;
    cnt.counter = cnt_val;

    if (!furi_hal_crypto_enclave_load_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE, iv)) {
        FURI_LOG_E(TAG, "Unable to load encryption key");
        goto cleanup;
    }
    key_loaded = true;

    if (!furi_hal_crypto_encrypt((uint8_t *)&cnt, cnt_encr, 32)) {
        FURI_LOG_E(TAG, "Encryption failed");
        goto cleanup;
    }
    furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    key_loaded = false;

    Storage *storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat *flipper_format = flipper_format_file_alloc(storage);

    if (!flipper_format || !u2f_data_ensure_directories(storage)) {
        if (flipper_format) {
            flipper_format_free(flipper_format);
        }
        furi_record_close(RECORD_STORAGE);
        goto cleanup;
    }
    zf_crypto_secure_zero(cnt_encr + 32, sizeof(cnt_encr) - 32);
    storage_common_remove(storage, U2F_CNT_FILE_TMP);
    if (flipper_format_file_open_always(flipper_format, U2F_CNT_FILE_TMP)) {
        do {
            if (!flipper_format_write_header_cstr(flipper_format, U2F_COUNTER_FILE_TYPE,
                                                  U2F_COUNTER_VERSION))
                break;
            if (!flipper_format_write_hex(flipper_format, "IV", iv, 16))
                break;
            if (!flipper_format_write_hex(flipper_format, "Data", cnt_encr, 48))
                break;
            wrote_temp = true;
        } while (0);
    }
    flipper_format_free(flipper_format);
    if (wrote_temp) {
        state = storage_common_rename(storage, U2F_CNT_FILE_TMP, U2F_CNT_FILE) == FSE_OK;
    }
    storage_common_remove(storage, U2F_CNT_FILE_TMP);
    furi_record_close(RECORD_STORAGE);

cleanup:
    zf_crypto_secure_zero(iv, sizeof(iv));
    zf_crypto_secure_zero(&cnt, sizeof(cnt));
    zf_crypto_secure_zero(cnt_encr, sizeof(cnt_encr));
    if (key_loaded) {
        furi_hal_crypto_enclave_unload_key(U2F_DATA_FILE_ENCRYPTION_KEY_SLOT_UNIQUE);
    }
    return state;
}

bool u2f_data_cnt_reserve(uint32_t cnt_val, uint32_t *reserved_cnt) {
    uint32_t high_water = u2f_data_counter_high_water(cnt_val);

    if (!u2f_data_cnt_write(high_water)) {
        return false;
    }
    if (reserved_cnt) {
        *reserved_cnt = high_water;
    }
    return true;
}

static bool u2f_data_remove_optional(Storage *storage, const char *path) {
    FS_Error result = storage_common_remove(storage, path);
    return result == FSE_OK || result == FSE_NOT_EXIST;
}

bool u2f_data_wipe(Storage *storage) {
    if (!storage) {
        return false;
    }

    return u2f_data_remove_optional(storage, U2F_CERT_FILE) &&
           u2f_data_remove_optional(storage, U2F_CERT_FILE_TMP) &&
           u2f_data_remove_optional(storage, U2F_CERT_KEY_FILE) &&
           u2f_data_remove_optional(storage, U2F_CERT_KEY_FILE_TMP) &&
           u2f_data_remove_optional(storage, U2F_KEY_FILE) &&
           u2f_data_remove_optional(storage, U2F_KEY_FILE_TMP) &&
           u2f_data_remove_optional(storage, U2F_CNT_FILE) &&
           u2f_data_remove_optional(storage, U2F_CNT_FILE_TMP);
}
