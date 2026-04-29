#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "furi.h"
#include "flipper_format/flipper_format.h"
#include "mbedtls/ecp.h"
#include "store/record_format.h"
#include "store/recovery.h"
#include "zerofido_attestation.h"
#include "zerofido_app_i.h"
#include "zerofido_cbor.h"
#include "zerofido_crypto.h"
#include "ctap/parse.h"
#include "ctap/policy.h"
#include "ctap/response.h"
#include "store/internal.h"
#include "pin/store/internal.h"
#include "store/record_format_internal.h"

/*
 * Host-native protocol regression harness. This file provides fake Flipper
 * platform services, includes the production C modules directly, and exercises
 * CTAP/PIN/store behavior without device hardware.
 */

#define FURI_PACKED __attribute__((packed))
static void test_furi_log_i(const char *tag, const char *fmt, ...);
#define FURI_LOG_I test_furi_log_i
#define FURI_LOG_E(tag, fmt, ...) ((void)0)
#define FURI_LOG_W(tag, fmt, ...) ((void)0)
#define FURI_LOG_D(tag, fmt, ...) ((void)0)
#define RECORD_STORAGE "storage"
#define EXT_PATH(path) path
#define __REV(value) __builtin_bswap32(value)
#define furi_assert(expr)                                                                          \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "FAIL: assertion failed: %s\n", #expr);                                \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

struct Storage {
    int unused;
};

struct File {
    char path[160];
    FS_AccessMode access_mode;
    size_t offset;
    bool open;
};

struct FileInfo {
    int unused;
};

struct FlipperFormat {
    int unused;
};

struct FuriString {
    char value[64];
};

static uint8_t g_key_agreement_seed = 1;
static bool g_fail_crypto_encrypt = false;
static bool g_fail_crypto_decrypt = false;
static size_t g_fail_crypto_decrypt_after = SIZE_MAX;
static bool g_fail_crypto_enclave_load_key = false;
static bool g_crypto_verify_hash_result = true;
static uint8_t g_pin_file_data[128];
static size_t g_pin_file_size = 0;
static bool g_pin_file_exists = false;
static uint8_t g_pin_temp_data[128];
static size_t g_pin_temp_size = 0;
static bool g_pin_temp_exists = false;
static bool g_remove_attempted_pin_v2_file = false;
static bool g_remove_attempted_pin_v2_temp = false;
static const char *g_storage_fail_rename_match = NULL;
static const char *g_storage_fail_remove_match = NULL;
static const char *g_storage_fail_copy_match = NULL;
static const char *g_storage_fail_write_match = NULL;
static const char *g_storage_fail_mkdir_match = NULL;
static size_t g_approval_request_count = 0;
static bool g_approval_request_ok = true;
static bool g_approval_result = true;
static ZfApprovalState g_approval_state = ZfApprovalApproved;
static bool g_attestation_ensure_ready = true;
static size_t g_selection_request_count = 0;
static bool g_selection_request_ok = true;
static size_t g_selection_index = 0;
static size_t g_last_selection_match_count = 0;
static uint32_t g_fake_tick = 1000;
static uint8_t g_transport_poll_status = ZF_CTAP_SUCCESS;
static size_t g_mutex_depth = 0;
static bool g_transport_poll_requires_unlocked = false;
static bool g_u2f_adapter_init_ok = true;
static size_t g_u2f_adapter_init_count = 0;
static size_t g_u2f_adapter_deinit_count = 0;
static size_t g_storage_file_alloc_index = 0;
static size_t g_storage_counter_rename_count = 0;
static bool g_storage_root_exists = true;
static bool g_storage_app_data_exists = true;
static char g_last_status_text[160];
static size_t g_status_update_count = 0;
static char g_last_log_text[192];
static char g_log_text[4096];
static size_t g_log_i_count = 0;
#define TEST_STORAGE_MAX_FILE_SIZE 768
typedef struct {
    bool in_use;
    char path[128];
    uint8_t data[TEST_STORAGE_MAX_FILE_SIZE];
    size_t size;
    bool exists;
} TestStorageFile;
static TestStorageFile g_storage_files[8];
static const char *k_repeated_credential_file_name =
    "1010101010101010101010101010101010101010101010101010101010101010";

static void test_furi_log_i(const char *tag, const char *fmt, ...) {
    char line[192];
    size_t used = 0U;
    va_list args;

    UNUSED(tag);
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    snprintf(g_last_log_text, sizeof(g_last_log_text), "%s", line);
    used = strlen(g_log_text);
    if (used < sizeof(g_log_text) - 1U) {
        snprintf(&g_log_text[used], sizeof(g_log_text) - used, "%s%s", used ? "\n" : "", line);
    }
    g_log_i_count++;
}

static bool test_log_contains(const char *needle) {
    return needle && strstr(g_log_text, needle) != NULL;
}

static bool test_storage_copy_basename(const char *path, char *name, size_t name_size) {
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;

    if (strlen(base) >= name_size) {
        return false;
    }

    strncpy(name, base, name_size - 1);
    name[name_size - 1] = '\0';
    return true;
}

static TestStorageFile *test_storage_file_slot(const char *path, bool create) {
    size_t free_index = SIZE_MAX;

    for (size_t i = 0; i < (sizeof(g_storage_files) / sizeof(g_storage_files[0])); ++i) {
        if (g_storage_files[i].in_use && strcmp(g_storage_files[i].path, path) == 0) {
            return &g_storage_files[i];
        }
        if (create && free_index == SIZE_MAX && !g_storage_files[i].in_use) {
            free_index = i;
        }
    }

    if (!create || free_index == SIZE_MAX) {
        return NULL;
    }

    g_storage_files[free_index].in_use = true;
    strncpy(g_storage_files[free_index].path, path, sizeof(g_storage_files[free_index].path) - 1);
    g_storage_files[free_index].path[sizeof(g_storage_files[free_index].path) - 1] = '\0';
    g_storage_files[free_index].size = 0;
    g_storage_files[free_index].exists = false;
    memset(g_storage_files[free_index].data, 0, sizeof(g_storage_files[free_index].data));
    return &g_storage_files[free_index];
}

static uint8_t *test_storage_select_data(const char *path, size_t **size_out, bool **exists_out) {
    TestStorageFile *slot = NULL;

    if (strstr(path, "client_pin") != NULL && strstr(path, ".bak") == NULL &&
        strstr(path, ".tmp") != NULL) {
        *size_out = &g_pin_temp_size;
        *exists_out = &g_pin_temp_exists;
        return g_pin_temp_data;
    }
    if (strstr(path, "client_pin") != NULL && strstr(path, ".bak") == NULL &&
        strstr(path, ".bin") != NULL) {
        *size_out = &g_pin_file_size;
        *exists_out = &g_pin_file_exists;
        return g_pin_file_data;
    }

    slot = test_storage_file_slot(path, true);
    if (!slot) {
        *size_out = NULL;
        *exists_out = NULL;
        return NULL;
    }

    *size_out = &slot->size;
    *exists_out = &slot->exists;
    return slot->data;
}

static void test_storage_reset(void) {
    g_fail_crypto_encrypt = false;
    g_fail_crypto_decrypt = false;
    g_fail_crypto_decrypt_after = SIZE_MAX;
    g_fail_crypto_enclave_load_key = false;
    g_crypto_verify_hash_result = true;
    memset(g_pin_file_data, 0, sizeof(g_pin_file_data));
    g_pin_file_size = 0;
    g_pin_file_exists = false;
    memset(g_pin_temp_data, 0, sizeof(g_pin_temp_data));
    g_pin_temp_size = 0;
    g_pin_temp_exists = false;
    g_remove_attempted_pin_v2_file = false;
    g_remove_attempted_pin_v2_temp = false;
    g_storage_fail_rename_match = NULL;
    g_storage_fail_remove_match = NULL;
    g_storage_fail_copy_match = NULL;
    g_storage_fail_write_match = NULL;
    g_storage_fail_mkdir_match = NULL;
    g_approval_request_count = 0;
    g_approval_request_ok = true;
    g_approval_result = true;
    g_approval_state = ZfApprovalApproved;
    g_attestation_ensure_ready = true;
    g_selection_request_count = 0;
    g_selection_request_ok = true;
    g_selection_index = 0;
    g_last_selection_match_count = 0;
    g_fake_tick = 1000;
    g_transport_poll_status = ZF_CTAP_SUCCESS;
    g_mutex_depth = 0;
    g_transport_poll_requires_unlocked = false;
    g_u2f_adapter_init_ok = true;
    g_u2f_adapter_init_count = 0;
    g_u2f_adapter_deinit_count = 0;
    g_storage_file_alloc_index = 0;
    g_storage_counter_rename_count = 0;
    g_storage_root_exists = true;
    g_storage_app_data_exists = true;
    memset(g_last_status_text, 0, sizeof(g_last_status_text));
    g_status_update_count = 0;
    memset(g_last_log_text, 0, sizeof(g_last_log_text));
    memset(g_log_text, 0, sizeof(g_log_text));
    g_log_i_count = 0;
    memset(g_storage_files, 0, sizeof(g_storage_files));
}

bool file_info_is_dir(const FileInfo *info) {
    UNUSED(info);
    return false;
}

FS_Error storage_common_remove(Storage *storage, const char *path) {
    size_t *size = NULL;
    bool *exists = NULL;

    UNUSED(storage);
    if (strcmp(path, ZF_APP_DATA_DIR "/client_pin_v2.bin") == 0) {
        g_remove_attempted_pin_v2_file = true;
    } else if (strcmp(path, ZF_APP_DATA_DIR "/client_pin_v2.tmp") == 0) {
        g_remove_attempted_pin_v2_temp = true;
    }
    if (g_storage_fail_remove_match && strstr(path, g_storage_fail_remove_match) != NULL) {
        return FSE_NOT_EXIST;
    }
    if (test_storage_select_data(path, &size, &exists) == NULL || !*exists) {
        return FSE_NOT_EXIST;
    }

    *size = 0;
    *exists = false;
    return FSE_OK;
}

FS_Error storage_common_copy(Storage *storage, const char *old_path, const char *new_path) {
    size_t *old_size = NULL;
    size_t *new_size = NULL;
    bool *old_exists = NULL;
    bool *new_exists = NULL;
    uint8_t *old_data = NULL;
    uint8_t *new_data = NULL;

    UNUSED(storage);
    if (g_storage_fail_copy_match && (strstr(old_path, g_storage_fail_copy_match) != NULL ||
                                      strstr(new_path, g_storage_fail_copy_match) != NULL)) {
        return FSE_NOT_EXIST;
    }
    old_data = test_storage_select_data(old_path, &old_size, &old_exists);
    new_data = test_storage_select_data(new_path, &new_size, &new_exists);
    if (old_data == NULL || new_data == NULL || !*old_exists) {
        return FSE_NOT_EXIST;
    }
    memcpy(new_data, old_data, *old_size);
    *new_size = *old_size;
    *new_exists = true;
    return FSE_OK;
}

FS_Error storage_common_rename(Storage *storage, const char *old_path, const char *new_path) {
    FS_Error copy_result = FSE_NOT_EXIST;
    size_t *old_size = NULL;
    bool *old_exists = NULL;
    uint8_t *old_data = NULL;

    if (g_storage_fail_rename_match && (strstr(old_path, g_storage_fail_rename_match) != NULL ||
                                        strstr(new_path, g_storage_fail_rename_match) != NULL)) {
        return FSE_NOT_EXIST;
    }
    old_data = test_storage_select_data(old_path, &old_size, &old_exists);
    if (old_data == NULL || !*old_exists) {
        return FSE_NOT_EXIST;
    }

    if (storage_file_exists(storage, new_path)) {
        storage_common_remove(storage, new_path);
    }
    copy_result = storage_common_copy(storage, old_path, new_path);
    if (copy_result != FSE_OK) {
        return copy_result;
    }
    if (strstr(new_path, ".counter") != NULL) {
        g_storage_counter_rename_count++;
    }

    memset(old_data, 0, *old_size);
    *old_size = 0;
    *old_exists = false;
    return FSE_OK;
}

bool storage_dir_exists(Storage *storage, const char *path) {
    UNUSED(storage);
    if (strcmp(path, ZF_APP_DATA_ROOT) == 0) {
        return g_storage_root_exists;
    }
    if (strcmp(path, ZF_APP_DATA_DIR) == 0) {
        return g_storage_app_data_exists;
    }
    return true;
}

bool storage_simply_mkdir(Storage *storage, const char *path) {
    UNUSED(storage);
    if (g_storage_fail_mkdir_match && strstr(path, g_storage_fail_mkdir_match) != NULL) {
        return false;
    }
    if (strcmp(path, ZF_APP_DATA_ROOT) == 0) {
        g_storage_root_exists = true;
    } else if (strcmp(path, ZF_APP_DATA_DIR) == 0) {
        g_storage_app_data_exists = true;
    }
    return true;
}

bool storage_file_exists(Storage *storage, const char *path) {
    TestStorageFile *slot = NULL;

    UNUSED(storage);
    if (strstr(path, "client_pin") != NULL && strstr(path, ".bak") == NULL &&
        strstr(path, ".tmp") != NULL) {
        return g_pin_temp_exists;
    }
    if (strstr(path, "client_pin") != NULL && strstr(path, ".bak") == NULL &&
        strstr(path, ".bin") != NULL) {
        return g_pin_file_exists;
    }
    slot = test_storage_file_slot(path, false);
    return slot && slot->exists;
}

bool storage_dir_open(File *file, const char *path) {
    if (!storage_dir_exists(NULL, path)) {
        return false;
    }
    memset(file, 0, sizeof(*file));
    strncpy(file->path, path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';
    file->open = true;
    file->offset = 0;
    return true;
}

bool storage_dir_read(File *file, FileInfo *info, char *name, size_t name_size) {
    size_t prefix_len = 0;

    UNUSED(info);
    if (!file || !file->open) {
        return false;
    }

    prefix_len = strlen(file->path);
    for (; file->offset < (sizeof(g_storage_files) / sizeof(g_storage_files[0])); ++file->offset) {
        const TestStorageFile *slot = &g_storage_files[file->offset];
        if (!slot->in_use || !slot->exists) {
            continue;
        }
        if (strncmp(slot->path, file->path, prefix_len) != 0 || slot->path[prefix_len] != '/') {
            continue;
        }
        if (!test_storage_copy_basename(slot->path, name, name_size)) {
            return false;
        }
        file->offset++;
        return true;
    }

    return false;
}

void storage_dir_close(File *file) {
    UNUSED(file);
}

File *storage_file_alloc(Storage *storage) {
    static File files[4];
    File *file = NULL;

    UNUSED(storage);
    file = &files[g_storage_file_alloc_index % (sizeof(files) / sizeof(files[0]))];
    g_storage_file_alloc_index++;
    memset(file, 0, sizeof(*file));
    return file;
}

void storage_file_free(File *file) {
    UNUSED(file);
}

bool storage_file_open(File *file, const char *path, FS_AccessMode access_mode,
                       FS_OpenMode open_mode) {
    size_t *size = NULL;
    bool *exists = NULL;

    if (strncmp(path, ZF_APP_DATA_DIR "/", strlen(ZF_APP_DATA_DIR) + 1) == 0 &&
        !g_storage_app_data_exists) {
        return false;
    }
    if (test_storage_select_data(path, &size, &exists) == NULL) {
        return false;
    }
    if (access_mode == FSAM_READ && (!*exists || open_mode != FSOM_OPEN_EXISTING)) {
        return false;
    }
    if (access_mode == FSAM_WRITE && open_mode == FSOM_CREATE_ALWAYS) {
        *size = 0;
        *exists = true;
    }

    memset(file, 0, sizeof(*file));
    strncpy(file->path, path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';
    file->access_mode = access_mode;
    file->open = true;
    return true;
}

size_t storage_file_size(File *file) {
    size_t *size = NULL;
    bool *exists = NULL;

    if (!file->open || test_storage_select_data(file->path, &size, &exists) == NULL || !*exists) {
        return 0;
    }
    return *size;
}

size_t storage_file_read(File *file, void *buffer, size_t size) {
    size_t *stored_size = NULL;
    bool *exists = NULL;
    uint8_t *data = NULL;
    size_t remaining = 0;

    if (!file->open || file->access_mode != FSAM_READ) {
        return 0;
    }
    data = test_storage_select_data(file->path, &stored_size, &exists);
    if (data == NULL || !*exists || file->offset >= *stored_size) {
        return 0;
    }

    remaining = *stored_size - file->offset;
    if (size > remaining) {
        size = remaining;
    }
    memcpy(buffer, data + file->offset, size);
    file->offset += size;
    return size;
}

size_t storage_file_write(File *file, const void *buffer, size_t size) {
    size_t *stored_size = NULL;
    bool *exists = NULL;
    uint8_t *data = NULL;

    if (!file->open || file->access_mode != FSAM_WRITE) {
        return 0;
    }
    if (g_storage_fail_write_match && strstr(file->path, g_storage_fail_write_match) != NULL) {
        return 0;
    }
    data = test_storage_select_data(file->path, &stored_size, &exists);
    if (data == NULL || (file->offset + size) > TEST_STORAGE_MAX_FILE_SIZE) {
        return 0;
    }

    memcpy(data + file->offset, buffer, size);
    file->offset += size;
    if (file->offset > *stored_size) {
        *stored_size = file->offset;
    }
    *exists = true;
    return size;
}

void storage_file_close(File *file) {
    file->open = false;
}

void *furi_record_open(const char *name) {
    static Storage storage;

    UNUSED(name);
    return &storage;
}

void furi_record_close(const char *name) {
    UNUSED(name);
}

uint32_t furi_hal_rtc_get_timestamp(void) {
    return 1234;
}

void furi_hal_random_fill_buf(void *buffer, size_t size) {
    memset(buffer, 0xA5, size);
}

bool furi_hal_crypto_enclave_ensure_key(uint8_t slot) {
    UNUSED(slot);
    return true;
}

bool furi_hal_crypto_enclave_load_key(uint8_t slot, const uint8_t *iv) {
    UNUSED(slot);
    UNUSED(iv);
    if (g_fail_crypto_enclave_load_key) {
        return false;
    }
    return true;
}

void furi_hal_crypto_enclave_unload_key(uint8_t slot) {
    UNUSED(slot);
}

bool furi_hal_crypto_load_key(const uint8_t *key, const uint8_t *iv) {
    UNUSED(key);
    UNUSED(iv);
    if (g_fail_crypto_enclave_load_key) {
        return false;
    }
    return true;
}

bool furi_hal_crypto_unload_key(void) {
    return true;
}

bool furi_hal_crypto_encrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

bool furi_hal_crypto_decrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

static const uint8_t k_test_aaguid[ZF_AAGUID_LEN] = {
    0xB5, 0x1A, 0x97, 0x6A, 0x0B, 0x02, 0x40, 0xAA, 0x9D, 0x8A, 0x36, 0xC8, 0xB9, 0x1B, 0xBD, 0x1A,
};

const uint8_t *zf_attestation_get_aaguid(void) {
    return k_test_aaguid;
}

const char *zf_attestation_get_aaguid_string(void) {
    return "b51a976a-0b02-40aa-9d8a-36c8b91bbd1a";
}

const uint8_t *zf_attestation_get_leaf_cert_der(size_t *out_len) {
    static const uint8_t cert[] = {0x30, 0x82, 0x00, 0x00};
    *out_len = sizeof(cert);
    return cert;
}

const uint8_t *zf_attestation_get_leaf_private_key(void) {
    static const uint8_t private_key[ZF_PRIVATE_KEY_LEN] = {0};
    return private_key;
}

bool zf_attestation_ensure_ready(void) {
    return g_attestation_ensure_ready;
}

bool zf_attestation_get_leaf_cert_der_len(size_t *out_len) {
    static const uint8_t cert[] = {0x30, 0x82, 0x00, 0x00};
    if (!out_len) {
        return false;
    }
    *out_len = sizeof(cert);
    return true;
}

bool zf_attestation_load_leaf_cert_der(uint8_t *out, size_t out_capacity, size_t *out_len) {
    static const uint8_t cert[] = {0x30, 0x82, 0x00, 0x00};
    if (!out || !out_len || out_capacity < sizeof(cert)) {
        return false;
    }
    memcpy(out, cert, sizeof(cert));
    *out_len = sizeof(cert);
    return true;
}

size_t zf_attestation_get_cert_chain(const uint8_t **certs, size_t *cert_lens, size_t max_certs) {
    static const uint8_t cert[] = {0x30, 0x82, 0x00, 0x00};
    if (max_certs == 0) {
        return 0;
    }
    certs[0] = cert;
    cert_lens[0] = sizeof(cert);
    return 1;
}

bool zf_attestation_sign_input(const uint8_t *input, size_t input_len, uint8_t *out,
                               size_t out_capacity, size_t *out_len) {
    UNUSED(input);
    UNUSED(input_len);
    UNUSED(out_capacity);
    out[0] = 0xAA;
    out[1] = 0x55;
    *out_len = 2;
    return true;
}

bool zf_attestation_sign_parts(const uint8_t *first, size_t first_len, const uint8_t *second,
                               size_t second_len, uint8_t *out, size_t out_capacity,
                               size_t *out_len) {
    UNUSED(first);
    UNUSED(first_len);
    UNUSED(second);
    UNUSED(second_len);
    UNUSED(out_capacity);
    out[0] = 0xAA;
    out[1] = 0x55;
    *out_len = 2;
    return true;
}

bool zf_attestation_validate_consistency(void) {
    return true;
}

void zf_attestation_reset_consistency_cache(void) {}

bool zf_crypto_ensure_store_key(void) {
    return true;
}

void zf_crypto_secure_zero(void *data, size_t size) {
    memset(data, 0, size);
}

void zf_crypto_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
    memset(out, 0, 32);
    for (size_t i = 0; i < size; ++i) {
        out[i % 32] ^= data[i];
    }
}

void zf_crypto_sha256_concat(const uint8_t *first, size_t first_size, const uint8_t *second,
                             size_t second_size, uint8_t out[32]) {
    zf_crypto_sha256(first, first_size, out);
    for (size_t i = 0; i < second_size; ++i) {
        out[i % 32] ^= second[i];
    }
}

bool zf_crypto_hmac_sha256_parts_with_scratch(ZfHmacSha256Scratch *scratch, const uint8_t *key,
                                              size_t key_len, const uint8_t *first,
                                              size_t first_size, const uint8_t *second,
                                              size_t second_size, uint8_t out[32]) {
    UNUSED(scratch);
    if (!key || !out || (first_size > 0U && !first) || (second_size > 0U && !second)) {
        return false;
    }

    zf_crypto_sha256(key, key_len, out);
    for (size_t i = 0; i < first_size; ++i) {
        out[i % 32] ^= first[i];
    }
    for (size_t i = 0; i < second_size; ++i) {
        out[i % 32] ^= second[i];
    }
    return true;
}

bool zf_crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t size,
                           uint8_t out[32]) {
    ZfHmacSha256Scratch scratch;

    return zf_crypto_hmac_sha256_parts_with_scratch(&scratch, key, key_len, data, size, NULL, 0,
                                                    out);
}

bool zf_crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *info, size_t info_len, uint8_t out[32]) {
    UNUSED(salt);
    UNUSED(salt_len);
    uint8_t hmac[32];
    if (!zf_crypto_hmac_sha256(ikm, ikm_len, info, info_len, hmac)) {
        return false;
    }
    memcpy(out, hmac, 32);
    return true;
}

bool zf_crypto_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *input,
                                  uint8_t *output, size_t size) {
    UNUSED(key);
    UNUSED(iv);
    if (g_fail_crypto_encrypt) {
        return false;
    }
    memcpy(output, input, size);
    return true;
}

bool zf_crypto_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *input,
                                  uint8_t *output, size_t size) {
    UNUSED(key);
    UNUSED(iv);
    if (g_fail_crypto_decrypt) {
        return false;
    }
    if (g_fail_crypto_decrypt_after != SIZE_MAX) {
        if (g_fail_crypto_decrypt_after == 0) {
            return false;
        }
        g_fail_crypto_decrypt_after--;
    }
    memcpy(output, input, size);
    return true;
}

bool zf_crypto_aes256_cbc_zero_iv_encrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};
    return zf_crypto_aes256_cbc_encrypt(key, iv, input, output, size);
}

bool zf_crypto_aes256_cbc_zero_iv_decrypt(const uint8_t key[32], const uint8_t *input,
                                          uint8_t *output, size_t size) {
    const uint8_t iv[16] = {0};
    return zf_crypto_aes256_cbc_decrypt(key, iv, input, output, size);
}

bool zf_crypto_generate_key_agreement_key(ZfP256KeyAgreementKey *key) {
    memset(key, 0, sizeof(*key));
    memset(key->private_key, g_key_agreement_seed, sizeof(key->private_key));
    memset(key->public_x, g_key_agreement_seed, sizeof(key->public_x));
    memset(key->public_y, (uint8_t)(g_key_agreement_seed + 1), sizeof(key->public_y));
    g_key_agreement_seed++;
    return true;
}

bool zf_crypto_ecdh_shared_secret(const ZfP256KeyAgreementKey *key,
                                  const uint8_t peer_x[ZF_PUBLIC_KEY_LEN],
                                  const uint8_t peer_y[ZF_PUBLIC_KEY_LEN], uint8_t out[32]) {
    UNUSED(key);
    UNUSED(peer_x);
    UNUSED(peer_y);
    memset(out, 0xAB, 32);
    return true;
}

bool zf_crypto_ecdh_raw_secret(const ZfP256KeyAgreementKey *key,
                               const uint8_t peer_x[ZF_PUBLIC_KEY_LEN],
                               const uint8_t peer_y[ZF_PUBLIC_KEY_LEN], uint8_t out[32]) {
    return zf_crypto_ecdh_shared_secret(key, peer_x, peer_y, out);
}

bool zf_crypto_generate_credential_keypair(ZfCredentialRecord *record) {
    memset(record->public_x, 0x11, sizeof(record->public_x));
    memset(record->public_y, 0x22, sizeof(record->public_y));
    memset(record->private_wrapped, 0x33, sizeof(record->private_wrapped));
    memset(record->private_iv, 0x44, sizeof(record->private_iv));
    return true;
}

bool zf_crypto_compute_public_key_from_private(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                               uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                               uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    UNUSED(private_key);
    memset(public_x, 0x11, ZF_PUBLIC_KEY_LEN);
    memset(public_y, 0x22, ZF_PUBLIC_KEY_LEN);
    return true;
}

bool zf_crypto_sign_hash_with_private_key(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                          const uint8_t hash[32], uint8_t *out, size_t out_capacity,
                                          size_t *out_len) {
    UNUSED(private_key);
    UNUSED(hash);
    UNUSED(out_capacity);
    out[0] = 0x01;
    out[1] = 0x02;
    *out_len = 2;
    return true;
}

bool zf_crypto_verify_hash_with_public_key(const uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t public_y[ZF_PUBLIC_KEY_LEN],
                                           const uint8_t hash[32], const uint8_t *signature,
                                           size_t signature_len) {
    UNUSED(public_x);
    UNUSED(public_y);
    UNUSED(hash);
    UNUSED(signature);
    UNUSED(signature_len);
    return g_crypto_verify_hash_result;
}

bool zf_crypto_sign_hash(const ZfCredentialRecord *record, const uint8_t hash[32], uint8_t *out,
                         size_t out_capacity, size_t *out_len) {
    UNUSED(record);
    UNUSED(hash);
    UNUSED(out_capacity);
    out[0] = 0xDE;
    out[1] = 0xAD;
    out[2] = 0xBE;
    out[3] = 0xEF;
    *out_len = 4;
    return true;
}

bool zf_crypto_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t size) {
    uint8_t diff = 0;
    for (size_t i = 0; i < size; ++i) {
        diff |= left[i] ^ right[i];
    }
    return diff == 0;
}

FlipperFormat *flipper_format_file_alloc(Storage *storage) {
    static FlipperFormat flipper_format;

    UNUSED(storage);
    return &flipper_format;
}

void flipper_format_free(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
}

bool flipper_format_file_open_always(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_open_existing(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_close(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
    return true;
}

bool flipper_format_write_header_cstr(FlipperFormat *flipper_format, const char *type,
                                      uint32_t version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_write_uint32(FlipperFormat *flipper_format, const char *key,
                                 const uint32_t *value, size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_write_hex(FlipperFormat *flipper_format, const char *key, const uint8_t *value,
                              size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

bool flipper_format_read_header(FlipperFormat *flipper_format, FuriString *type,
                                uint32_t *version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_read_uint32(FlipperFormat *flipper_format, const char *key, uint32_t *value,
                                size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_read_hex(FlipperFormat *flipper_format, const char *key, uint8_t *value,
                             size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

FuriString *furi_string_alloc(void) {
    static FuriString string;

    memset(&string, 0, sizeof(string));
    return &string;
}

void furi_string_free(FuriString *string) {
    UNUSED(string);
}

const char *furi_string_get_cstr(const FuriString *string) {
    return string ? string->value : "";
}

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp) {
    memset(grp, 0, sizeof(*grp));
}

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp) {
    UNUSED(grp);
}

int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, int id) {
    UNUSED(grp);
    UNUSED(id);
    return 0;
}

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt) {
    memset(pt, 0, sizeof(*pt));
}

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt) {
    UNUSED(pt);
}

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *r, const mbedtls_mpi *m,
                    const mbedtls_ecp_point *p, int (*f_rng)(), void *p_rng) {
    UNUSED(grp);
    UNUSED(r);
    UNUSED(m);
    UNUSED(p);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp, const mbedtls_mpi *d) {
    UNUSED(grp);
    UNUSED(d);
    return 0;
}

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt) {
    UNUSED(grp);
    UNUSED(pt);
    return 0;
}

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                   int format, size_t *olen, unsigned char *buf, size_t buflen) {
    UNUSED(grp);
    UNUSED(pt);
    UNUSED(format);
    if (buflen > 0) {
        memset(buf, 0, buflen);
        buf[0] = 0x04;
    }
    *olen = buflen;
    return 0;
}

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *q,
                            int (*f_rng)(), void *p_rng) {
    UNUSED(grp);
    UNUSED(d);
    UNUSED(q);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_mpi_read_binary(mbedtls_mpi *x, const unsigned char *buf, size_t buflen) {
    UNUSED(x);
    UNUSED(buf);
    UNUSED(buflen);
    return 0;
}

int mbedtls_mpi_write_binary(const mbedtls_mpi *x, unsigned char *buf, size_t buflen) {
    UNUSED(x);
    memset(buf, 0, buflen);
    return 0;
}

int mbedtls_mpi_lset(mbedtls_mpi *x, int z) {
    UNUSED(x);
    UNUSED(z);
    return 0;
}

void mbedtls_mpi_init(mbedtls_mpi *x) {
    memset(x, 0, sizeof(*x));
}

void mbedtls_mpi_free(mbedtls_mpi *x) {
    UNUSED(x);
}

typedef int FuriStatus;

struct FuriMutex {
    int unused;
};

#define FuriWaitForever 0U
#define FuriStatusOk 0

FuriStatus furi_mutex_acquire(FuriMutex *mutex, uint32_t timeout) {
    UNUSED(mutex);
    UNUSED(timeout);
    g_mutex_depth++;
    return FuriStatusOk;
}

void furi_mutex_release(FuriMutex *mutex) {
    UNUSED(mutex);
    if (g_mutex_depth > 0) {
        g_mutex_depth--;
    }
}

uint32_t furi_get_tick(void) {
    return g_fake_tick;
}

FuriThreadId furi_thread_get_current_id(void) {
    return (FuriThreadId)0x1;
}

uint32_t furi_thread_get_stack_space(FuriThreadId thread_id) {
    UNUSED(thread_id);
    return 4096U;
}

bool zerofido_ui_request_approval(ZerofidoApp *app, ZfUiProtocol protocol, const char *operation,
                                  const char *target_id, const char *user_text,
                                  uint32_t current_cid, bool *approved) {
    UNUSED(protocol);
    UNUSED(operation);
    UNUSED(target_id);
    UNUSED(user_text);
    UNUSED(current_cid);
    if (app &&
        (app->runtime_config.auto_accept_requests || app->transport_auto_accept_transaction)) {
        *approved = true;
        return true;
    }
    g_approval_request_count++;
    *approved = g_approval_result;
    return g_approval_request_ok;
}

bool zerofido_ui_request_assertion_selection(ZerofidoApp *app, const char *rp_id,
                                             const uint16_t *match_indices, size_t match_count,
                                             uint32_t current_cid,
                                             uint32_t *selected_record_index) {
    UNUSED(app);
    UNUSED(rp_id);
    UNUSED(current_cid);
    g_selection_request_count++;
    g_last_selection_match_count = match_count;
    if (!g_selection_request_ok || g_selection_index >= match_count) {
        return false;
    }

    *selected_record_index = match_indices[g_selection_index];
    return true;
}

ZfApprovalState zerofido_ui_get_interaction_state(ZerofidoApp *app) {
    UNUSED(app);
    return g_approval_state;
}

uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, uint32_t current_cid) {
    UNUSED(app);
    UNUSED(current_cid);
    if (g_transport_poll_requires_unlocked && g_mutex_depth != 0) {
        return ZF_CTAP_ERR_OTHER;
    }
    return g_transport_poll_status;
}

void zerofido_notify_success(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_error(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_reset(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *text) {
    UNUSED(app);
    g_status_update_count++;
    if (!text) {
        g_last_status_text[0] = '\0';
        return;
    }
    strncpy(g_last_status_text, text, sizeof(g_last_status_text) - 1);
    g_last_status_text[sizeof(g_last_status_text) - 1] = '\0';
}

bool u2f_data_wipe(Storage *storage) {
    UNUSED(storage);
    return true;
}

bool zf_u2f_adapter_init(ZerofidoApp *app) {
    UNUSED(app);
    g_u2f_adapter_init_count++;
    return g_u2f_adapter_init_ok;
}

void zf_u2f_adapter_deinit(ZerofidoApp *app) {
    UNUSED(app);
    g_u2f_adapter_deinit_count++;
}

#include "../src/zerofido_cbor.c"
#include "../src/ctap/parse/shared.c"
#include "../src/ctap/parse/get_assertion.c"
#include "../src/ctap/parse/make_credential.c"
#include "../src/pin/protocol.c"
#include "../src/ctap/extensions/hmac_secret.c"
#include "../src/ctap/core/approval.c"
#include "../src/ctap/core/assertion_queue.c"
#include "../src/ctap/core/internal.c"
#include "../src/ctap/commands/get_assertion.c"
#include "../src/ctap/commands/make_credential.c"
#include "../src/ctap/commands/reset.c"
#include "../src/ctap/dispatch.c"
#include "../src/ctap/policy.c"
#include "../src/ctap/response.c"
#include "../src/pin/store/state_store.c"
#include "../src/pin/flow.c"
#include "../src/pin/core/token.c"
#include "../src/pin/core/retry.c"
#include "../src/pin/core/plaintext.c"
#include "../src/pin/core/lifecycle.c"
#include "../src/pin/client_pin/parse.c"
#include "../src/pin/client_pin/response.c"
#include "../src/pin/client_pin/operations.c"
#include "../src/pin/command.c"
#include "../src/zerofido_storage.c"
#include "../src/zerofido_runtime_config.c"
#include "../src/store/bootstrap.c"
#include "../src/store/record_format.c"
#include "../src/store/recovery.c"
#include "../src/zerofido_store.c"
#include "../src/zerofido_ui_format.c"
#include "../src/zerofido_ctap_dispatch.c"

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_init_descriptor_list(ZfCredentialDescriptorList *list,
                                      ZfCredentialDescriptor *entries, size_t capacity) {
    list->entries = entries;
    list->count = 0;
    list->capacity = capacity;
}

#define TEST_INIT_GET_ASSERTION_REQUEST(request)                                                   \
    ZfCredentialDescriptor request##_allow_descriptors[ZF_MAX_ALLOW_LIST];                         \
    test_init_descriptor_list(&(request).allow_list, request##_allow_descriptors, ZF_MAX_ALLOW_LIST)

#define TEST_INIT_MAKE_CREDENTIAL_REQUEST(request)                                                 \
    ZfCredentialDescriptor request##_exclude_descriptors[ZF_MAX_ALLOW_LIST];                       \
    test_init_descriptor_list(&(request).exclude_list, request##_exclude_descriptors,              \
                              ZF_MAX_ALLOW_LIST)

static bool test_zf_store_add_record(Storage *storage, ZfCredentialStore *store,
                                     const ZfCredentialRecord *record) {
    uint8_t buffer[ZF_STORE_RECORD_IO_SIZE];

    return zf_store_add_record_with_buffer(storage, store, record, buffer, sizeof(buffer));
}

static bool test_zf_store_init(Storage *storage, ZfCredentialStore *store) {
    uint8_t buffer[ZF_STORE_RECORD_IO_SIZE];

    return zf_store_init_with_buffer(storage, store, buffer, sizeof(buffer));
}

static bool test_zf_store_record_format_load_record(Storage *storage, const char *file_name,
                                                    ZfCredentialRecord *record) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];

    return zf_store_record_format_load_record_with_buffer(storage, file_name, record, buffer,
                                                          sizeof(buffer));
}

static bool test_zf_store_record_format_write_record(Storage *storage,
                                                     const ZfCredentialRecord *record) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];

    return zf_store_record_format_write_record_with_buffer(storage, record, buffer, sizeof(buffer));
}

static void test_command_scratch_is_fixed_lifetime_and_single_owner(void) {
    ZerofidoApp app = {0};
    uint8_t *first = zf_app_command_scratch_acquire(&app, 128);

    expect(first != NULL, "command scratch should acquire fixed arena");
    expect(first == app.command_scratch.bytes, "command scratch should use app-lifetime arena");
    expect(app.command_scratch_in_use, "command scratch should be marked in use");
    memset(first, 0xA5, 128);
    expect(zf_app_command_scratch_acquire(&app, 64) == NULL,
           "command scratch should reject nested acquire");

    zf_app_command_scratch_release(&app);
    expect(app.command_scratch.bytes[0] == 0, "command scratch release should wipe arena");
    expect(!app.command_scratch_in_use, "command scratch release should clear in-use flag");
    expect(app.command_scratch_size == 0, "command scratch release should clear used size");

    uint8_t *second = zf_app_command_scratch_acquire(&app, ZF_COMMAND_SCRATCH_SIZE);
    expect(second == first, "command scratch should reuse fixed arena");
    zf_app_command_scratch_release(&app);
    zf_app_command_scratch_destroy(&app);
    expect(app.command_scratch.bytes[ZF_COMMAND_SCRATCH_SIZE - 1U] == 0,
           "command scratch destroy should wipe full arena");
    expect(!app.command_scratch_in_use, "command scratch destroy should leave arena idle");
}

static bool contains_text(const uint8_t *buffer, size_t size, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > size) {
        return false;
    }

    for (size_t i = 0; i + needle_len <= size; ++i) {
        if (memcmp(buffer + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool cbor_map_contains_uint_key(const uint8_t *buffer, size_t size, uint64_t wanted_key) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint64_t key = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == wanted_key) {
            return true;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool cbor_map_uint_key_bool_value(const uint8_t *buffer, size_t size, uint64_t wanted_key,
                                         bool *value) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint64_t key = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == wanted_key) {
            return zf_cbor_read_bool(&cursor, value);
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static void test_enable_auto_accept_requests(ZerofidoApp *app) {
    zf_runtime_config_load_defaults(&app->runtime_config);
    app->runtime_config.auto_accept_requests = true;
    zf_runtime_config_resolve_capabilities(&app->runtime_config, &app->capabilities);
    app->capabilities_resolved = true;
}

static void test_enable_fido2_1_experimental(ZerofidoApp *app) {
    zf_runtime_config_load_defaults(&app->runtime_config);
    app->runtime_config.fido2_profile = ZfFido2ProfileCtap2_1Experimental;
    app->pin_state.pin_set = true;
    zf_runtime_config_resolve_capabilities(&app->runtime_config, &app->capabilities);
    app->capabilities_resolved = true;
}

static void test_enable_auto_accept_fido2_1_experimental(ZerofidoApp *app) {
    zf_runtime_config_load_defaults(&app->runtime_config);
    app->runtime_config.auto_accept_requests = true;
    app->runtime_config.fido2_profile = ZfFido2ProfileCtap2_1Experimental;
    app->pin_state.pin_set = true;
    zf_runtime_config_resolve_capabilities(&app->runtime_config, &app->capabilities);
    app->capabilities_resolved = true;
}

static bool parse_assertion_response_credential_id(const uint8_t *buffer, size_t size,
                                                   const uint8_t **credential_id,
                                                   size_t *credential_id_len) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint64_t key = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        size_t credential_pairs = 0;
        const uint8_t *field_value = NULL;
        size_t field_value_len = 0;
        const uint8_t *field_name = NULL;
        size_t field_name_len = 0;

        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key != 1) {
            if (!zf_cbor_skip(&cursor)) {
                return false;
            }
            continue;
        }
        if (!zf_cbor_read_map_start(&cursor, &credential_pairs)) {
            return false;
        }
        for (size_t j = 0; j < credential_pairs; ++j) {
            if (!zf_cbor_read_text_ptr(&cursor, &field_name, &field_name_len)) {
                return false;
            }
            if (field_name_len == 2 && memcmp(field_name, "id", 2) == 0) {
                if (!zf_cbor_read_bytes_ptr(&cursor, &field_value, &field_value_len)) {
                    return false;
                }
                *credential_id = field_value;
                *credential_id_len = field_value_len;
                return true;
            }
            if (!zf_cbor_skip(&cursor)) {
                return false;
            }
        }
        return false;
    }

    return false;
}

static bool parse_pin_token_response(const uint8_t *buffer, size_t size, const uint8_t **token,
                                     size_t *token_len) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint64_t key = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs) || pairs != 1) {
        return false;
    }
    if (!zf_cbor_read_uint(&cursor, &key) || key != 2) {
        return false;
    }
    if (!zf_cbor_read_bytes_ptr(&cursor, token, token_len)) {
        return false;
    }

    return cursor.ptr == cursor.end;
}

static bool get_info_has_extension(const uint8_t *buffer, size_t size, const char *expected) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    size_t expected_len = strlen(expected);

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 2) {
            size_t items = 0;
            if (!zf_cbor_read_array_start(&cursor, &items)) {
                return false;
            }
            for (size_t j = 0; j < items; ++j) {
                const uint8_t *extension = NULL;
                size_t extension_len = 0;
                if (!zf_cbor_read_text_ptr(&cursor, &extension, &extension_len)) {
                    return false;
                }
                if (extension_len == expected_len &&
                    memcmp(extension, expected, expected_len) == 0) {
                    return true;
                }
            }
            return false;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool get_info_has_cred_protect_extension(const uint8_t *buffer, size_t size) {
    return get_info_has_extension(buffer, size, "credProtect");
}

static bool get_info_has_version(const uint8_t *buffer, size_t size, const char *version) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    size_t version_len = strlen(version);

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 1) {
            size_t items = 0;
            if (!zf_cbor_read_array_start(&cursor, &items)) {
                return false;
            }
            for (size_t item = 0; item < items; ++item) {
                const uint8_t *value = NULL;
                size_t value_len = 0;
                if (!zf_cbor_read_text_ptr(&cursor, &value, &value_len)) {
                    return false;
                }
                if (value_len == version_len && memcmp(value, version, version_len) == 0) {
                    return true;
                }
            }
            return false;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool get_info_has_uint_field(const uint8_t *buffer, size_t size, uint64_t expected_key,
                                    uint64_t expected_value) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        uint64_t value = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == expected_key) {
            return zf_cbor_read_uint(&cursor, &value) && value == expected_value;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool get_info_has_pin_uv_auth_protocol(const uint8_t *buffer, size_t size,
                                              uint64_t expected_protocol) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 6) {
            size_t items = 0;
            if (!zf_cbor_read_array_start(&cursor, &items)) {
                return false;
            }
            for (size_t item = 0; item < items; ++item) {
                uint64_t protocol = 0;
                if (!zf_cbor_read_uint(&cursor, &protocol)) {
                    return false;
                }
                if (protocol == expected_protocol) {
                    return true;
                }
            }
            return false;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool get_info_pin_uv_auth_protocols_equal(const uint8_t *buffer, size_t size,
                                                 const uint64_t *expected, size_t expected_count) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 6) {
            size_t items = 0;
            if (!zf_cbor_read_array_start(&cursor, &items) || items != expected_count) {
                return false;
            }
            for (size_t item = 0; item < items; ++item) {
                uint64_t protocol = 0;
                if (!zf_cbor_read_uint(&cursor, &protocol) || protocol != expected[item]) {
                    return false;
                }
            }
            return cursor.ptr <= cursor.end;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool get_info_option_bool(const uint8_t *buffer, size_t size, const char *option,
                                 bool *value) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    size_t option_len = strlen(option);

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 4) {
            size_t option_pairs = 0;
            if (!zf_cbor_read_map_start(&cursor, &option_pairs)) {
                return false;
            }
            for (size_t option_index = 0; option_index < option_pairs; ++option_index) {
                const uint8_t *name = NULL;
                size_t name_len = 0;
                if (!zf_cbor_read_text_ptr(&cursor, &name, &name_len)) {
                    return false;
                }
                if (name_len == option_len && memcmp(name, option, option_len) == 0) {
                    return zf_cbor_read_bool(&cursor, value);
                }
                if (!zf_cbor_skip(&cursor)) {
                    return false;
                }
            }
            return false;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool parse_make_credential_cred_protect_output(const uint8_t *buffer, size_t size,
                                                      uint8_t *cred_protect) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    size_t offset = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 2) {
            if (!zf_cbor_read_bytes_ptr(&cursor, &auth_data, &auth_data_len)) {
                return false;
            }
            break;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    if (!auth_data || auth_data_len < 55 || (auth_data[32] & 0xC0U) != 0xC0U) {
        return false;
    }

    offset = 55 + (((size_t)auth_data[53] << 8) | auth_data[54]);
    if (offset >= auth_data_len) {
        return false;
    }

    zf_cbor_cursor_init(&cursor, auth_data + offset, auth_data_len - offset);
    if (!zf_cbor_skip(&cursor)) {
        return false;
    }
    if (!zf_cbor_read_map_start(&cursor, &pairs) || pairs != 1) {
        return false;
    }

    const uint8_t *name = NULL;
    size_t name_len = 0;
    uint64_t raw = 0;
    if (!zf_cbor_read_text_ptr(&cursor, &name, &name_len) ||
        zf_ctap_classify_text_key(name, name_len) != ZfCtapTextKeyCredProtect ||
        !zf_cbor_read_uint(&cursor, &raw) || raw > UINT8_MAX || cursor.ptr != cursor.end) {
        return false;
    }

    *cred_protect = (uint8_t)raw;
    return true;
}

static bool parse_make_credential_hmac_secret_output(const uint8_t *buffer, size_t size,
                                                     bool *hmac_secret) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    size_t offset = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 2) {
            if (!zf_cbor_read_bytes_ptr(&cursor, &auth_data, &auth_data_len)) {
                return false;
            }
            break;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    if (!auth_data || auth_data_len < 55 || (auth_data[32] & 0xC0U) != 0xC0U) {
        return false;
    }

    offset = 55 + (((size_t)auth_data[53] << 8) | auth_data[54]);
    if (offset >= auth_data_len) {
        return false;
    }

    zf_cbor_cursor_init(&cursor, auth_data + offset, auth_data_len - offset);
    if (!zf_cbor_skip(&cursor) || !zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        const uint8_t *name = NULL;
        size_t name_len = 0;
        if (!zf_cbor_read_text_ptr(&cursor, &name, &name_len)) {
            return false;
        }
        if (zf_ctap_classify_text_key(name, name_len) == ZfCtapTextKeyHmacSecret) {
            return zf_cbor_read_bool(&cursor, hmac_secret);
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool parse_hmac_secret_extension_output(const uint8_t *buffer, size_t size,
                                               const uint8_t **hmac_secret_enc,
                                               size_t *hmac_secret_enc_len) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }
    for (size_t i = 0; i < pairs; ++i) {
        const uint8_t *name = NULL;
        size_t name_len = 0;
        if (!zf_cbor_read_text_ptr(&cursor, &name, &name_len)) {
            return false;
        }
        if (zf_ctap_classify_text_key(name, name_len) == ZfCtapTextKeyHmacSecret) {
            return zf_cbor_read_bytes_ptr(&cursor, hmac_secret_enc, hmac_secret_enc_len) &&
                   cursor.ptr == cursor.end;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return false;
}

static bool parse_assertion_response_hmac_secret_output(const uint8_t *buffer, size_t size,
                                                        const uint8_t **hmac_secret_enc,
                                                        size_t *hmac_secret_enc_len) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 2) {
            if (!zf_cbor_read_bytes_ptr(&cursor, &auth_data, &auth_data_len)) {
                return false;
            }
            break;
        }
        if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    if (!auth_data || auth_data_len <= 37U || (auth_data[32] & 0x80U) == 0) {
        return false;
    }

    return parse_hmac_secret_extension_output(auth_data + 37U, auth_data_len - 37U, hmac_secret_enc,
                                              hmac_secret_enc_len);
}

static bool parse_make_credential_auth_flags(const uint8_t *buffer, size_t size, uint8_t *flags) {
    ZfCborCursor cursor;
    size_t pairs = 0;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        const uint8_t *auth_data = NULL;
        size_t auth_data_len = 0;

        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key != 2) {
            if (!zf_cbor_skip(&cursor)) {
                return false;
            }
            continue;
        }

        if (!zf_cbor_read_bytes_ptr(&cursor, &auth_data, &auth_data_len) || auth_data_len < 37U) {
            return false;
        }
        *flags = auth_data[32];
        return true;
    }

    return false;
}

static bool parse_make_credential_packed_attestation(const uint8_t *buffer, size_t size) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    bool saw_fmt = false;
    bool saw_x5c = false;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;

        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 1) {
            const uint8_t *fmt = NULL;
            size_t fmt_len = 0;
            if (!zf_cbor_read_text_ptr(&cursor, &fmt, &fmt_len) || fmt_len != 6 ||
                memcmp(fmt, "packed", 6) != 0) {
                return false;
            }
            saw_fmt = true;
        } else if (key == 3) {
            size_t att_stmt_pairs = 0;
            if (!zf_cbor_read_map_start(&cursor, &att_stmt_pairs)) {
                return false;
            }
            for (size_t j = 0; j < att_stmt_pairs; ++j) {
                const uint8_t *att_key = NULL;
                size_t att_key_len = 0;
                if (!zf_cbor_read_text_ptr(&cursor, &att_key, &att_key_len)) {
                    return false;
                }
                if (att_key_len == 3 && memcmp(att_key, "x5c", 3) == 0) {
                    size_t cert_count = 0;
                    const uint8_t *cert = NULL;
                    size_t cert_len = 0;
                    if (!zf_cbor_read_array_start(&cursor, &cert_count) || cert_count != 1 ||
                        !zf_cbor_read_bytes_ptr(&cursor, &cert, &cert_len) || cert_len == 0) {
                        return false;
                    }
                    saw_x5c = true;
                } else if (!zf_cbor_skip(&cursor)) {
                    return false;
                }
            }
        } else if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return saw_fmt && saw_x5c && cursor.ptr == cursor.end;
}

static bool parse_make_credential_none_attestation(const uint8_t *buffer, size_t size) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    bool saw_fmt = false;
    bool saw_empty_att_stmt = false;

    zf_cbor_cursor_init(&cursor, buffer, size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;

        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (key == 1) {
            const uint8_t *fmt = NULL;
            size_t fmt_len = 0;
            if (!zf_cbor_read_text_ptr(&cursor, &fmt, &fmt_len) || fmt_len != 4 ||
                memcmp(fmt, "none", 4) != 0) {
                return false;
            }
            saw_fmt = true;
        } else if (key == 3) {
            size_t att_stmt_pairs = 1;
            if (!zf_cbor_read_map_start(&cursor, &att_stmt_pairs) || att_stmt_pairs != 0) {
                return false;
            }
            saw_empty_att_stmt = true;
        } else if (!zf_cbor_skip(&cursor)) {
            return false;
        }
    }

    return saw_fmt && saw_empty_att_stmt && cursor.ptr == cursor.end;
}

static void mark_pin_token_issued(ZfClientPinState *state) {
    state->pin_token_active = true;
    state->pin_token_issued_at = g_fake_tick;
}

static size_t encode_complete_record(uint8_t *buffer, size_t capacity) {
    ZfCredentialRecord record = {0};
    size_t encoded_size = 0;

    memset(record.credential_id, 0x10, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    strcpy(record.file_name, k_repeated_credential_file_name);
    strcpy(record.rp_id, "example.com");
    memcpy(record.user_id, "user-1", 6);
    record.user_id_len = 6;
    strcpy(record.user_name, "alice");
    strcpy(record.user_display_name, "Alice Example");
    memset(record.public_x, 0x21, sizeof(record.public_x));
    memset(record.public_y, 0x22, sizeof(record.public_y));
    memset(record.private_wrapped, 0x23, sizeof(record.private_wrapped));
    memset(record.private_iv, 0x24, sizeof(record.private_iv));
    record.sign_count = 7;
    record.created_at = 1234;
    record.resident_key = true;

    expect(zf_store_record_format_encode(&record, buffer, &encoded_size), "encode complete record");
    expect(encoded_size <= capacity, "encoded record fits");
    return encoded_size;
}

static void fill_large_resident_hmac_secret_record(ZfCredentialRecord *record) {
    memset(record, 0, sizeof(*record));
    memset(record->credential_id, 0x10, sizeof(record->credential_id));
    record->credential_id_len = sizeof(record->credential_id);
    strcpy(record->file_name, k_repeated_credential_file_name);
    memset(record->rp_id, 'r', 253);
    record->rp_id[253] = '\0';
    memset(record->user_id, 0xA5, sizeof(record->user_id));
    record->user_id_len = sizeof(record->user_id);
    memset(record->user_name, 'n', ZF_MAX_USER_NAME_LEN - 1U);
    record->user_name[ZF_MAX_USER_NAME_LEN - 1U] = '\0';
    memset(record->user_display_name, 'd', ZF_MAX_DISPLAY_NAME_LEN - 1U);
    record->user_display_name[ZF_MAX_DISPLAY_NAME_LEN - 1U] = '\0';
    memset(record->public_x, 0x21, sizeof(record->public_x));
    memset(record->public_y, 0x22, sizeof(record->public_y));
    memset(record->private_wrapped, 0x23, sizeof(record->private_wrapped));
    memset(record->private_iv, 0x24, sizeof(record->private_iv));
    record->sign_count = UINT32_MAX - 1U;
    record->created_at = UINT32_MAX - 2U;
    record->resident_key = true;
    record->cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL;
    record->hmac_secret = true;
    memset(record->hmac_secret_without_uv, 0x55, sizeof(record->hmac_secret_without_uv));
    memset(record->hmac_secret_with_uv, 0x66, sizeof(record->hmac_secret_with_uv));
    record->in_use = true;
}

static void test_record_decode_rejects_partial_record(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfCredentialRecord record;

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init partial record encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 3) &&
               zf_cbor_encode_text(&enc, "example.com"),
           "encode partial record");

    expect(!zf_record_decode(buffer, zf_cbor_encoder_size(&enc), k_repeated_credential_file_name,
                             &record),
           "partial record should be rejected");
}

static void test_record_decode_accepts_complete_record(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record;
    size_t size = encode_complete_record(buffer, sizeof(buffer));

    expect(zf_record_decode(buffer, size, k_repeated_credential_file_name, &record),
           "complete record should decode");
    expect(record.in_use, "decoded record should be marked in use");
    expect(record.resident_key, "decoded record should preserve resident key");
    expect(strcmp(record.rp_id, "example.com") == 0, "decoded rp id");
}

static void test_record_encode_accepts_large_resident_record_with_hmac_secret(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record = {0};
    size_t encoded_size = 0;

    fill_large_resident_hmac_secret_record(&record);

    expect(zf_store_record_format_encode(&record, buffer, &encoded_size),
           "large resident hmac-secret record should encode");
    expect(encoded_size <= sizeof(buffer), "large resident hmac-secret record should fit buffer");
}

static void test_record_decode_rejects_embedded_nul_text(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCborEncoder enc;
    ZfCredentialRecord record = {0};
    static const char rp_id_with_nul[] = {'e', 'x',  'a', 'm', 'p', 'l',
                                          'e', '\0', '.', 'c', 'o', 'm'};

    memset(record.credential_id, 0x10, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    memcpy(record.user_id, "user-1", 6);
    record.user_id_len = 6;
    strcpy(record.user_name, "alice");
    strcpy(record.user_display_name, "Alice Example");
    memset(record.public_x, 0x21, sizeof(record.public_x));
    memset(record.public_y, 0x22, sizeof(record.public_y));
    memset(record.private_wrapped, 0x23, sizeof(record.private_wrapped));
    memset(record.private_iv, 0x24, sizeof(record.private_iv));
    record.sign_count = 7;
    record.created_at = 1234;
    record.resident_key = true;

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init embedded nul record encoder");
    expect(zf_cbor_encode_map(&enc, 13) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, record.credential_id, record.credential_id_len) &&
               zf_cbor_encode_uint(&enc, 3) &&
               zf_cbor_encode_text_n(&enc, rp_id_with_nul, sizeof(rp_id_with_nul)) &&
               zf_cbor_encode_uint(&enc, 4) &&
               zf_cbor_encode_bytes(&enc, record.user_id, record.user_id_len) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_text(&enc, record.user_name) &&
               zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_text(&enc, record.user_display_name) &&
               zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_bytes(&enc, record.public_x, sizeof(record.public_x)) &&
               zf_cbor_encode_uint(&enc, 8) &&
               zf_cbor_encode_bytes(&enc, record.public_y, sizeof(record.public_y)) &&
               zf_cbor_encode_uint(&enc, 9) &&
               zf_cbor_encode_bytes(&enc, record.private_wrapped, sizeof(record.private_wrapped)) &&
               zf_cbor_encode_uint(&enc, 10) &&
               zf_cbor_encode_bytes(&enc, record.private_iv, sizeof(record.private_iv)) &&
               zf_cbor_encode_uint(&enc, 11) && zf_cbor_encode_uint(&enc, record.sign_count) &&
               zf_cbor_encode_uint(&enc, 12) && zf_cbor_encode_uint(&enc, record.created_at) &&
               zf_cbor_encode_uint(&enc, 13) && zf_cbor_encode_bool(&enc, record.resident_key),
           "encode embedded nul record");

    expect(!zf_record_decode(buffer, zf_cbor_encoder_size(&enc),
                             "1010101010101010101010101010101010101010101010101010101010101010",
                             &record),
           "record with embedded nul text should be rejected");
}

static void test_record_decode_rejects_file_name_mismatch(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record;
    size_t size = encode_complete_record(buffer, sizeof(buffer));

    expect(!zf_record_decode(buffer, size,
                             "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                             &record),
           "record should reject mismatched file name");
}

static size_t encode_complete_record_with_version(uint8_t *buffer, size_t capacity,
                                                  uint64_t version) {
    ZfCredentialRecord record = {0};
    ZfCborEncoder enc;

    memset(record.credential_id, 0x10, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    strcpy(record.file_name, k_repeated_credential_file_name);
    strcpy(record.rp_id, "example.com");
    memcpy(record.user_id, "user-1", 6);
    record.user_id_len = 6;
    strcpy(record.user_name, "alice");
    strcpy(record.user_display_name, "Alice Example");
    memset(record.public_x, 0x21, sizeof(record.public_x));
    memset(record.public_y, 0x22, sizeof(record.public_y));
    memset(record.private_wrapped, 0x23, sizeof(record.private_wrapped));
    memset(record.private_iv, 0x24, sizeof(record.private_iv));
    record.sign_count = 7;
    record.created_at = 1234;
    record.resident_key = true;

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init versioned record encoder");
    expect(zf_cbor_encode_map(&enc, 13) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_uint(&enc, version) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, record.credential_id, record.credential_id_len) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_text(&enc, record.rp_id) &&
               zf_cbor_encode_uint(&enc, 4) &&
               zf_cbor_encode_bytes(&enc, record.user_id, record.user_id_len) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_text(&enc, record.user_name) &&
               zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_text(&enc, record.user_display_name) &&
               zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_bytes(&enc, record.public_x, sizeof(record.public_x)) &&
               zf_cbor_encode_uint(&enc, 8) &&
               zf_cbor_encode_bytes(&enc, record.public_y, sizeof(record.public_y)) &&
               zf_cbor_encode_uint(&enc, 9) &&
               zf_cbor_encode_bytes(&enc, record.private_wrapped, sizeof(record.private_wrapped)) &&
               zf_cbor_encode_uint(&enc, 10) &&
               zf_cbor_encode_bytes(&enc, record.private_iv, sizeof(record.private_iv)) &&
               zf_cbor_encode_uint(&enc, 11) && zf_cbor_encode_uint(&enc, record.sign_count) &&
               zf_cbor_encode_uint(&enc, 12) && zf_cbor_encode_uint(&enc, record.created_at) &&
               zf_cbor_encode_uint(&enc, 13) && zf_cbor_encode_bool(&enc, record.resident_key),
           "encode record with custom version");
    return zf_cbor_encoder_size(&enc);
}

static void test_record_decode_rejects_oversized_version(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record;
    size_t size = encode_complete_record_with_version(buffer, sizeof(buffer), 4294967298ULL);

    expect(!zf_record_decode(buffer, size, k_repeated_credential_file_name, &record),
           "oversized version should be rejected");
}

static void test_record_decode_rejects_unsupported_record_version(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    ZfCredentialRecord record;
    size_t size = encode_complete_record(buffer, sizeof(buffer));

    expect(buffer[1] == 0x01 && buffer[2] == ZF_STORE_FORMAT_VERSION,
           "stored record version field should be at the expected prefix");
    buffer[2] = 0x00;

    expect(!zf_record_decode(buffer, size, k_repeated_credential_file_name, &record),
           "unsupported stored record versions should be rejected");
}

static void test_store_init_ignores_unsupported_record_file(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    store.records = store_records;
    TestStorageFile *slot = NULL;
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t size = encode_complete_record(buffer, sizeof(buffer));
    char path[160];

    test_storage_reset();
    expect(buffer[1] == 0x01 && buffer[2] == ZF_STORE_FORMAT_VERSION,
           "stored record version field should be at the expected prefix");
    buffer[2] = 0x00;

    snprintf(path, sizeof(path), "%s/%s", ZF_APP_DATA_DIR, k_repeated_credential_file_name);
    slot = test_storage_file_slot(path, true);
    expect(slot != NULL, "allocate storage slot for unsupported-version record");
    memcpy(slot->data, buffer, size);
    slot->size = size;
    slot->exists = true;

    expect(test_zf_store_init(&storage, &store),
           "store init should succeed with unsupported-version record present");
    expect(store.count == 0, "store init should ignore unsupported-version record files");
    expect(slot->exists, "store init should not rewrite unsupported-version record files");
}

static void test_cbor_text_read_rejects_declared_length_past_buffer(void) {
    static const uint8_t malformed[] = {0x7B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ZfCborCursor cursor;
    const uint8_t *text = NULL;
    size_t text_len = 0;

    zf_cbor_cursor_init(&cursor, malformed, sizeof(malformed));
    expect(!zf_cbor_read_text_ptr(&cursor, &text, &text_len),
           "text read should reject a declared length that exceeds the buffer");
}

static void test_cbor_skip_rejects_declared_length_past_buffer(void) {
    static const uint8_t malformed[] = {0x5A, 0xFF, 0xFF, 0xFF, 0xFF};
    ZfCborCursor cursor;

    zf_cbor_cursor_init(&cursor, malformed, sizeof(malformed));
    expect(!zf_cbor_skip(&cursor), "skip should reject a declared length that exceeds the buffer");
}

static void test_cbor_skip_accepts_single_precision_float(void) {
    static const uint8_t encoded[] = {0xFA, 0x3F, 0x80, 0x00, 0x00};
    ZfCborCursor cursor;

    zf_cbor_cursor_init(&cursor, encoded, sizeof(encoded));
    expect(zf_cbor_skip(&cursor), "skip should consume payload-carrying simple values");
    expect(cursor.ptr == cursor.end, "skip should consume the full float payload");
}

static void test_cbor_read_uint_rejects_noncanonical_encoding(void) {
    static const uint8_t malformed[] = {0x18, 0x17};
    ZfCborCursor cursor;
    uint64_t value = 0;

    zf_cbor_cursor_init(&cursor, malformed, sizeof(malformed));
    expect(!zf_cbor_read_uint(&cursor, &value),
           "uint read should reject non-canonical one-byte encodings");
}

static void test_cbor_read_text_rejects_noncanonical_length(void) {
    static const uint8_t malformed[] = {
        0x78, 0x17, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'a',  'a',  'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
    };
    ZfCborCursor cursor;
    const uint8_t *text = NULL;
    size_t text_len = 0;

    zf_cbor_cursor_init(&cursor, malformed, sizeof(malformed));
    expect(!zf_cbor_read_text_ptr(&cursor, &text, &text_len),
           "text read should reject non-canonical length encodings");
}

static void test_get_assertion_parse_treats_empty_allow_list_as_omitted(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init getAssertion encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 0),
           "encode getAssertion request with empty allow list");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "empty allow list should be accepted");
    expect(!zf_ctap_request_uses_allow_list(&request),
           "empty allow list should be treated as omitted");
}

static void test_get_assertion_parse_skips_unknown_float_member(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t float32_one[] = {0xFA, 0x3F, 0x80, 0x00, 0x00};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init float extension encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 99),
           "encode getAssertion request with unknown float key");
    expect(enc.offset + sizeof(float32_one) <= enc.capacity, "float extension should fit");
    memcpy(enc.buf + enc.offset, float32_one, sizeof(float32_one));
    enc.offset += sizeof(float32_one);

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "unknown float-valued members should be skipped cleanly");
    expect(strcmp(request.assertion.rp_id, "example.com") == 0,
           "parser should preserve required fields");
}

static void test_get_assertion_parse_rejects_duplicate_top_level_key(void) {
    uint8_t buffer[160];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate getAssertion encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "duplicate.example") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode getAssertion request with duplicate top-level key");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "duplicate getAssertion top-level keys should be rejected");
}

static void test_get_assertion_parse_rejects_duplicate_option_key(void) {
    uint8_t buffer[160];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init duplicate options encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "up") && zf_cbor_encode_bool(&enc, true) &&
               zf_cbor_encode_text(&enc, "up") && zf_cbor_encode_bool(&enc, false),
           "encode getAssertion request with duplicate option key");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "duplicate options keys should be rejected");
}

static void test_get_assertion_parse_ignores_unknown_true_option(void) {
    uint8_t buffer[160];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init unknown true option encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "unknownOption") && zf_cbor_encode_bool(&enc, true),
           "encode getAssertion request with unknown true option");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "unknown true options should be ignored");
}

static void test_get_assertion_parse_ignores_unknown_false_option(void) {
    uint8_t buffer[160];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init unknown false option encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "unknownOption") && zf_cbor_encode_bool(&enc, false),
           "encode getAssertion request with unknown false option");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "unknown false options should be ignored");
}

static void test_get_assertion_parse_rejects_zero_length_descriptor_id(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init zero-length descriptor encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, (const uint8_t *)"", 0) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode zero-length descriptor id");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "zero-length descriptor id should be rejected");
}

static void test_get_assertion_parse_accepts_oversized_descriptor_id(void) {
    uint8_t buffer[512];
    uint8_t oversized_id[ZF_CREDENTIAL_ID_LEN + 1];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    memset(oversized_id, 0xAB, sizeof(oversized_id));
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init oversized descriptor encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, oversized_id, sizeof(oversized_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode oversized descriptor id");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "oversized descriptor id should be accepted");
    expect(request.allow_list.count == 1, "oversized descriptor id should be counted");
    expect(zf_ctap_request_uses_allow_list(&request),
           "oversized public-key descriptor should still make an allow-list request");
    expect(!zf_ctap_descriptor_list_contains_id(&request.allow_list, oversized_id,
                                                ZF_CREDENTIAL_ID_LEN),
           "oversized descriptor id should not match by truncated bytes");
}

static void test_get_assertion_parse_rejects_duplicate_descriptor_type_after_invalid_value(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t credential_id[16] = {0xAB};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate descriptor type encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "bogus") &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode getAssertion request with rescuable duplicate descriptor type");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "duplicate descriptor type should be rejected even if a later value is valid");
}

static void test_get_assertion_parse_rejects_embedded_nul_rp_id(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const char rp_id_with_nul[] = {'e', 'x', 'a', 'm', 'p',  'l', 'e',
                                          '.', 'c', 'o', 'm', '\0', 'x'};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init nul rpId encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text_n(&enc, rp_id_with_nul, sizeof(rp_id_with_nul)) &&
               zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode getAssertion request with embedded nul rpId");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "embedded nul rpId should be rejected");
}

static void test_get_assertion_parse_rejects_invalid_utf8_rp_id(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t invalid_utf8[] = {0xC3, 0x28};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init invalid utf8 rpId encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, invalid_utf8, sizeof(invalid_utf8)) &&
               zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode getAssertion request with invalid utf8 rpId");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "invalid utf8 rpId should be rejected");
}

static void test_get_assertion_parse_accepts_rk_false_option(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init rk option encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "rk") && zf_cbor_encode_bool(&enc, false),
           "encode getAssertion request with rk option");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "GetAssertion rk=false option should be ignored");
}

static void test_get_assertion_parse_rejects_rk_true_option_with_unsupported_option(void) {
    uint8_t buffer[128];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init rk=true option encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "rk") && zf_cbor_encode_bool(&enc, true),
           "encode getAssertion request with rk=true option");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_UNSUPPORTED_OPTION,
           "GetAssertion rk=true option should be rejected as unsupported option");
}

static void test_make_credential_parse_skips_unknown_simple_value(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init makeCredential encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 99) &&
               zf_cbor_encode_bool(&enc, true),
           "encode makeCredential request with unknown bool");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "unknown simple value should be skipped");
}

static void test_make_credential_parse_ignores_unknown_true_option(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init makeCredential unknown option encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "makeTea") &&
               zf_cbor_encode_bool(&enc, true),
           "encode makeCredential request with unknown true option");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "unknown true options should be ignored");
    expect(!request.has_up && !request.has_uv && !request.has_rk,
           "unknown option should not set any known option flags");
}

static void test_make_credential_parse_rejects_duplicate_user_name(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init duplicate user-name encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 3) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "mallory") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with duplicate user name");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "duplicate user-name keys should be rejected");
}

static void test_make_credential_parse_accepts_64_byte_display_name(void) {
    uint8_t buffer[512];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};
    static const char display_name[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    expect(sizeof(display_name) - 1 == 64, "displayName fixture should be exactly 64 bytes");
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init exact-64-byte displayName encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "displayName") &&
               zf_cbor_encode_text_n(&enc, display_name, sizeof(display_name) - 1) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with exact-64-byte displayName");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "exact-64-byte displayName should be accepted");
    expect(strcmp(request.user_display_name, display_name) == 0,
           "exact-64-byte displayName should round-trip");
}

static void test_make_credential_parse_rejects_non_text_rp_name(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init non-text rp.name encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with non-text rp.name");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "non-text rp.name should be rejected");
}

static void test_make_credential_parse_rejects_non_text_rp_icon(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init non-text rp.icon encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_text(&enc, "icon") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with non-text rp.icon");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "non-text rp.icon should be rejected");
}

static void test_make_credential_parse_rejects_non_text_user_icon(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init non-text user.icon encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "icon") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with non-text user.icon");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "non-text user.icon should be rejected");
}

static void test_get_assertion_parse_accepts_253_byte_rp_id(void) {
    uint8_t buffer[512];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const char rp_id[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
                                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
                                "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
                                "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    expect(sizeof(rp_id) - 1 == 253, "rpId fixture should be exactly 253 bytes");
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init long rpId encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text_n(&enc, rp_id, sizeof(rp_id) - 1) &&
               zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode getAssertion request with 253-byte rpId");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "253-byte rpId should be accepted");
    expect(strcmp(request.assertion.rp_id, rp_id) == 0, "253-byte rpId should round-trip");
}

static void test_make_credential_parse_rejects_duplicate_exclude_descriptors(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0x01};
    static const uint8_t credential_id[] = {0xAA, 0xBB, 0xCC, 0xDD};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate makeCredential excludeList encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_array(&enc, 2) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode makeCredential request with duplicate excludeList descriptors");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_PARAMETER,
           "duplicate excludeList descriptors should be rejected");
}

static void test_get_assertion_parse_rejects_duplicate_allow_list_descriptors(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t credential_id[] = {0xAA, 0xBB, 0xCC, 0xDD};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate getAssertion allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 2) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode getAssertion request with duplicate allowList descriptors");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_PARAMETER,
           "duplicate allowList descriptors should be rejected");
}

static void test_get_assertion_parse_rejects_too_many_allow_list_descriptors(void) {
    uint8_t buffer[1024];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init oversized getAssertion allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, ZF_MAX_ALLOW_LIST + 1U),
           "encode oversized getAssertion allowList header");
    for (size_t i = 0; i <= ZF_MAX_ALLOW_LIST; ++i) {
        uint8_t credential_id[] = {(uint8_t)(i + 1U)};
        expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
                   zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
                   zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
               "encode allowList descriptor");
    }

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_PARAMETER,
           "too many effective allowList descriptors should be rejected");
}

static void test_get_assertion_parse_rejects_duplicate_oversized_allow_list_descriptors(void) {
    uint8_t buffer[512];
    uint8_t oversized_id[ZF_CREDENTIAL_ID_LEN + 1];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    memset(oversized_id, 0xBC, sizeof(oversized_id));
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate oversized allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 2) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, oversized_id, sizeof(oversized_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, oversized_id, sizeof(oversized_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode duplicate oversized allowList descriptors");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_PARAMETER,
           "duplicate oversized allowList descriptors should be rejected during insertion");
}

static void test_assertion_response_user_fields_follow_uv(void) {
    ZfGetAssertionRequest request = {0};
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    ZfCredentialRecord record = {0};
    ZfAssertionResponseScratch scratch = {0};
    uint8_t response[256];
    size_t response_len = 0;

    strcpy(request.assertion.rp_id, "example.com");
    memset(request.assertion.client_data_hash, 0x5A, sizeof(request.assertion.client_data_hash));
    memset(record.credential_id, 0x10, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    memcpy(record.user_id, "user-1", 6);
    record.user_id_len = 6;
    strcpy(record.user_name, "alice");
    strcpy(record.user_display_name, "Alice Example");

    expect(zf_ctap_build_assertion_response_with_scratch(
               &scratch, &request.assertion, &record, true, true, 8, true, true, 2, false, false,
               NULL, 0, response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "uv assertion response should build");
    expect(contains_text(response, response_len, "name"), "uv response should include name key");
    expect(contains_text(response, response_len, "displayName"),
           "uv response should include displayName key");
    expect(contains_text(response, response_len, "alice"), "uv response should include user name");
    expect(contains_text(response, response_len, "Alice Example"),
           "uv response should include display name value");

    expect(zf_ctap_build_assertion_response_with_scratch(
               &scratch, &request.assertion, &record, true, false, 9, false, false, 1, false, false,
               NULL, 0, response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "non-uv assertion response should build");
    expect(!contains_text(response, response_len, "displayName"),
           "non-uv response omits displayName");
    expect(!contains_text(response, response_len, "alice"), "non-uv response omits user name");
}

static void test_client_pin_parse_rejects_trailing_bytes(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[16];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCborEncoder enc;

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init clientPin retries encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, 1),
           "encode clientPin getRetries request");
    buffer[zf_cbor_encoder_size(&enc)] = 0xFF;

    expect(zerofido_pin_handle_command(&app, buffer, zf_cbor_encoder_size(&enc) + 1, response,
                                       sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_CBOR,
           "clientPin request should reject trailing bytes");
}

static void test_client_pin_get_retries_accepts_missing_pin_protocol(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[16];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCborEncoder enc;
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint64_t key = 0;
    uint64_t retries = 0;

    test_storage_reset();
    app.pin_state.pin_retries = 7;

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init clientPin getRetries encoder");
    expect(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, ZF_CLIENT_PIN_SUBCMD_GET_RETRIES),
           "encode clientPin getRetries without pinProtocol");

    expect(zerofido_pin_handle_command(&app, buffer, zf_cbor_encoder_size(&enc), response,
                                       sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "clientPin getRetries should not require pinProtocol");
    zf_cbor_cursor_init(&cursor, response, response_len);
    expect(zf_cbor_read_map_start(&cursor, &pairs) && pairs == 1, "decode retries response map");
    expect(zf_cbor_read_uint(&cursor, &key) && key == 3, "decode retries response key");
    expect(zf_cbor_read_uint(&cursor, &retries) && retries == 7, "decode retries value");
    expect(cursor.ptr == cursor.end, "retries response should not have trailing bytes");
}

static void test_client_pin_get_key_agreement_requires_pin_protocol(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[16];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCborEncoder enc;

    test_storage_reset();
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init clientPin getKeyAgreement missing protocol encoder");
    expect(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT),
           "encode clientPin getKeyAgreement without pinProtocol");

    expect(zerofido_pin_handle_command(&app, buffer, zf_cbor_encoder_size(&enc), response,
                                       sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_MISSING_PARAMETER,
           "clientPin getKeyAgreement should still require pinProtocol");
}

static void test_client_pin_parse_rejects_duplicate_top_level_keys(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[32];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCborEncoder enc;

    test_storage_reset();
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate clientPin key encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, ZF_CLIENT_PIN_SUBCMD_GET_RETRIES) &&
               zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT),
           "encode duplicate clientPin subCommand key");

    expect(zerofido_pin_handle_command(&app, buffer, zf_cbor_encoder_size(&enc), response,
                                       sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_CBOR,
           "clientPin should reject duplicate top-level keys");
}

static void test_client_pin_parse_rejects_duplicate_key_agreement_keys(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[256];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCborEncoder enc;

    test_storage_reset();
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init duplicate keyAgreement encoder");
    expect(zf_cbor_encode_map(&enc, 4), "encode clientPin top-level map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 1), "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_uint(&enc, ZF_CLIENT_PIN_SUBCMD_GET_PIN_TOKEN),
           "encode subCommand");
    expect(zf_cbor_encode_uint(&enc, 3), "encode keyAgreement key");
    expect(zf_cbor_encode_map(&enc, 6), "encode malformed keyAgreement map");
    expect(zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, 2), "encode kty");
    expect(zf_cbor_encode_int(&enc, 3) && zf_cbor_encode_int(&enc, -25), "encode alg");
    expect(zf_cbor_encode_int(&enc, -1) && zf_cbor_encode_int(&enc, 1), "encode crv");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x11}, ZF_PUBLIC_KEY_LEN),
        "encode first x");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x12}, ZF_PUBLIC_KEY_LEN),
        "encode duplicate x");
    expect(
        zf_cbor_encode_int(&enc, -3) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x22}, ZF_PUBLIC_KEY_LEN),
        "encode y");
    expect(zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PIN_HASH_LEN]){0x33}, ZF_PIN_HASH_LEN),
           "encode pinHashEnc");

    expect(zerofido_pin_handle_command(&app, buffer, zf_cbor_encoder_size(&enc), response,
                                       sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_CBOR,
           "clientPin should reject duplicate keyAgreement keys");
}

static size_t encode_client_pin_get_pin_token_request_with_protocol(
    uint8_t *buffer, size_t capacity, uint64_t pin_protocol, const uint8_t *pin_hash_enc,
    size_t pin_hash_enc_len, bool include_alg) {
    ZfCborEncoder enc;

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init clientPin getPinToken encoder");
    expect(zf_cbor_encode_map(&enc, 4), "encode top-level clientPin map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, pin_protocol),
           "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 5), "encode subcommand");
    expect(zf_cbor_encode_uint(&enc, 3), "encode keyAgreement key");
    expect(zf_cbor_encode_map(&enc, include_alg ? 5 : 4), "encode keyAgreement map");
    expect(zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, 2), "encode keyAgreement kty");
    if (include_alg) {
        expect(zf_cbor_encode_int(&enc, 3) && zf_cbor_encode_int(&enc, -25),
               "encode keyAgreement alg");
    }
    expect(zf_cbor_encode_int(&enc, -1) && zf_cbor_encode_int(&enc, 1), "encode keyAgreement crv");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x11}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement x");
    expect(
        zf_cbor_encode_int(&enc, -3) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x22}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement y");
    expect(zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_bytes(&enc, pin_hash_enc, pin_hash_enc_len),
           "encode pinHashEnc");
    return zf_cbor_encoder_size(&enc);
}

static size_t encode_client_pin_get_pin_token_request(uint8_t *buffer, size_t capacity,
                                                      const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                                                      bool include_alg) {
    return encode_client_pin_get_pin_token_request_with_protocol(
        buffer, capacity, ZF_PIN_PROTOCOL_V1, pin_hash, ZF_PIN_HASH_LEN, include_alg);
}

static size_t encode_client_pin_request_with_permissions(uint8_t *buffer, size_t capacity,
                                                         uint64_t subcommand,
                                                         const uint8_t pin_hash[ZF_PIN_HASH_LEN],
                                                         bool include_permissions,
                                                         uint64_t permissions, const char *rp_id) {
    ZfCborEncoder enc;
    size_t map_size = 4;

    if (include_permissions) {
        map_size++;
    }
    if (rp_id) {
        map_size++;
    }

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init clientPin permissions encoder");
    expect(zf_cbor_encode_map(&enc, map_size), "encode permissions top-level clientPin map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 1), "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, subcommand),
           "encode permissions subcommand");
    expect(zf_cbor_encode_uint(&enc, 3), "encode permissions keyAgreement key");
    expect(zf_cbor_encode_map(&enc, 5), "encode permissions keyAgreement map");
    expect(zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, 2), "encode permissions kty");
    expect(zf_cbor_encode_int(&enc, 3) && zf_cbor_encode_int(&enc, -25), "encode permissions alg");
    expect(zf_cbor_encode_int(&enc, -1) && zf_cbor_encode_int(&enc, 1), "encode permissions crv");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x11}, ZF_PUBLIC_KEY_LEN),
        "encode permissions x");
    expect(
        zf_cbor_encode_int(&enc, -3) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x22}, ZF_PUBLIC_KEY_LEN),
        "encode permissions y");
    expect(zf_cbor_encode_uint(&enc, 6) && zf_cbor_encode_bytes(&enc, pin_hash, ZF_PIN_HASH_LEN),
           "encode permissions pinHashEnc");
    if (include_permissions) {
        expect(zf_cbor_encode_uint(&enc, 9) && zf_cbor_encode_uint(&enc, permissions),
               "encode permissions field");
    }
    if (rp_id) {
        expect(zf_cbor_encode_uint(&enc, 10) && zf_cbor_encode_text(&enc, rp_id),
               "encode rpId field");
    }
    return zf_cbor_encoder_size(&enc);
}

static size_t encode_make_credential_ctap_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, bool include_uv, bool uv_value, bool include_pin_auth,
    const uint8_t *pin_auth, size_t pin_auth_len, bool include_pin_protocol, bool include_exclude,
    const uint8_t *exclude_id, size_t exclude_len);

static void test_client_pin_key_agreement_requires_alg(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[256];
    uint8_t response[64];
    size_t response_len = 0;
    static const uint8_t wrong_pin_hash[ZF_PIN_HASH_LEN] = {
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    };

    expect(
        zerofido_pin_handle_command(
            &app, buffer,
            encode_client_pin_get_pin_token_request(buffer, sizeof(buffer), wrong_pin_hash, false),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_CBOR,
        "clientPin keyAgreement should reject missing alg");
}

static void test_make_credential_parse_rejects_malformed_pubkey_cred_params(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init malformed pubKeyCredParams encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 2) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
               zf_cbor_encode_text(&enc, "alg") && zf_cbor_encode_int(&enc, -7),
           "encode malformed pubKeyCredParams request");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "malformed pubKeyCredParams should be rejected");
}

static void
test_make_credential_parse_rejects_non_public_key_pubkey_cred_param_as_unsupported_algorithm(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0xAA};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init unsupported pubKeyCredParams type encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "bogus-key"),
           "encode unsupported pubKeyCredParams type request");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_UNSUPPORTED_ALGORITHM,
           "non-public-key pubKeyCredParams type should map to unsupported algorithm");
}

static void test_make_credential_parse_rejects_zero_length_exclude_id(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0xAA};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init zero-length exclude id encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_array(&enc, 1) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, (const uint8_t *)"", 0) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode zero-length exclude id");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_CBOR,
           "zero-length exclude id should be rejected");
}

static void test_make_credential_parse_accepts_oversized_exclude_id(void) {
    uint8_t buffer[512];
    uint8_t oversized_id[ZF_CREDENTIAL_ID_LEN + 1];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0xAA};

    memset(oversized_id, 0xCD, sizeof(oversized_id));
    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init oversized exclude id encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_array(&enc, 1) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, oversized_id, sizeof(oversized_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode oversized exclude id");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "oversized exclude id should be accepted");
    expect(request.exclude_list.count == 1, "oversized exclude id should be counted");
    expect(!zf_ctap_descriptor_list_contains_id(&request.exclude_list, oversized_id,
                                                ZF_CREDENTIAL_ID_LEN),
           "oversized exclude id should not match by truncated bytes");
}

static void test_make_credential_parse_ignores_non_public_key_exclude_descriptor(void) {
    uint8_t buffer[512];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t user_id[] = {0xAA};
    static const uint8_t exclude_id[] = {0x10, 0x20, 0x30};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init non-public-key exclude descriptor encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_array(&enc, 1) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, exclude_id, sizeof(exclude_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "bogus-key"),
           "encode excludeList descriptor with non-public-key type");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "excludeList entries with non-public-key type should be ignored");
    expect(request.exclude_list.count == 0,
           "non-public-key exclude descriptors should not populate the parsed list");
}

static void test_make_credential_parse_rejects_empty_user_id(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfMakeCredentialRequest request;
    TEST_INIT_MAKE_CREDENTIAL_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)), "init empty user id encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, (const uint8_t *)"", 0) && zf_cbor_encode_uint(&enc, 4) &&
               zf_cbor_encode_array(&enc, 1) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "alg") && zf_cbor_encode_int(&enc, -7) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode empty user id request");

    expect(zf_ctap_parse_make_credential(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_ERR_INVALID_PARAMETER,
           "empty user id should be rejected");
}

static void test_get_assertion_parse_ignores_non_public_key_allow_list_descriptor(void) {
    uint8_t buffer[256];
    ZfCborEncoder enc;
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    static const uint8_t client_data_hash[32] = {0};
    static const uint8_t credential_id[] = {0xAB};

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init non-public-key allowList descriptor encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, sizeof(credential_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "bogus-key"),
           "encode allowList descriptor with non-public-key type");

    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "allowList entries with non-public-key type should be ignored");
    expect(request.allow_list.count == 0,
           "non-public-key allowList descriptors should not populate the parsed list");
}

static void test_store_find_by_rp_orders_records_by_newest_first(void) {
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    store.records = store_records;
    uint16_t matches[ZF_MAX_CREDENTIALS] = {0};

    store.count = 3;
    for (size_t i = 0; i < store.count; ++i) {
        store.records[i].in_use = true;
        store.records[i].resident_key = true;
        strcpy(store.records[i].rp_id, "example.com");
        memset(store.records[i].credential_id, (int)(0x10 + i), ZF_CREDENTIAL_ID_LEN);
        store.records[i].credential_id_len = ZF_CREDENTIAL_ID_LEN;
    }
    store.records[0].created_at = 10;
    store.records[1].created_at = 30;
    store.records[2].created_at = 20;

    expect(zf_store_find_by_rp(NULL, &store, "example.com", matches, ZF_MAX_CREDENTIALS) == 3,
           "should find all resident credentials for rp");
    expect(matches[0] == 1, "newest credential should be first");
    expect(matches[1] == 2, "second-newest credential should be second");
    expect(matches[2] == 0, "oldest credential should be last");
}

static void test_store_descriptor_list_ignores_oversized_descriptor_ids(void) {
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    ZfGetAssertionRequest request;
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    store.records = store_records;
    uint16_t matches[ZF_MAX_CREDENTIALS] = {0};
    uint8_t buffer[512];
    uint8_t oversized_id[ZF_CREDENTIAL_ID_LEN + 1];
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {0};

    memset(oversized_id, 0xAB, sizeof(oversized_id));
    store.count = 1;
    store.records[0].in_use = true;
    strcpy(store.records[0].rp_id, "example.com");
    store.records[0].credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(store.records[0].credential_id, 0xAB, ZF_CREDENTIAL_ID_LEN);

    expect(zf_cbor_encoder_init(&enc, buffer, sizeof(buffer)),
           "init oversized store allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, oversized_id, sizeof(oversized_id)) &&
               zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
           "encode oversized store allowList descriptor");
    expect(zf_ctap_parse_get_assertion(buffer, zf_cbor_encoder_size(&enc), &request) ==
               ZF_CTAP_SUCCESS,
           "parse oversized store allowList descriptor");

    expect(zf_store_find_by_rp_filtered(NULL, &store, request.assertion.rp_id,
                                        zf_ctap_store_entry_matches_descriptor_list,
                                        &request.allow_list, matches, ZF_MAX_CREDENTIALS) == 0,
           "oversized descriptor ids should be ignored rather than matched");
}

static size_t encode_get_assertion_ctap_request(uint8_t *buffer, size_t capacity) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    buffer[0] = ZfCtapeCmdGetAssertion;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1), "init CTAP getAssertion encoder");
    expect(zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode CTAP getAssertion request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_get_assertion_ctap_request_with_up(uint8_t *buffer, size_t capacity, bool up) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    buffer[0] = ZfCtapeCmdGetAssertion;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP getAssertion up option encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "up") && zf_cbor_encode_bool(&enc, up),
           "encode CTAP getAssertion up option request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_get_assertion_ctap_request_with_allow_list(uint8_t *buffer, size_t capacity,
                                                                const uint8_t *credential_id,
                                                                size_t credential_id_len) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    buffer[0] = ZfCtapeCmdGetAssertion;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP getAssertion allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id, credential_id_len),
           "encode CTAP getAssertion allowList request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_get_assertion_ctap_request_with_two_allow_list_entries(
    uint8_t *buffer, size_t capacity, const uint8_t *credential_id_a, size_t credential_id_len_a,
    const uint8_t *credential_id_b, size_t credential_id_len_b) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    buffer[0] = ZfCtapeCmdGetAssertion;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP getAssertion two-entry allowList encoder");
    expect(zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_array(&enc, 2) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id_a, credential_id_len_a) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, credential_id_b, credential_id_len_b),
           "encode CTAP getAssertion two-entry allowList request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static void seed_assertion_queue_record_full(ZfCredentialRecord *record, uint8_t id_byte,
                                             uint32_t sign_count);
static void seed_assertion_queue_record_index(ZfCredentialIndexEntry *record, uint8_t id_byte,
                                              uint32_t sign_count);
#define seed_assertion_queue_record(record, id_byte, sign_count)                                   \
    _Generic((record),                                                                             \
        ZfCredentialRecord *: seed_assertion_queue_record_full,                                    \
        ZfCredentialIndexEntry *: seed_assertion_queue_record_index)(record, id_byte, sign_count)

static size_t encode_get_assertion_ctap_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, bool include_uv, bool uv_value, bool include_pin_auth,
    const uint8_t *pin_auth, size_t pin_auth_len, bool include_pin_protocol) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };
    size_t pair_count = 2;

    if (include_uv) {
        pair_count++;
    }
    if (include_pin_auth) {
        pair_count++;
    }
    if (include_pin_protocol) {
        pair_count++;
    }

    buffer[0] = ZfCtapeCmdGetAssertion;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP getAssertion pinAuth encoder");
    expect(zf_cbor_encode_map(&enc, pair_count) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_text(&enc, "example.com") && zf_cbor_encode_uint(&enc, 2) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)),
           "encode CTAP getAssertion pinAuth request");
    if (include_uv) {
        expect(zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_map(&enc, 1) &&
                   zf_cbor_encode_text(&enc, "uv") && zf_cbor_encode_bool(&enc, uv_value),
               "encode getAssertion uv option");
    }
    if (include_pin_auth) {
        expect(zf_cbor_encode_uint(&enc, 6) && zf_cbor_encode_bytes(&enc, pin_auth, pin_auth_len),
               "encode getAssertion pinAuth");
    }
    if (include_pin_protocol) {
        expect(zf_cbor_encode_uint(&enc, 7) && zf_cbor_encode_uint(&enc, 1),
               "encode getAssertion pinProtocol");
    }
    return zf_cbor_encoder_size(&enc) + 1;
}

static void test_pin_auth_block_state_clears_on_reinit_but_keeps_retries(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set baseline PIN");

    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "first wrong PIN should be invalid");
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "second wrong PIN should be invalid");
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_AUTH_BLOCKED,
           "third wrong PIN should auth-block");

    expect(zerofido_pin_init(&storage, &restored), "re-init PIN state");
    expect(!restored.pin_auth_blocked, "re-init should clear temporary auth-block state");
    expect(restored.pin_consecutive_mismatches == 0,
           "re-init should clear temporary pinAuth mismatch count");
    expect(restored.pin_retries == (ZF_PIN_RETRIES_MAX - 3),
           "re-init should keep the decremented retry counter");
    expect(zerofido_pin_verify_plaintext(&storage, &restored, "1234") == ZF_CTAP_SUCCESS,
           "correct PIN should work again after re-init clears the temporary auth block");
    expect(restored.pin_retries == ZF_PIN_RETRIES_MAX,
           "successful PIN verification after re-init should reset retries");
}

static void test_pin_plaintext_accepts_ctap_max_utf8_length(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    char max_pin[ZF_PIN_NEW_PIN_BLOCK_MAX_LEN];
    char too_long_pin[ZF_PIN_NEW_PIN_BLOCK_MAX_LEN + 1U];
    uint8_t max_pin_block[ZF_PIN_NEW_PIN_BLOCK_MAX_LEN] = {0};
    size_t unpadded_len = 0;

    test_storage_reset();
    memset(max_pin, '7', sizeof(max_pin) - 1U);
    max_pin[sizeof(max_pin) - 1U] = '\0';
    memset(too_long_pin, '8', sizeof(too_long_pin) - 1U);
    too_long_pin[sizeof(too_long_pin) - 1U] = '\0';
    memset(max_pin_block, '9', ZF_PIN_NEW_PIN_BLOCK_MAX_LEN - 1U);

    expect(zerofido_pin_init(&storage, &state), "init PIN state for max-length PIN");
    expect(zerofido_pin_set_plaintext(&storage, &state, max_pin) == ZF_CTAP_SUCCESS,
           "63-byte PIN should be accepted");
    expect(zerofido_pin_verify_plaintext(&storage, &state, max_pin) == ZF_CTAP_SUCCESS,
           "63-byte PIN should verify");
    expect(zf_pin_validate_plaintext_block(max_pin_block, sizeof(max_pin_block), &unpadded_len),
           "63-byte padded newPinEnc block should be accepted");
    expect(unpadded_len == ZF_PIN_NEW_PIN_BLOCK_MAX_LEN - 1U,
           "max PIN block should report 63 unpadded bytes");
    expect(zf_pin_validate_plaintext_policy((const uint8_t *)too_long_pin, strlen(too_long_pin)) ==
               ZF_CTAP_ERR_PIN_POLICY_VIOLATION,
           "64-byte PIN should be rejected");
}

static void test_pin_resume_auth_attempts_clears_persisted_block(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0};
    uint8_t pin_auth[ZF_PIN_AUTH_LEN];
    bool uv_verified = false;

    test_storage_reset();
    memset(pin_auth, 0x01, sizeof(pin_auth));
    expect(zerofido_pin_init(&storage, &state), "init PIN state");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set baseline PIN");
    mark_pin_token_issued(&state);

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "first pinAuth mismatch should be invalid");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "second pinAuth mismatch should be invalid");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_BLOCKED,
           "third pinAuth mismatch should auth-block");
    expect(zerofido_pin_resume_auth_attempts(&storage, &state),
           "resume PIN attempts should persist");

    expect(zerofido_pin_init(&storage, &restored), "re-init PIN state after resume");
    expect(!restored.pin_auth_blocked, "resumed PIN state should not stay auth-blocked");
    expect(restored.pin_consecutive_mismatches == 0,
           "resumed PIN mismatch count should be cleared");
}

static void test_pin_clear_removes_persisted_state_and_resets_runtime(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for clear test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for clear test");
    expect(state.pin_set, "PIN should be set before clear");
    expect(g_pin_file_exists, "PIN file should exist before clear");

    expect(zerofido_pin_clear(&storage, &state), "clear PIN should succeed");
    expect(!state.pin_set, "runtime PIN state should be cleared");
    expect(state.pin_retries == ZF_PIN_RETRIES_MAX, "clear should restore retry count");
    expect(!state.pin_auth_blocked, "clear should remove auth block state");
    expect(!state.pin_token_active, "clear should invalidate the active pin token");
    expect(!g_pin_file_exists, "clear should remove the persisted PIN file");

    expect(zerofido_pin_init(&storage, &restored), "re-init after clear should succeed");
    expect(!restored.pin_set, "re-init after clear should not restore a PIN");
}

static void test_pin_init_rejects_unsupported_format_state(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfPinFileRecordBase invalid = {0};

    test_storage_reset();
    invalid.magic = ZF_PIN_FILE_MAGIC;
    invalid.version = 0U;
    invalid.pin_retries = 5;
    invalid.pin_consecutive_mismatches = 2;
    invalid.flags = ZF_PIN_FILE_FLAG_AUTH_BLOCKED;
    memset(invalid.iv, 0xA5, sizeof(invalid.iv));
    memset(invalid.encrypted_pin_hash, 0x5C, sizeof(invalid.encrypted_pin_hash));
    memcpy(g_pin_file_data, &invalid, sizeof(invalid));
    g_pin_file_size = sizeof(invalid);
    g_pin_file_exists = true;

    expect(!zerofido_pin_init(&storage, &state), "unsupported PIN state format should be rejected");
    expect(zerofido_pin_init_with_result(&storage, &state) == ZfPinInitInvalidPersistedState,
           "unsupported PIN state format should be classified as invalid persisted state");
}

static void test_pin_init_rejects_unsupported_current_format_version(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for unsupported-version test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for unsupported-version test");

    ((ZfPinFileRecord *)g_pin_file_data)->base.version = 0U;
    expect(!zerofido_pin_init(&storage, &restored),
           "current-format PIN state with unsupported version should be rejected");
}

static void test_pin_init_rejects_tampered_retry_state(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for tamper test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for tamper test");

    ((ZfPinFileRecord *)g_pin_file_data)->base.pin_retries--;
    expect(!zerofido_pin_init(&storage, &restored),
           "tampered PIN retry state should fail sealed-state verification");
}

static void test_pin_auth_blocks_after_three_mismatches(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0};
    uint8_t pin_auth[ZF_PIN_AUTH_LEN];
    bool uv_verified = false;

    test_storage_reset();
    state.pin_set = true;
    memset(state.pin_token, 0, sizeof(state.pin_token));
    mark_pin_token_issued(&state);
    memset(pin_auth, 0x01, sizeof(pin_auth));

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "first pinAuth mismatch should be invalid");
    expect(!uv_verified, "uv flag should stay false after first pinAuth mismatch");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "second pinAuth mismatch should be invalid");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_BLOCKED,
           "third pinAuth mismatch should auth-block");
}

static void test_ui_format_approval_header_prefixes_protocol(void) {
    char out[32];

    zf_ui_format_approval_header(out, sizeof(out), ZfUiProtocolFido2, "Authenticate");
    expect(strcmp(out, "Use passkey") == 0, "FIDO2 approvals should use friendly passkey text");
}

static void test_ui_format_approval_body_uses_protocol_specific_target_label(void) {
    char out[160];

    zf_ui_format_approval_body(out, sizeof(out), ZfUiProtocolFido2, "example.com", "User: alice");
    expect(!contains_text((const uint8_t *)out, strlen(out), "Protocol:"),
           "FIDO2 approval body should hide protocol jargon");
    expect(contains_text((const uint8_t *)out, strlen(out), "Website: example.com"),
           "FIDO2 approval body should use website label");
}

static void test_ui_format_fido2_credential_label_uses_passkey_text(void) {
    ZfCredentialRecord record = {0};
    char out[128];

    record.in_use = true;
    record.resident_key = true;
    strncpy(record.rp_id, "example.com", sizeof(record.rp_id) - 1);
    strncpy(record.user_name, "alice", sizeof(record.user_name) - 1);
    strncpy(record.user_display_name, "Alice Example", sizeof(record.user_display_name) - 1);
    zf_ui_format_fido2_credential_label(&record, out, sizeof(out));
    expect(strcmp(out, "Alice Example | example.com") == 0,
           "passkey labels should prefer display name and website");

    record.resident_key = false;
    record.user_name[0] = '\0';
    record.user_display_name[0] = '\0';
    zf_ui_format_fido2_credential_label(&record, out, sizeof(out));
    expect(strcmp(out, "example.com") == 0, "passkey labels should fall back to website");
}

static void test_ui_format_fido2_credential_detail_uses_user_facing_text(void) {
    ZfCredentialRecord record = {0};
    char out[256];

    record.in_use = true;
    record.resident_key = false;
    record.credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(record.credential_id, 0xab, sizeof(record.credential_id));
    strncpy(record.rp_id, "example.com", sizeof(record.rp_id) - 1);
    strncpy(record.user_name, "alice", sizeof(record.user_name) - 1);
    record.sign_count = 9;
    record.created_at = 42;

    zf_ui_format_fido2_credential_detail(&record, out, sizeof(out));
    expect(contains_text((const uint8_t *)out, strlen(out), "Website: example.com"),
           "passkey detail should show the website");
    expect(contains_text((const uint8_t *)out, strlen(out), "Account: alice"),
           "passkey detail should show the account");
    expect(contains_text((const uint8_t *)out, strlen(out), "Type: Saved passkey"),
           "passkey detail should use user-facing type text");
    expect(contains_text((const uint8_t *)out, strlen(out), "Used: 9 times"),
           "passkey detail should show the use count");
}

static void test_ui_hex_encode_truncated_limits_output(void) {
    uint8_t bytes[] = {0xaa, 0xbb, 0xcc, 0xdd};
    char out[5];

    zf_ui_hex_encode_truncated(bytes, sizeof(bytes), out, sizeof(out));
    expect(strcmp(out, "aabb") == 0, "hex encoder should truncate to available output space");
}

static void test_get_pin_token_wrong_pin_regenerates_key_agreement(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t buffer[256];
    uint8_t response[64];
    size_t response_len = 0;
    uint8_t original_public_x = 0;
    static const uint8_t wrong_pin_hash[ZF_PIN_HASH_LEN] = {
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    };

    app.pin_state.pin_set = true;
    app.pin_state.pin_retries = ZF_PIN_RETRIES_MAX;
    memset(app.pin_state.pin_hash, 0x11, sizeof(app.pin_state.pin_hash));
    expect(zf_crypto_generate_key_agreement_key(&app.pin_state.key_agreement),
           "generate initial key agreement");
    original_public_x = app.pin_state.key_agreement.public_x[0];

    expect(
        zerofido_pin_handle_command(
            &app, buffer,
            encode_client_pin_get_pin_token_request(buffer, sizeof(buffer), wrong_pin_hash, true),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_INVALID,
        "wrong PIN should return pin invalid");
    expect(app.pin_state.key_agreement.public_x[0] != original_public_x,
           "wrong PIN should regenerate key agreement");
}

static size_t encode_client_pin_change_pin_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, const uint8_t current_pin_hash[ZF_PIN_HASH_LEN],
    const uint8_t *new_pin_block, size_t new_pin_block_len,
    const uint8_t pin_auth[ZF_PIN_AUTH_LEN]) {
    uint8_t combined[288];
    uint8_t computed_pin_auth[32];
    ZfCborEncoder enc;
    static const uint8_t shared_secret[32] = {[0 ... 31] = 0xAB};

    expect(new_pin_block_len >= 64 && (new_pin_block_len % 16) == 0, "changePin newPinEnc length");
    if (!pin_auth) {
        memcpy(combined, new_pin_block, new_pin_block_len);
        memcpy(combined + new_pin_block_len, current_pin_hash, ZF_PIN_HASH_LEN);
        zf_crypto_hmac_sha256(shared_secret, sizeof(shared_secret), combined,
                              new_pin_block_len + ZF_PIN_HASH_LEN, computed_pin_auth);
        pin_auth = computed_pin_auth;
    }

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init clientPin changePin encoder");
    expect(zf_cbor_encode_map(&enc, 6), "encode changePin top-level map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 1), "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 4), "encode subcommand");
    expect(zf_cbor_encode_uint(&enc, 3), "encode keyAgreement key");
    expect(zf_cbor_encode_map(&enc, 5), "encode keyAgreement map");
    expect(zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, 2), "encode keyAgreement kty");
    expect(zf_cbor_encode_int(&enc, 3) && zf_cbor_encode_int(&enc, -25), "encode keyAgreement alg");
    expect(zf_cbor_encode_int(&enc, -1) && zf_cbor_encode_int(&enc, 1), "encode keyAgreement crv");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x11}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement x");
    expect(
        zf_cbor_encode_int(&enc, -3) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x22}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement y");
    expect(zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_bytes(&enc, pin_auth, ZF_PIN_AUTH_LEN),
           "encode pinAuth");
    expect(zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_bytes(&enc, new_pin_block, new_pin_block_len),
           "encode newPinEnc");
    expect(zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_bytes(&enc, current_pin_hash, ZF_PIN_HASH_LEN),
           "encode pinHashEnc");
    return zf_cbor_encoder_size(&enc);
}

static size_t encode_client_pin_change_pin_request(uint8_t *buffer, size_t capacity,
                                                   const uint8_t current_pin_hash[ZF_PIN_HASH_LEN],
                                                   const uint8_t *new_pin_block,
                                                   size_t new_pin_block_len) {
    return encode_client_pin_change_pin_request_with_pin_auth(
        buffer, capacity, current_pin_hash, new_pin_block, new_pin_block_len, NULL);
}

static size_t encode_client_pin_set_pin_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, const uint8_t *new_pin_block, size_t new_pin_block_len,
    const uint8_t pin_auth[ZF_PIN_AUTH_LEN]) {
    uint8_t computed_pin_auth[32];
    ZfCborEncoder enc;
    static const uint8_t shared_secret[32] = {[0 ... 31] = 0xAB};

    expect(new_pin_block_len >= 64 && (new_pin_block_len % 16) == 0, "setPin newPinEnc length");
    if (!pin_auth) {
        zf_crypto_hmac_sha256(shared_secret, sizeof(shared_secret), new_pin_block,
                              new_pin_block_len, computed_pin_auth);
        pin_auth = computed_pin_auth;
    }

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init clientPin setPin encoder");
    expect(zf_cbor_encode_map(&enc, 5), "encode setPin top-level map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 1), "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 3), "encode subcommand");
    expect(zf_cbor_encode_uint(&enc, 3), "encode keyAgreement key");
    expect(zf_cbor_encode_map(&enc, 5), "encode keyAgreement map");
    expect(zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, 2), "encode keyAgreement kty");
    expect(zf_cbor_encode_int(&enc, 3) && zf_cbor_encode_int(&enc, -25), "encode keyAgreement alg");
    expect(zf_cbor_encode_int(&enc, -1) && zf_cbor_encode_int(&enc, 1), "encode keyAgreement crv");
    expect(
        zf_cbor_encode_int(&enc, -2) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x11}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement x");
    expect(
        zf_cbor_encode_int(&enc, -3) &&
            zf_cbor_encode_bytes(&enc, (const uint8_t[ZF_PUBLIC_KEY_LEN]){0x22}, ZF_PUBLIC_KEY_LEN),
        "encode keyAgreement y");
    expect(zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_bytes(&enc, pin_auth, ZF_PIN_AUTH_LEN),
           "encode pinAuth");
    expect(zf_cbor_encode_uint(&enc, 5) &&
               zf_cbor_encode_bytes(&enc, new_pin_block, new_pin_block_len),
           "encode newPinEnc");
    return zf_cbor_encoder_size(&enc);
}

static size_t encode_client_pin_get_key_agreement_request(uint8_t *buffer, size_t capacity) {
    ZfCborEncoder enc;

    expect(zf_cbor_encoder_init(&enc, buffer, capacity), "init clientPin getKeyAgreement encoder");
    expect(zf_cbor_encode_map(&enc, 2), "encode getKeyAgreement top-level map");
    expect(zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 1), "encode pinProtocol");
    expect(zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_uint(&enc, 2), "encode subcommand");
    return zf_cbor_encoder_size(&enc);
}

static void test_change_pin_invalid_new_pin_after_correct_current_pin_resets_retries(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for changePin");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for changePin");
    app.storage = &storage;
    app.pin_state.pin_retries = 2;
    app.pin_state.pin_consecutive_mismatches = 1;
    expect(zf_pin_persist_state(&storage, &app.pin_state), "persist retry state before changePin");

    memcpy(new_pin_block, "5678", 4);
    new_pin_block[4] = 0x00;
    new_pin_block[5] = 0x7F;

    expect(
        zerofido_pin_handle_command(
            &app, request,
            encode_client_pin_change_pin_request(request, sizeof(request), app.pin_state.pin_hash,
                                                 new_pin_block, sizeof(new_pin_block)),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_POLICY_VIOLATION,
        "invalid new PIN block should be rejected");
    expect(app.pin_state.pin_retries == ZF_PIN_RETRIES_MAX,
           "verified current PIN should reset retries before new PIN validation");
    expect(app.pin_state.pin_consecutive_mismatches == 0,
           "verified current PIN should clear mismatches before new PIN validation");
}

static void test_change_pin_preserves_key_agreement_on_success(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    ZfP256KeyAgreementKey original_key_agreement = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for changePin keyAgreement continuity");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for changePin keyAgreement continuity");
    app.storage = &storage;
    memcpy(new_pin_block, "5678", 4);
    memcpy(&original_key_agreement, &app.pin_state.key_agreement, sizeof(original_key_agreement));

    expect(
        zerofido_pin_handle_command(
            &app, request,
            encode_client_pin_change_pin_request(request, sizeof(request), app.pin_state.pin_hash,
                                                 new_pin_block, sizeof(new_pin_block)),
            response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
        "changePin should succeed before checking keyAgreement continuity");
    expect(memcmp(&app.pin_state.key_agreement, &original_key_agreement,
                  sizeof(original_key_agreement)) == 0,
           "changePin should preserve the active keyAgreement so browser follow-up requests work");
}

static void test_set_pin_invalid_new_pin_block_is_rejected(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for setPin padding test");
    app.storage = &storage;
    memcpy(new_pin_block, "1234", 4);
    new_pin_block[4] = 0x00;
    new_pin_block[5] = 0x7F;

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_set_pin_request_with_pin_auth(
                   request, sizeof(request), new_pin_block, sizeof(new_pin_block), NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_POLICY_VIOLATION,
           "setPin should reject garbage after the first NUL in newPinEnc");
    expect(!app.pin_state.pin_set, "invalid setPin block should not set a PIN");
}

static void test_set_pin_new_pin_decrypt_failure_returns_pin_auth_invalid(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for setPin failure");
    app.storage = &storage;
    memcpy(new_pin_block, "1234", 4);
    g_fail_crypto_decrypt = true;

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_set_pin_request_with_pin_auth(
                   request, sizeof(request), new_pin_block, sizeof(new_pin_block), NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "setPin newPinEnc decrypt failure should return pin auth invalid");
}

static void test_set_pin_rejects_oversized_new_pin_block(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[640];
    uint8_t response[64];
    uint8_t new_pin_block[ZF_PIN_NEW_PIN_BLOCK_MAX_LEN + 16U] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for long setPin block");
    app.storage = &storage;
    memcpy(new_pin_block, "1234", 4);

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_set_pin_request_with_pin_auth(
                   request, sizeof(request), new_pin_block, sizeof(new_pin_block), NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "setPin should reject oversized protocol 1 newPinEnc blocks");
    expect(!app.pin_state.pin_set, "oversized setPin block should not configure a PIN");
}

static void test_set_pin_preserves_key_agreement_on_success(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    ZfP256KeyAgreementKey original_key_agreement = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for setPin keyAgreement continuity");
    app.storage = &storage;
    memcpy(new_pin_block, "1234", 4);
    memcpy(&original_key_agreement, &app.pin_state.key_agreement, sizeof(original_key_agreement));

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_set_pin_request_with_pin_auth(
                   request, sizeof(request), new_pin_block, sizeof(new_pin_block), NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "setPin should succeed before checking keyAgreement continuity");
    expect(memcmp(&app.pin_state.key_agreement, &original_key_agreement,
                  sizeof(original_key_agreement)) == 0,
           "setPin should preserve the active keyAgreement so browser follow-up requests work");
}

static void test_set_pin_creates_app_data_dir_before_persisting(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    g_storage_root_exists = false;
    g_storage_app_data_exists = false;
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state before mkdir setPin");
    app.storage = &storage;
    memcpy(new_pin_block, "1234", 4);

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_set_pin_request_with_pin_auth(
                   request, sizeof(request), new_pin_block, sizeof(new_pin_block), NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "setPin should create the app data directory before persisting state");
    expect(g_storage_root_exists, "setPin should create the app data root when missing");
    expect(g_storage_app_data_exists, "setPin should create the app data directory when missing");
    expect(g_pin_file_exists, "setPin should persist the PIN state file");
}

static void test_runtime_config_load_defaults_auto_accept_off(void) {
    ZfRuntimeConfig config = {.auto_accept_requests = true, .fido2_enabled = false};

    zf_runtime_config_load_defaults(&config);

    expect(!config.auto_accept_requests, "runtime config defaults should keep auto-accept off");
    expect(config.fido2_enabled, "runtime config defaults should keep FIDO2 enabled");
    expect(config.fido2_profile == ZfFido2ProfileCtap2_0,
           "runtime config defaults should use the CTAP 2.0 profile");
    expect(config.attestation_mode == ZfAttestationModePacked,
           "runtime config defaults should use packed attestation");
}

static void test_runtime_config_persist_round_trips_auto_accept_setting(void) {
    Storage storage = {0};
    ZfRuntimeConfig saved = {0};
    ZfRuntimeConfig loaded = {0};

    test_storage_reset();
    zf_runtime_config_load_defaults(&saved);
    saved.auto_accept_requests = true;
    saved.fido2_enabled = false;

    expect(zf_runtime_config_persist(&storage, &saved),
           "persisting runtime config should succeed in native storage");

    zf_runtime_config_load(&storage, &loaded);
    expect(loaded.auto_accept_requests,
           "runtime config load should restore persisted auto-accept setting");
    expect(loaded.fido2_enabled,
           "runtime config load should ignore stale persisted FIDO2 disabled state");
}

static void test_runtime_config_persist_round_trips_transport_mode(void) {
    Storage storage = {0};
    ZfRuntimeConfig saved = {0};
    ZfRuntimeConfig loaded = {0};

    test_storage_reset();
    zf_runtime_config_load_defaults(&saved);
    saved.transport_mode = ZfTransportModeNfc;

    expect(zf_runtime_config_persist(&storage, &saved),
           "persisting NFC transport config should succeed in native storage");

    zf_runtime_config_load(&storage, &loaded);
    expect(loaded.transport_mode == ZfTransportModeNfc,
           "runtime config load should restore the persisted NFC transport mode");
}

static void test_runtime_config_persist_round_trips_fido2_profile(void) {
    Storage storage = {0};
    ZfRuntimeConfig saved = {0};
    ZfRuntimeConfig loaded = {0};

    test_storage_reset();
    zf_runtime_config_load_defaults(&saved);
    saved.fido2_profile = ZfFido2ProfileCtap2_1Experimental;

    expect(zf_runtime_config_persist(&storage, &saved),
           "persisting experimental FIDO2 profile should succeed in native storage");

    zf_runtime_config_load(&storage, &loaded);
    expect(loaded.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "runtime config load should restore the persisted FIDO2 profile");
}

static void test_runtime_config_persist_round_trips_attestation_mode(void) {
    Storage storage = {0};
    ZfRuntimeConfig saved = {0};
    ZfRuntimeConfig loaded = {0};

    test_storage_reset();
    zf_runtime_config_load_defaults(&saved);
    saved.attestation_mode = ZfAttestationModeNone;

    expect(zf_runtime_config_persist(&storage, &saved),
           "persisting none attestation mode should succeed in native storage");

    zf_runtime_config_load(&storage, &loaded);
    expect(loaded.attestation_mode == ZfAttestationModeNone,
           "runtime config load should restore the persisted attestation mode");
}

static void test_runtime_config_set_attestation_mode_updates_capabilities(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.pin_state.pin_set = true;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_runtime_config_set_attestation_mode(&app, &storage, ZfAttestationModeNone),
           "runtime config should persist the selected attestation mode");
    expect(app.runtime_config.attestation_mode == ZfAttestationModeNone,
           "runtime config should apply the selected attestation mode");
    expect(app.capabilities.attestation_mode == ZfAttestationModeNone,
           "resolved capabilities should expose the selected attestation mode");
    expect(strcmp(zf_attestation_mode_name(app.runtime_config.attestation_mode), "None") == 0,
           "attestation label should expose none mode");
}

static void test_runtime_config_set_fido2_profile_updates_capabilities(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.pin_state.pin_set = true;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_runtime_config_set_fido2_profile(&app, &storage, ZfFido2ProfileCtap2_1Experimental),
           "runtime config should persist the user-selected FIDO2 profile");
    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "runtime config should apply the selected FIDO2 profile");
    expect(app.capabilities.advertise_fido_2_1,
           "experimental FIDO2 profile should advertise FIDO_2_1");
    expect(app.capabilities.pin_uv_auth_protocol_2_enabled,
           "experimental FIDO2 profile should enable protocol 2 advertisement");
    expect(app.capabilities.selection_enabled,
           "experimental FIDO2 profile should enable authenticatorSelection");
    expect(strcmp(zf_fido2_profile_name(app.runtime_config.fido2_profile), "2.1 exp") == 0,
           "FIDO2 profile label should expose the experimental profile");
}

static void test_runtime_config_set_fido2_profile_requires_pin_for_2_1(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(!zf_runtime_config_set_fido2_profile(&app, &storage, ZfFido2ProfileCtap2_1Experimental),
           "runtime config should reject CTAP 2.1 profile while PIN is unset");
    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_0,
           "failed PIN-gated profile switch should keep CTAP 2.0");
    expect(!app.capabilities.advertise_fido_2_1,
           "failed PIN-gated profile switch should not advertise CTAP 2.1");
}

static void test_runtime_config_apply_downgrades_2_1_when_pin_is_unset(void) {
    ZerofidoApp app = {0};
    ZfRuntimeConfig config = {0};

    zf_runtime_config_load_defaults(&config);
    config.fido2_profile = ZfFido2ProfileCtap2_1Experimental;
    zf_runtime_config_apply(&app, &config);

    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "runtime config apply should preserve the requested CTAP 2.1 profile");
    expect(app.capabilities.fido2_profile == ZfFido2ProfileCtap2_0,
           "resolved capabilities should downgrade CTAP 2.1 when PIN is unset");
    expect(!app.capabilities.advertise_fido_2_1,
           "downgraded capabilities should not advertise CTAP 2.1");
    expect(!app.capabilities.selection_enabled,
           "downgraded capabilities should keep authenticatorSelection disabled");
}

static void test_runtime_config_pin_refresh_restores_requested_2_1_profile(void) {
    ZerofidoApp app = {0};
    ZfRuntimeConfig config = {0};

    zf_runtime_config_load_defaults(&config);
    config.fido2_profile = ZfFido2ProfileCtap2_1Experimental;
    zf_runtime_config_apply(&app, &config);

    app.pin_state.pin_set = true;
    zf_runtime_config_refresh_capabilities(&app);
    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "PIN refresh should keep the requested CTAP 2.1 profile");
    expect(app.capabilities.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "PIN refresh should restore effective CTAP 2.1 capabilities");
    expect(app.capabilities.advertise_fido_2_1,
           "PIN refresh should advertise CTAP 2.1 after PIN is set");

    app.pin_state.pin_set = false;
    zf_runtime_config_refresh_capabilities(&app);
    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "clearing PIN should not erase the requested CTAP 2.1 profile");
    expect(app.capabilities.fido2_profile == ZfFido2ProfileCtap2_0,
           "clearing PIN should downgrade only effective capabilities");
}

static void test_runtime_config_persist_preserves_requested_2_1_after_pin_clear(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfRuntimeConfig config = {0};
    ZfRuntimeConfig loaded = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&config);
    config.fido2_profile = ZfFido2ProfileCtap2_1Experimental;
    zf_runtime_config_apply(&app, &config);

    expect(zf_runtime_config_set_auto_accept_requests(&app, &storage, true),
           "persisting another setting after PIN clear should succeed");
    zf_runtime_config_load(&storage, &loaded);
    expect(loaded.fido2_profile == ZfFido2ProfileCtap2_1Experimental,
           "persisting another setting should not write the downgraded profile");
    expect(loaded.auto_accept_requests,
           "persisting another setting should still update that setting");
}

static void test_runtime_config_load_invalid_file_falls_back_to_defaults(void) {
    Storage storage = {0};
    ZfRuntimeConfig loaded = {.auto_accept_requests = true, .fido2_enabled = false};
    TestStorageFile *file = NULL;

    test_storage_reset();
    file = test_storage_file_slot(ZF_RUNTIME_CONFIG_FILE_PATH, true);
    expect(file != NULL, "allocate runtime config storage slot");
    file->exists = true;
    file->size = 1;
    file->data[0] = 0xFF;

    zf_runtime_config_load(&storage, &loaded);
    expect(!loaded.auto_accept_requests,
           "invalid runtime config file should fall back to defaults");
    expect(loaded.fido2_enabled,
           "invalid runtime config file should restore default FIDO2 availability");
}

static void test_runtime_config_load_rejects_unsupported_version(void) {
    Storage storage = {0};
    ZfRuntimeConfig loaded = {.auto_accept_requests = true, .fido2_enabled = false};
    TestStorageFile *file = NULL;
    ZfRuntimeConfigFileRecord record = {
        .magic = ZF_RUNTIME_CONFIG_FILE_MAGIC,
        .version = 5U,
        .flags = ZF_RUNTIME_CONFIG_FLAG_AUTO_ACCEPT_REQUESTS,
        .transport_mode = ZfTransportModeUsbHid,
        .fido2_profile = ZfFido2ProfileCtap2_0,
    };

    test_storage_reset();
    file = test_storage_file_slot(ZF_RUNTIME_CONFIG_FILE_PATH, true);
    expect(file != NULL, "allocate runtime config storage slot for unsupported version");
    file->exists = true;
    file->size = sizeof(record);
    memcpy(file->data, &record, sizeof(record));

    zf_runtime_config_load(&storage, &loaded);
    expect(!loaded.auto_accept_requests,
           "unsupported runtime config version should fall back to defaults");
    expect(loaded.fido2_enabled,
           "unsupported runtime config version should keep default FIDO2 availability");
}

static void test_runtime_config_set_auto_accept_preserves_runtime_state_on_persist_failure(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_storage_fail_write_match = "runtime_config.tmp";

    expect(!zf_runtime_config_set_auto_accept_requests(&app, &storage, true),
           "runtime config mutation should fail when persistence fails");
    expect(!app.runtime_config.auto_accept_requests,
           "failed runtime config persist should keep auto-accept disabled");
    expect(!app.capabilities.auto_accept_requests,
           "failed runtime config persist should keep resolved auto-accept disabled");
}

static void test_runtime_config_set_fido2_preserves_runtime_state_on_persist_failure(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_storage_fail_write_match = "runtime_config.tmp";

    expect(!zf_runtime_config_set_fido2_enabled(&app, &storage, false),
           "runtime config mutation should fail when FIDO2 persist fails");
    expect(app.runtime_config.fido2_enabled,
           "failed runtime config persist should keep FIDO2 enabled");
    expect(app.capabilities.fido2_enabled,
           "failed runtime config persist should keep resolved FIDO2 enabled");
}

static void test_runtime_config_set_fido2_profile_preserves_runtime_state_on_persist_failure(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.pin_state.pin_set = true;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_storage_fail_write_match = "runtime_config.tmp";

    expect(!zf_runtime_config_set_fido2_profile(&app, &storage, ZfFido2ProfileCtap2_1Experimental),
           "runtime config profile mutation should fail when persistence fails");
    expect(app.runtime_config.fido2_profile == ZfFido2ProfileCtap2_0,
           "failed profile persist should keep the CTAP 2.0 profile");
    expect(!app.capabilities.advertise_fido_2_1,
           "failed profile persist should keep FIDO_2_1 disabled");
}

static void test_runtime_config_set_attestation_preserves_runtime_state_on_persist_failure(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_storage_fail_write_match = "runtime_config.tmp";

    expect(!zf_runtime_config_set_attestation_mode(&app, &storage, ZfAttestationModeNone),
           "runtime config attestation mutation should fail when persistence fails");
    expect(app.runtime_config.attestation_mode == ZfAttestationModePacked,
           "failed attestation persist should keep packed mode");
    expect(app.capabilities.attestation_mode == ZfAttestationModePacked,
           "failed attestation persist should keep resolved packed mode");
}

static void test_get_key_agreement_does_not_rotate_runtime_secrets(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[64];
    uint8_t response[160];
    uint8_t original_pin_token[ZF_PIN_TOKEN_LEN];
    ZfP256KeyAgreementKey original_key_agreement = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for getKeyAgreement");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for getKeyAgreement");
    app.storage = &storage;
    memcpy(original_pin_token, app.pin_state.pin_token, sizeof(original_pin_token));
    memcpy(&original_key_agreement, &app.pin_state.key_agreement, sizeof(original_key_agreement));

    expect(zerofido_pin_handle_command(
               &app, request, encode_client_pin_get_key_agreement_request(request, sizeof(request)),
               response, sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "getKeyAgreement should succeed");
    expect(response_len > 0, "getKeyAgreement should return a COSE key response");
    expect(memcmp(app.pin_state.pin_token, original_pin_token, sizeof(original_pin_token)) == 0,
           "getKeyAgreement should not rotate the runtime pin token");
    expect(memcmp(&app.pin_state.key_agreement, &original_key_agreement,
                  sizeof(original_key_agreement)) == 0,
           "getKeyAgreement should not rotate the runtime key agreement key");
}

static void test_get_pin_token_success_rotates_pin_token(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[96];
    uint8_t original_pin_token[ZF_PIN_TOKEN_LEN];
    const uint8_t *token = NULL;
    size_t token_len = 0;
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for getPinToken success");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for getPinToken success");
    app.storage = &storage;
    memset(app.pin_state.pin_token, 0x11, sizeof(app.pin_state.pin_token));
    memcpy(original_pin_token, app.pin_state.pin_token, sizeof(original_pin_token));

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_get_pin_token_request(
                                           request, sizeof(request), app.pin_state.pin_hash, true),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_SUCCESS,
           "correct PIN should return a pin token");
    expect(parse_pin_token_response(response, response_len, &token, &token_len),
           "getPinToken response should encode a token");
    expect(token_len == ZF_PIN_TOKEN_LEN, "returned pin token should have the expected length");
    expect(memcmp(app.pin_state.pin_token, original_pin_token, sizeof(original_pin_token)) != 0,
           "successful getPinToken should rotate the runtime pin token");
    expect(memcmp(token, app.pin_state.pin_token, ZF_PIN_TOKEN_LEN) == 0,
           "returned pin token should match the rotated runtime token");
    expect(app.pin_state.pin_token_active,
           "successful getPinToken should mark the runtime token active");
    expect(app.pin_state.pin_token_issued_at == g_fake_tick,
           "successful getPinToken should timestamp the runtime token");
    expect(app.pin_state.pin_token_permissions == (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
           "legacy getPinToken should grant default mc|ga permissions");
    expect(!app.pin_state.pin_token_permissions_rp_id_set,
           "legacy getPinToken should not bind an RP ID until first use");
    expect(g_approval_request_count == 0, "legacy getPinToken should not request local consent");
}

static void test_get_pin_token_experimental_2_1_requires_consent(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[96];
    const uint8_t *token = NULL;
    size_t token_len = 0;
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for 2.1 getPinToken consent");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for 2.1 getPinToken consent");
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_get_pin_token_request(
                                           request, sizeof(request), app.pin_state.pin_hash, true),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_SUCCESS,
           "experimental CTAP 2.1 getPinToken should return a pin token after consent");
    expect(parse_pin_token_response(response, response_len, &token, &token_len),
           "2.1 getPinToken response should encode a token");
    expect(token_len == ZF_PIN_TOKEN_LEN,
           "2.1 getPinToken should return the expected token length");
    expect(g_approval_request_count == 1, "2.1 getPinToken should request local consent");
    expect(app.pin_state.pin_token_permissions == (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
           "2.1 getPinToken should grant default mc|ga permissions");
    expect(app.pin_state.pin_token_permissions_managed,
           "2.1 getPinToken should issue a permission-managed token");
}

static void test_get_pin_token_protocol2_returns_iv_prefixed_token(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[128];
    uint8_t pin_hash_enc[ZF_PIN_ENCRYPTED_HASH_MAX_LEN] = {0xA5};
    const uint8_t *token = NULL;
    size_t token_len = 0;
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for protocol 2 getPinToken");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for protocol 2 getPinToken");
    memcpy(pin_hash_enc + ZF_PIN_PROTOCOL2_IV_LEN, app.pin_state.pin_hash, ZF_PIN_HASH_LEN);
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_get_pin_token_request_with_protocol(
                                           request, sizeof(request), ZF_PIN_PROTOCOL_V2,
                                           pin_hash_enc, sizeof(pin_hash_enc), true),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_SUCCESS,
           "protocol 2 getPinToken should return a token");
    expect(parse_pin_token_response(response, response_len, &token, &token_len),
           "protocol 2 getPinToken response should encode a token");
    expect(token_len == ZF_PIN_ENCRYPTED_TOKEN_MAX_LEN,
           "protocol 2 tokenEnc should include the CBC IV");
    expect(memcmp(token + ZF_PIN_PROTOCOL2_IV_LEN, app.pin_state.pin_token, ZF_PIN_TOKEN_LEN) == 0,
           "protocol 2 tokenEnc payload should encrypt the runtime token");
}

static void test_client_pin_protocol2_requires_experimental_profile(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t pin_hash_enc[ZF_PIN_ENCRYPTED_HASH_MAX_LEN] = {0xA5};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for default-profile protocol 2 rejection");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for default-profile protocol 2 rejection");
    memcpy(pin_hash_enc + ZF_PIN_PROTOCOL2_IV_LEN, app.pin_state.pin_hash, ZF_PIN_HASH_LEN);
    app.storage = &storage;

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_get_pin_token_request_with_protocol(
                                           request, sizeof(request), ZF_PIN_PROTOCOL_V2,
                                           pin_hash_enc, sizeof(pin_hash_enc), true),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "default CTAP 2.0 profile should reject unadvertised protocol 2");
    expect(!app.pin_state.pin_token_active,
           "default-profile protocol 2 rejection should not activate a token");
}

static void test_get_pin_token_decrypt_failure_consumes_retry(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t original_public_x = 0;
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for getPinToken failure");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for getPinToken failure");
    app.storage = &storage;
    app.pin_state.pin_retries = 2;
    original_public_x = app.pin_state.key_agreement.public_x[0];
    g_fail_crypto_decrypt = true;

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_get_pin_token_request(
                                           request, sizeof(request), app.pin_state.pin_hash, true),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_PIN_INVALID,
           "pinHash decrypt failure should consume a retry");
    expect(app.pin_state.pin_retries == 1, "pinHash decrypt failure should decrement retries");
    expect(app.pin_state.key_agreement.public_x[0] != original_public_x,
           "pinHash decrypt failure should regenerate key agreement");
}

static void test_get_pin_token_rejects_permissions_fields(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for permissions rejection");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for permissions rejection");
    app.storage = &storage;

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x05, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_MC, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "legacy getPinToken should reject permissions");
    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x05, app.pin_state.pin_hash, false, 0, "example.com"),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "legacy getPinToken should reject rpId");
}

static void test_client_pin_permissions_subcommand_requires_permissions(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for permissions missing-parameter test");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for permissions missing-parameter test");
    app.storage = &storage;

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, false, 0, "example.com"),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_SUBCOMMAND,
           "CTAP 2.0 profile should not expose the 0x09 permissions-token subcommand");
}

static void test_client_pin_permissions_subcommand_rejects_zero_permissions(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for zero permissions test");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for zero permissions test");
    app.storage = &storage;

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, true, 0, "example.com"),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_SUBCOMMAND,
           "CTAP 2.0 profile should not expose the 0x09 permissions-token subcommand");
}

static void test_client_pin_permissions_subcommand_rejects_unsupported_permissions(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for unsupported permissions test");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for unsupported permissions test");
    app.storage = &storage;

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, true, 0x04U, NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_SUBCOMMAND,
           "CTAP 2.0 profile should not expose the 0x09 permissions-token subcommand");
}

static void test_client_pin_permissions_subcommand_requires_rp_id_for_mc_ga(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for permissions rpId test");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for permissions rpId test");
    app.storage = &storage;

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_MC, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_INVALID_SUBCOMMAND,
           "CTAP 2.0 profile should not expose the 0x09 permissions-token subcommand");
}

static void test_client_pin_permissions_subcommand_experimental_validates_parameters(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for 2.1 permission validation");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for 2.1 permission validation");
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);

    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, false, 0, "example.com"),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_MISSING_PARAMETER,
           "2.1 0x09 should require the permissions field");
    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, true, 0, "example.com"),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "2.1 0x09 should reject zero permissions");
    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_MC, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_MISSING_PARAMETER,
           "2.1 0x09 should require rpId for mc and ga permissions");
    expect(zerofido_pin_handle_command(
               &app, request,
               encode_client_pin_request_with_permissions(
                   request, sizeof(request), 0x09, app.pin_state.pin_hash, true, 0x40U, NULL),
               response, sizeof(response), &response_len) == ZF_CTAP_ERR_INVALID_PARAMETER,
           "2.1 0x09 should reject unknown permission bits as invalid parameters");
    expect(g_approval_request_count == 0,
           "invalid 2.1 0x09 requests should fail before local consent");
    expect(!app.pin_state.pin_token_active,
           "invalid 2.1 0x09 requests should not mint a pinUvAuthToken");
}

static void test_client_pin_permissions_subcommand_stores_permissions_and_rp_id(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    const uint8_t *token = NULL;
    size_t token_len = 0;
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for 0x09 token request");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for 0x09 token request");
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_MC, "example.com"),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_SUCCESS,
           "experimental CTAP 2.1 profile should issue a permission-scoped pinUvAuthToken");
    expect(response_len > 0, "0x09 should return a CBOR token response");
    expect(parse_pin_token_response(response, response_len, &token, &token_len),
           "0x09 should encode a token response");
    expect(token_len == ZF_PIN_TOKEN_LEN, "0x09 should return the expected token length");
    expect(app.pin_state.pin_token_active, "0x09 should activate the runtime PIN token");
    expect(app.pin_state.pin_token_permissions == ZF_PIN_PERMISSION_MC,
           "0x09 should store the requested permission bits");
    expect(app.pin_state.pin_token_permissions_scoped,
           "0x09 should mark the runtime token as permission-scoped");
    expect(app.pin_state.pin_token_permissions_managed,
           "0x09 should mark the runtime token as permission-managed");
    expect(app.pin_state.pin_token_permissions_rp_id_set, "0x09 should bind the requested RP ID");
    expect(strcmp(app.pin_state.pin_token_permissions_rp_id, "example.com") == 0,
           "0x09 should persist the requested RP ID");
    expect(g_approval_request_count == 1,
           "0x09 should require local consent before issuing a permission token");
}

static void test_client_pin_permissions_subcommand_issued_token_consumes_mc_after_up(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t token_request[256];
    uint8_t token_response[64];
    uint8_t ctap_request[256];
    uint8_t ctap_response[512];
    uint8_t pin_auth[32];
    size_t token_response_len = 0;
    size_t ctap_response_len = 0;
    static const uint8_t make_credential_client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for issued 0x09 token");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for issued 0x09 token");
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_fido2_1_experimental(&app);

    expect(zerofido_pin_handle_command(
               &app, token_request,
               encode_client_pin_request_with_permissions(token_request, sizeof(token_request),
                                                          0x09, app.pin_state.pin_hash, true,
                                                          ZF_PIN_PERMISSION_MC, "example.com"),
               token_response, sizeof(token_response), &token_response_len) == ZF_CTAP_SUCCESS,
           "2.1 0x09 should mint an mc-scoped token");
    expect(app.pin_state.pin_token_permissions == ZF_PIN_PERMISSION_MC,
           "issued 0x09 token should start with mc permission");
    expect(app.pin_state.pin_token_permissions_managed,
           "issued 0x09 token should be permission-managed");
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 make_credential_client_data_hash,
                                 sizeof(make_credential_client_data_hash), pin_auth),
           "derive makeCredential pinAuth from issued 0x09 token");

    ctap_response_len =
        zerofido_handle_ctap2(&app, 0x01020304, ctap_request,
                              encode_make_credential_ctap_request_with_pin_auth(
                                  ctap_request, sizeof(ctap_request), false, false, true, pin_auth,
                                  ZF_PIN_AUTH_LEN, true, false, NULL, 0),
                              ctap_response, sizeof(ctap_response));

    expect(ctap_response_len > 1, "makeCredential should accept the issued 0x09 token once");
    expect(ctap_response[0] == ZF_CTAP_SUCCESS,
           "makeCredential should succeed with the issued 0x09 token");
    expect(app.pin_state.pin_token_permissions == 0,
           "UP-tested makeCredential should consume the issued mc permission");
    expect(!app.pin_state.pin_token_permissions_rp_id_set,
           "consumed 0x09 token should clear the RP binding");

    ctap_response_len =
        zerofido_handle_ctap2(&app, 0x01020304, ctap_request,
                              encode_make_credential_ctap_request_with_pin_auth(
                                  ctap_request, sizeof(ctap_request), false, false, true, pin_auth,
                                  ZF_PIN_AUTH_LEN, true, false, NULL, 0),
                              ctap_response, sizeof(ctap_response));

    expect(ctap_response_len == 1, "reused consumed 0x09 token should return status only");
    expect(ctap_response[0] == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "consumed 0x09 token should not authorize another makeCredential");
    expect(g_approval_request_count == 2,
           "consumed 0x09 token replay should fail before another approval prompt");
}

static void test_client_pin_permissions_subcommand_denied_consent_does_not_issue_token(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for denied permission-token consent");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for denied permission-token consent");
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);
    g_approval_result = false;
    g_approval_state = ZfApprovalDenied;

    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_MC, "example.com"),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_OPERATION_DENIED,
           "experimental CTAP 2.1 0x09 should fail when local consent is denied");
    expect(g_approval_request_count == 1, "denied 0x09 should request local consent once");
    expect(!app.pin_state.pin_token_active, "denied 0x09 should not activate a runtime PIN token");
    expect(app.pin_state.pin_token_permissions == 0,
           "denied 0x09 should not store requested permissions");
    expect(response_len == 0, "denied 0x09 should not return a token body");
}

static void test_client_pin_permissions_subcommand_rejects_unsupported_be_permission(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for unsupported BE permission");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for unsupported BE permission");
    app.storage = &storage;
    test_enable_fido2_1_experimental(&app);

    expect(
        zerofido_pin_handle_command(
            &app, request,
            encode_client_pin_request_with_permissions(
                request, sizeof(request), 0x09, app.pin_state.pin_hash, true,
                ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA | ZF_PIN_PERMISSION_BE, "example.com"),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_UNAUTHORIZED_PERMISSION,
        "experimental CTAP 2.1 0x09 should reject unsupported bioEnrollment permission");
    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_CM, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_UNAUTHORIZED_PERMISSION,
           "experimental CTAP 2.1 0x09 should reject unsupported credentialManagement permission");
    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_LBW, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_UNAUTHORIZED_PERMISSION,
           "experimental CTAP 2.1 0x09 should reject unsupported largeBlobWrite permission");
    expect(zerofido_pin_handle_command(&app, request,
                                       encode_client_pin_request_with_permissions(
                                           request, sizeof(request), 0x09, app.pin_state.pin_hash,
                                           true, ZF_PIN_PERMISSION_ACFG, NULL),
                                       response, sizeof(response),
                                       &response_len) == ZF_CTAP_ERR_UNAUTHORIZED_PERMISSION,
           "experimental CTAP 2.1 0x09 should reject unsupported authenticatorConfig permission");
    expect(!app.pin_state.pin_token_active,
           "unsupported BE permission should not mint a pinUvAuthToken");
    expect(app.pin_state.pin_token_permissions == 0,
           "unsupported BE permission should not store token permissions");
}

static void test_pin_auth_rejects_expired_pin_token(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0x5A};
    uint8_t pin_auth[32];
    bool uv_verified = false;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for token-expiry test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for token-expiry test");
    mark_pin_token_issued(&state);
    state.pin_token_issued_at = g_fake_tick - ZF_PIN_TOKEN_TIMEOUT_MS;
    expect(zf_crypto_hmac_sha256(state.pin_token, sizeof(state.pin_token), client_data_hash,
                                 sizeof(client_data_hash), pin_auth),
           "derive pinAuth for expired token");

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_LEN, true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_TOKEN_EXPIRED,
           "expired pin token should return PIN_TOKEN_EXPIRED");
    expect(!state.pin_token_active, "expired pin token should be cleared after rejection");
    expect(!uv_verified, "expired pin token should not set UV");
}

static void test_pin_auth_protocol2_accepts_full_hmac(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0x7B};
    uint8_t pin_auth[32];
    bool uv_verified = false;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for protocol 2 pinAuth");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for protocol 2 pinAuth");
    mark_pin_token_issued(&state);
    state.pin_token_permissions = ZF_PIN_PERMISSION_MC;
    expect(zf_crypto_hmac_sha256(state.pin_token, sizeof(state.pin_token), client_data_hash,
                                 sizeof(client_data_hash), pin_auth),
           "derive protocol 2 pinAuth");

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_MAX_LEN, true, ZF_PIN_PROTOCOL_V2, NULL,
                                     ZF_PIN_PERMISSION_MC, &uv_verified) == ZF_CTAP_SUCCESS,
           "protocol 2 pinAuth should accept the full HMAC");
    expect(uv_verified, "protocol 2 pinAuth should set UV");
}

static void test_legacy_pin_token_allows_reuse_without_rp_binding(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0x5A};
    uint8_t pin_auth[32];
    bool uv_verified = false;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for legacy token rp scope");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for legacy token rp scope");
    memset(state.pin_token, 0x44, sizeof(state.pin_token));
    state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    mark_pin_token_issued(&state);
    expect(zf_crypto_hmac_sha256(state.pin_token, sizeof(state.pin_token), client_data_hash,
                                 sizeof(client_data_hash), pin_auth),
           "derive pinAuth for legacy token rp scope");

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_LEN, true, 1, "example.com", ZF_PIN_PERMISSION_MC,
                                     &uv_verified) == ZF_CTAP_SUCCESS,
           "legacy getPinToken should authorize the first RP without binding it");
    expect(uv_verified, "successful legacy token authorization should set UV");
    expect(!state.pin_token_permissions_rp_id_set,
           "legacy getPinToken should not bind an RP ID on first use");
    expect(state.pin_token_permissions == (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
           "CTAP 2.0 legacy token should keep mc/ga permissions after UP use");

    uv_verified = false;
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_LEN, true, 1, "other.example",
                                     ZF_PIN_PERMISSION_GA, &uv_verified) == ZF_CTAP_SUCCESS,
           "CTAP 2.0 legacy token should remain reusable for another RP");
    expect(uv_verified, "successful legacy token reuse should set UV");
}

static void test_pin_auth_rejects_missing_required_permission(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0x6B};
    uint8_t pin_auth[32];
    bool uv_verified = false;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for permission check");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for permission check");
    memset(state.pin_token, 0x55, sizeof(state.pin_token));
    state.pin_token_permissions = ZF_PIN_PERMISSION_MC;
    state.pin_token_permissions_scoped = true;
    state.pin_token_permissions_rp_id_set = true;
    strcpy(state.pin_token_permissions_rp_id, "example.com");
    mark_pin_token_issued(&state);
    expect(zf_crypto_hmac_sha256(state.pin_token, sizeof(state.pin_token), client_data_hash,
                                 sizeof(client_data_hash), pin_auth),
           "derive pinAuth for permission check");

    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_LEN, true, 1, "example.com", ZF_PIN_PERMISSION_GA,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "pinAuth should reject tokens missing the required permission");
    expect(!uv_verified, "missing permission should not set UV");
}

static void test_change_pin_pin_hash_decrypt_failure_consumes_retry(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for changePin failure");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for changePin failure");
    app.storage = &storage;
    app.pin_state.pin_retries = 2;
    app.pin_state.pin_consecutive_mismatches = 1;
    expect(zf_pin_persist_state(&storage, &app.pin_state), "persist retry state before failure");
    memcpy(new_pin_block, "5678", 4);
    g_fail_crypto_decrypt = true;

    expect(
        zerofido_pin_handle_command(
            &app, request,
            encode_client_pin_change_pin_request(request, sizeof(request), app.pin_state.pin_hash,
                                                 new_pin_block, sizeof(new_pin_block)),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_INVALID,
        "pinHash decrypt failure during changePin should consume a retry");
    expect(app.pin_state.pin_retries == 1,
           "changePin pinHash decrypt failure should decrement retries");
    expect(app.pin_state.pin_consecutive_mismatches == 2,
           "changePin pinHash decrypt failure should count as a mismatch");
}

static void test_change_pin_new_pin_decrypt_failure_returns_pin_auth_invalid(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[256];
    uint8_t response[64];
    uint8_t new_pin_block[64] = {0};
    size_t response_len = 0;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &app.pin_state),
           "init PIN state for changePin decrypt failure");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for changePin decrypt failure");
    app.storage = &storage;
    memcpy(new_pin_block, "5678", 4);
    g_fail_crypto_decrypt_after = 1;

    expect(
        zerofido_pin_handle_command(
            &app, request,
            encode_client_pin_change_pin_request(request, sizeof(request), app.pin_state.pin_hash,
                                                 new_pin_block, sizeof(new_pin_block)),
            response, sizeof(response), &response_len) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
        "changePin newPinEnc decrypt failure should return pin auth invalid");
}

static void test_pin_init_cleans_temp_file(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};

    test_storage_reset();
    g_pin_temp_exists = true;
    g_pin_temp_size = 4;
    memcpy(g_pin_temp_data, "temp", 4);

    expect(zerofido_pin_init(&storage, &state), "init PIN state with temp file");
    expect(!g_pin_temp_exists, "pin init should clean temp file");
}

static void test_store_resident_records_for_same_user_coexist_after_reload(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    store.records = store_records;
    ZfCredentialStore reloaded = {0};
    ZfCredentialIndexEntry reloaded_records[ZF_MAX_CREDENTIALS] = {0};
    reloaded.records = reloaded_records;
    ZfCredentialRecord first = {0};
    ZfCredentialRecord second = {0};
    ZfCredentialRecord loaded = {0};

    test_storage_reset();
    memset(first.credential_id, 0x11, sizeof(first.credential_id));
    first.credential_id_len = sizeof(first.credential_id);
    zf_store_record_format_hex_encode(first.credential_id, first.credential_id_len,
                                      first.file_name);
    strcpy(first.rp_id, "example.com");
    memcpy(first.user_id, "user-1", 6);
    first.user_id_len = 6;
    first.resident_key = true;
    first.in_use = true;
    first.created_at = 1;

    memset(second.credential_id, 0x22, sizeof(second.credential_id));
    second.credential_id_len = sizeof(second.credential_id);
    zf_store_record_format_hex_encode(second.credential_id, second.credential_id_len,
                                      second.file_name);
    strcpy(second.rp_id, "example.com");
    memcpy(second.user_id, "user-1", 6);
    second.user_id_len = 6;
    second.resident_key = true;
    second.in_use = true;
    second.created_at = 2;

    expect(test_zf_store_add_record(&storage, &store, &first), "write original resident record");
    expect(test_zf_store_add_record(&storage, &store, &second),
           "second resident record for the same user should coexist");
    expect(store.count == 2, "coexisting resident records should both remain in memory");
    expect(test_zf_store_record_format_load_record(&storage, first.file_name, &loaded),
           "original resident record should remain reloadable");
    expect(memcmp(loaded.credential_id, first.credential_id, sizeof(first.credential_id)) == 0,
           "loaded original record should keep its credential id");
    expect(test_zf_store_record_format_load_record(&storage, second.file_name, &loaded),
           "second resident record should load from its own file");
    expect(memcmp(loaded.credential_id, second.credential_id, sizeof(second.credential_id)) == 0,
           "loaded resident record should keep its credential id");
    expect(test_zf_store_init(&storage, &reloaded), "reloading store should preserve both records");
    expect(reloaded.count == 2, "store init must not collapse resident credentials for one user");
}

static void test_store_wipe_app_data_clears_credentials_and_pin_state(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    store.records = store_records;
    ZfCredentialStore reloaded = {0};
    ZfCredentialIndexEntry reloaded_records[ZF_MAX_CREDENTIALS] = {0};
    reloaded.records = reloaded_records;
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};
    ZfCredentialRecord record = {0};

    test_storage_reset();
    expect(test_zf_store_init(&storage, &store), "init store before app-data wipe");
    expect(zerofido_pin_init(&storage, &state), "init PIN state before app-data wipe");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN before app-data wipe");
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential before app-data wipe");
    expect(test_zf_store_add_record(&storage, &store, &record),
           "persist credential before app-data wipe");
    expect(zf_store_count_saved(&store) == 1, "store should contain one credential before wipe");
    expect(g_pin_file_exists, "PIN file should exist before app-data wipe");

    expect(zf_store_wipe_app_data(&storage), "wipe ZeroFIDO app data");
    expect(g_remove_attempted_pin_v2_file, "app-data wipe should remove current v2 PIN file");
    expect(g_remove_attempted_pin_v2_temp, "app-data wipe should remove current v2 PIN temp file");
    expect(!g_pin_file_exists, "PIN file should be removed by app-data wipe");
    expect(test_zf_store_init(&storage, &reloaded), "re-init store after app-data wipe");
    expect(zf_store_count_saved(&reloaded) == 0, "store should be empty after app-data wipe");
    expect(zerofido_pin_init(&storage, &restored), "re-init PIN state after app-data wipe");
    expect(!restored.pin_set, "PIN should be cleared after app-data wipe");
}

static size_t encode_make_credential_ctap_request(uint8_t *buffer, size_t capacity) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP makeCredential encoder");
    expect(zf_cbor_encode_map(&enc, 4) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode CTAP makeCredential request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_make_credential_ctap_request_with_unknown_true_option(uint8_t *buffer,
                                                                           size_t capacity) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP makeCredential unknown option encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "makeTea") &&
               zf_cbor_encode_bool(&enc, true),
           "encode CTAP makeCredential request with unknown true option");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_make_credential_ctap_request_with_attestation_formats(
    uint8_t *buffer, size_t capacity, const char *first_format, const char *second_format) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};
    size_t formats_count = second_format ? 2U : 1U;

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP makeCredential attestation preference encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 11) &&
               zf_cbor_encode_array(&enc, formats_count) &&
               zf_cbor_encode_text(&enc, first_format) &&
               (!second_format || zf_cbor_encode_text(&enc, second_format)),
           "encode CTAP makeCredential request with attestation preference");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_resident_make_credential_ctap_request(uint8_t *buffer, size_t capacity) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP resident makeCredential encoder");
    expect(zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "rk") &&
               zf_cbor_encode_bool(&enc, true),
           "encode CTAP resident makeCredential request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_resident_make_credential_ctap_request_with_cred_protect(uint8_t *buffer,
                                                                             size_t capacity,
                                                                             uint8_t cred_protect) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP resident makeCredential credProtect encoder");
    expect(zf_cbor_encode_map(&enc, 6) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "credProtect") &&
               zf_cbor_encode_uint(&enc, cred_protect) && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "rk") &&
               zf_cbor_encode_bool(&enc, true),
           "encode CTAP resident makeCredential credProtect request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_resident_make_credential_ctap_request_with_hmac_secret(uint8_t *buffer,
                                                                            size_t capacity) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP resident makeCredential hmac-secret encoder");
    expect(zf_cbor_encode_map(&enc, 6) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 6) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "hmac-secret") &&
               zf_cbor_encode_bool(&enc, true) && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "rk") &&
               zf_cbor_encode_bool(&enc, true),
           "encode CTAP resident makeCredential hmac-secret request");
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_make_credential_ctap_request_with_pin_auth_protocol(
    uint8_t *buffer, size_t capacity, bool include_uv, bool uv_value, bool include_pin_auth,
    const uint8_t *pin_auth, size_t pin_auth_len, bool include_pin_protocol, uint64_t pin_protocol,
    bool include_exclude, const uint8_t *exclude_id, size_t exclude_len) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};
    size_t pair_count = 4;

    if (include_uv) {
        pair_count++;
    }
    if (include_pin_auth) {
        pair_count++;
    }
    if (include_pin_protocol) {
        pair_count++;
    }
    if (include_exclude) {
        pair_count++;
    }

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP makeCredential pinAuth encoder");
    expect(zf_cbor_encode_map(&enc, pair_count) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key"),
           "encode CTAP makeCredential pinAuth request");
    if (include_uv) {
        expect(zf_cbor_encode_uint(&enc, 7) && zf_cbor_encode_map(&enc, 1) &&
                   zf_cbor_encode_text(&enc, "uv") && zf_cbor_encode_bool(&enc, uv_value),
               "encode makeCredential uv option");
    }
    if (include_pin_auth) {
        expect(zf_cbor_encode_uint(&enc, 8) && zf_cbor_encode_bytes(&enc, pin_auth, pin_auth_len),
               "encode makeCredential pinAuth");
    }
    if (include_pin_protocol) {
        expect(zf_cbor_encode_uint(&enc, 9) && zf_cbor_encode_uint(&enc, pin_protocol),
               "encode makeCredential pinProtocol");
    }
    if (include_exclude) {
        expect(zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_array(&enc, 1) &&
                   zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
                   zf_cbor_encode_bytes(&enc, exclude_id, exclude_len) &&
                   zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key"),
               "encode makeCredential excludeList");
    }
    return zf_cbor_encoder_size(&enc) + 1;
}

static size_t encode_make_credential_ctap_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, bool include_uv, bool uv_value, bool include_pin_auth,
    const uint8_t *pin_auth, size_t pin_auth_len, bool include_pin_protocol, bool include_exclude,
    const uint8_t *exclude_id, size_t exclude_len) {
    return encode_make_credential_ctap_request_with_pin_auth_protocol(
        buffer, capacity, include_uv, uv_value, include_pin_auth, pin_auth, pin_auth_len,
        include_pin_protocol, ZF_PIN_PROTOCOL_V1, include_exclude, exclude_id, exclude_len);
}

static size_t encode_resident_make_credential_ctap_request_with_pin_auth(
    uint8_t *buffer, size_t capacity, bool include_uv, bool uv_value, bool include_pin_auth,
    const uint8_t *pin_auth, size_t pin_auth_len, bool include_pin_protocol) {
    ZfCborEncoder enc;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t user_id[] = {0xAA};
    size_t pair_count = 5;
    size_t options_count = 1;

    if (include_pin_auth) {
        pair_count++;
    }
    if (include_pin_protocol) {
        pair_count++;
    }
    if (include_uv) {
        options_count++;
    }

    buffer[0] = ZfCtapeCmdMakeCredential;
    expect(zf_cbor_encoder_init(&enc, buffer + 1, capacity - 1),
           "init CTAP resident makeCredential pinAuth encoder");
    expect(zf_cbor_encode_map(&enc, pair_count) && zf_cbor_encode_uint(&enc, 1) &&
               zf_cbor_encode_bytes(&enc, client_data_hash, sizeof(client_data_hash)) &&
               zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_map(&enc, 1) &&
               zf_cbor_encode_text(&enc, "id") && zf_cbor_encode_text(&enc, "example.com") &&
               zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 2) &&
               zf_cbor_encode_text(&enc, "id") &&
               zf_cbor_encode_bytes(&enc, user_id, sizeof(user_id)) &&
               zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, "alice") &&
               zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_array(&enc, 1) &&
               zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
               zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
               zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 7) &&
               zf_cbor_encode_map(&enc, options_count) && zf_cbor_encode_text(&enc, "rk") &&
               zf_cbor_encode_bool(&enc, true),
           "encode CTAP resident makeCredential pinAuth request");
    if (include_uv) {
        expect(zf_cbor_encode_text(&enc, "uv") && zf_cbor_encode_bool(&enc, uv_value),
               "encode resident makeCredential uv option");
    }
    if (include_pin_auth) {
        expect(zf_cbor_encode_uint(&enc, 8) && zf_cbor_encode_bytes(&enc, pin_auth, pin_auth_len),
               "encode resident makeCredential pinAuth");
    }
    if (include_pin_protocol) {
        expect(zf_cbor_encode_uint(&enc, 9) && zf_cbor_encode_uint(&enc, 1),
               "encode resident makeCredential pinProtocol");
    }
    return zf_cbor_encoder_size(&enc) + 1;
}

static void test_ctap_error_response_omits_body_when_store_add_fails(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    g_storage_fail_rename_match = ".tmp";
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "CTAP error response should not include a stale body");
    expect(response[0] == ZF_CTAP_ERR_KEY_STORE_FULL,
           "MakeCredential store failure should surface");
}

static void test_make_credential_rejects_local_maintenance_window(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.maintenance_busy = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "maintenance rejection should only return a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "MakeCredential should reject while local maintenance owns the state");
    expect(g_approval_request_count == 0,
           "maintenance rejection should happen before any approval prompt");
}

static void test_make_credential_empty_pin_auth_requires_pin_protocol(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true,
                                             (const uint8_t *)"", 0, false, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len == 1, "missing pinProtocol should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_MISSING_PARAMETER,
           "empty pinAuth probes must still require pinProtocol");
    expect(g_approval_request_count == 0,
           "missing pinProtocol should fail before any approval prompt");
}

static void test_get_assertion_empty_pin_auth_requires_pin_protocol(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, (const uint8_t *)"", 0, false),
        response, sizeof(response));

    expect(response_len == 1, "missing pinProtocol should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_MISSING_PARAMETER,
           "GetAssertion empty pinAuth probes must still require pinProtocol");
    expect(g_approval_request_count == 0,
           "GetAssertion missing pinProtocol should fail before approval");
}

static void test_make_credential_empty_pin_auth_probe_returns_pin_status_after_touch(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true,
                                             (const uint8_t *)"", 0, true, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len == 1, "empty pinAuth probe should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_PIN_NOT_SET,
           "empty pinAuth probe should return PIN_NOT_SET when no PIN is configured");
    expect(g_approval_request_count == 1,
           "empty pinAuth probe should still require one approval/touch");

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true,
                                             (const uint8_t *)"", 0, true, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len == 1, "empty pinAuth probe with PIN should return only status");
    expect(response[0] == ZF_CTAP_ERR_PIN_INVALID,
           "empty pinAuth probe should return PIN_INVALID when a PIN is configured");
    expect(g_approval_request_count == 1,
           "empty pinAuth probe with PIN should still require one approval/touch");
}

static void test_get_assertion_empty_pin_auth_probe_returns_pin_status_after_touch(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, (const uint8_t *)"", 0, true),
        response, sizeof(response));

    expect(response_len == 1, "empty pinAuth probe should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_PIN_NOT_SET,
           "GetAssertion empty pinAuth probe should return PIN_NOT_SET when no PIN is configured");
    expect(g_approval_request_count == 1,
           "GetAssertion empty pinAuth probe should still require one approval/touch");

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, (const uint8_t *)"", 0, true),
        response, sizeof(response));

    expect(response_len == 1, "empty pinAuth probe with PIN should return only status");
    expect(response[0] == ZF_CTAP_ERR_PIN_INVALID,
           "GetAssertion empty pinAuth probe should return PIN_INVALID when a PIN is configured");
    expect(g_approval_request_count == 1,
           "GetAssertion empty pinAuth probe with PIN should still require one approval/touch");
}

static void test_get_assertion_uv_without_pin_auth_returns_unsupported_option(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_get_assertion_ctap_request_with_pin_auth(
                                  request, sizeof(request), true, true, false, NULL, 0, false),
                              response, sizeof(response));

    expect(response_len == 1, "unsupported uv request should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_UNSUPPORTED_OPTION,
           "GetAssertion uv=true without pinAuth should return UNSUPPORTED_OPTION");
    expect(g_approval_request_count == 0,
           "GetAssertion uv=true without pinAuth should fail before approval");
}

static void test_make_credential_uv_without_pin_auth_returns_unsupported_option(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_make_credential_ctap_request_with_pin_auth(request, sizeof(request), true, true,
                                                          false, NULL, 0, false, false, NULL, 0),
        response, sizeof(response));

    expect(response_len == 1, "unsupported uv makeCredential should return only status");
    expect(response[0] == ZF_CTAP_ERR_UNSUPPORTED_OPTION,
           "MakeCredential uv=true without pinAuth should return UNSUPPORTED_OPTION");
    expect(g_approval_request_count == 0,
           "MakeCredential uv=true without pinAuth should fail before approval");
}

static void test_make_credential_pin_auth_takes_precedence_over_uv(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x5A, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive makeCredential pinAuth");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), true, true, true, pin_auth,
                                             ZF_PIN_AUTH_LEN, true, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len > 1, "valid pinAuth plus uv=true should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "pinAuth should take precedence over uv=true on MakeCredential");
    expect(g_approval_request_count == 1,
           "successful MakeCredential should still request approval");
}

static void test_make_credential_pin_auth_clears_permission_scoped_token_after_up(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x66, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC;
    app.pin_state.pin_token_permissions_scoped = true;
    app.pin_state.pin_token_permissions_managed = true;
    app.pin_state.pin_token_permissions_rp_id_set = true;
    strcpy(app.pin_state.pin_token_permissions_rp_id, "example.com");
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive makeCredential pinAuth for permission-scoped token");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true, pin_auth,
                                             ZF_PIN_AUTH_LEN, true, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len > 1, "permission-scoped makeCredential should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "permission-scoped makeCredential should return success");
    expect(app.pin_state.pin_token_active,
           "permission-scoped token should remain active after makeCredential");
    expect(app.pin_state.pin_token_permissions == 0,
           "makeCredential should clear mc/ga token permissions after UP");
    expect(!app.pin_state.pin_token_permissions_rp_id_set,
           "makeCredential should clear the consumed permission RP binding");
    expect(app.pin_state.pin_token_permissions_rp_id[0] == '\0',
           "makeCredential should clear the consumed permission RP ID value");
}

static void test_make_credential_legacy_pin_token_keeps_mc_ga_after_up(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x6A, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive makeCredential pinAuth for legacy token");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true, pin_auth,
                                             ZF_PIN_AUTH_LEN, true, false, NULL, 0),
                                         response, sizeof(response));

    expect(response_len > 1, "legacy-token makeCredential should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "legacy-token makeCredential should return success");
    expect(app.pin_state.pin_token_permissions == (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
           "CTAP 2.0 legacy getPinToken permissions should survive successful UP");
}

static void test_make_credential_requires_pin_auth_when_pin_is_set(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1,
           "MakeCredential without pinAuth should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_PIN_REQUIRED,
           "MakeCredential without pinAuth should require PIN when a PIN is set");
    expect(g_approval_request_count == 0,
           "MakeCredential without pinAuth should fail before approval");
}

static void test_make_credential_auto_accept_bypasses_approval_prompt(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "auto-accept makeCredential should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "auto-accept makeCredential should return success");
    expect(g_approval_request_count == 0,
           "auto-accept makeCredential should bypass the approval prompt");
}

static void test_make_credential_unknown_option_succeeds(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_make_credential_ctap_request_with_unknown_true_option(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "makeCredential with unknown option should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "makeCredential should ignore unknown true options");
}

static void test_make_credential_returns_packed_attestation(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "MakeCredential should return a CTAP response body");
    expect(response[0] == ZF_CTAP_SUCCESS, "MakeCredential should return success");
    expect(parse_make_credential_packed_attestation(response + 1, response_len - 1),
           "MakeCredential should return packed attestation with one leaf certificate");
}

static void test_make_credential_runtime_none_returns_none_attestation(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);
    app.runtime_config.attestation_mode = ZfAttestationModeNone;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "runtime none makeCredential should return a CTAP response body");
    expect(response[0] == ZF_CTAP_SUCCESS, "runtime none makeCredential should return success");
    expect(parse_make_credential_none_attestation(response + 1, response_len - 1),
           "runtime none mode should return fmt none with empty attStmt");
}

static void test_make_credential_attestation_preference_overrides_runtime_default(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_make_credential_ctap_request_with_attestation_formats(
                                  request, sizeof(request), "none", NULL),
                              response, sizeof(response));

    expect(response_len > 1, "none attestation preference should return a CTAP response body");
    expect(response[0] == ZF_CTAP_SUCCESS, "none attestation preference should return success");
    expect(parse_make_credential_none_attestation(response + 1, response_len - 1),
           "single none attestation preference should omit packed attestation");
}

static void test_make_credential_attestation_preference_uses_lowest_supported_index(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);
    app.runtime_config.attestation_mode = ZfAttestationModeNone;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_make_credential_ctap_request_with_attestation_formats(
                                  request, sizeof(request), "packed", "none"),
                              response, sizeof(response));

    expect(response_len > 1, "packed-first attestation preference should return a CTAP body");
    expect(response[0] == ZF_CTAP_SUCCESS, "packed-first attestation preference should succeed");
    expect(parse_make_credential_packed_attestation(response + 1, response_len - 1),
           "packed should win when it is the lowest-index supported preference");
}

static void test_make_credential_response_does_not_downgrade_required_packed(void) {
    ZfMakeCredentialResponseScratch scratch;
    ZfCredentialRecord record = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0};
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    strcpy(record.rp_id, "example.com");
    memset(record.credential_id, 0x42, sizeof(record.credential_id));
    record.credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(record.public_x, 0x11, sizeof(record.public_x));
    memset(record.public_y, 0x22, sizeof(record.public_y));

    g_attestation_ensure_ready = false;
    expect(zf_ctap_build_packed_make_credential_response_with_scratch(
               &scratch, record.rp_id, &record, client_data_hash, false, false, false, response,
               sizeof(response), &response_len) == ZF_CTAP_ERR_OTHER,
           "required packed attestation should fail when assets are unavailable");

    response_len = 0;
    expect(zf_ctap_build_none_make_credential_response_with_scratch(
               &scratch, record.rp_id, &record, false, false, false, response, sizeof(response),
               &response_len) == ZF_CTAP_SUCCESS,
           "explicit none attestation should remain available");
    expect(parse_make_credential_none_attestation(response, response_len),
           "explicit none attestation should encode fmt none with empty attStmt");
}

static void test_make_credential_nfc_auto_accept_keeps_uv_clear(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    uint8_t flags = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.transport_auto_accept_transaction = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_make_credential_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "NFC auto-accept makeCredential should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "NFC auto-accept makeCredential should return success");
    expect(parse_make_credential_auth_flags(response + 1, response_len - 1, &flags),
           "NFC makeCredential response should expose authenticator data flags");
    expect((flags & 0x04U) == 0U,
           "NFC auto-accept makeCredential should not fake user verification");
    expect(g_approval_request_count == 0,
           "NFC auto-accept makeCredential should bypass the approval prompt");
    expect(g_status_update_count == 0,
           "NFC auto-accept makeCredential should not update UI status before the APDU response");
}

static void test_make_credential_nfc_auto_accept_rejects_uv_option_without_pin(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.transport_auto_accept_transaction = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_make_credential_ctap_request_with_pin_auth(request, sizeof(request), true, true,
                                                          false, NULL, 0, false, false, NULL, 0),
        response, sizeof(response));

    expect(response_len == 1, "NFC auto-accept uv=true makeCredential should return only status");
    expect(response[0] == ZF_CTAP_ERR_UNSUPPORTED_OPTION,
           "NFC auto-accept must not satisfy uv=true without real UV/PIN support");
    expect(g_approval_request_count == 0,
           "NFC auto-accept uv=true rejection should happen before approval");
}

static void test_get_assertion_pin_auth_takes_precedence_over_uv(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    ZfCredentialRecord record = {0};
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x33, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive getAssertion pinAuth");

    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    zf_store_index_entry_from_record(&record, &app.store.records[0]);
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), true, true, true,
                                                        pin_auth, ZF_PIN_AUTH_LEN, true),
        response, sizeof(response));

    expect(response_len > 1, "valid pinAuth plus uv=true should still build an assertion");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "pinAuth should take precedence over uv=true on GetAssertion");
    expect(g_approval_request_count == 1, "successful GetAssertion should still request approval");
}

static void test_get_assertion_pin_auth_clears_permission_scoped_token_after_up(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x77, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_GA;
    app.pin_state.pin_token_permissions_scoped = true;
    app.pin_state.pin_token_permissions_managed = true;
    app.pin_state.pin_token_permissions_rp_id_set = true;
    strcpy(app.pin_state.pin_token_permissions_rp_id, "example.com");
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive getAssertion pinAuth for permission-scoped token");

    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, pin_auth, ZF_PIN_AUTH_LEN, true),
        response, sizeof(response));

    expect(response_len > 1, "permission-scoped getAssertion should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "permission-scoped getAssertion should return success");
    expect(app.pin_state.pin_token_active,
           "permission-scoped token should remain active after getAssertion");
    expect(app.pin_state.pin_token_permissions == 0,
           "getAssertion should clear mc/ga token permissions after UP");
    expect(!app.pin_state.pin_token_permissions_rp_id_set,
           "getAssertion should clear the consumed permission RP binding");
    expect(app.pin_state.pin_token_permissions_rp_id[0] == '\0',
           "getAssertion should clear the consumed permission RP ID value");
}

static void test_permission_scoped_pin_token_rejects_browser_style_replay_after_mc(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t make_credential_pin_auth[32];
    uint8_t get_assertion_pin_auth[32];
    size_t response_len = 0;
    static const uint8_t make_credential_client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };
    static const uint8_t get_assertion_client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x79, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    app.pin_state.pin_token_permissions_scoped = true;
    app.pin_state.pin_token_permissions_managed = true;
    app.pin_state.pin_token_permissions_rp_id_set = true;
    strcpy(app.pin_state.pin_token_permissions_rp_id, "example.com");
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 make_credential_client_data_hash,
                                 sizeof(make_credential_client_data_hash),
                                 make_credential_pin_auth),
           "derive browser-style makeCredential pinAuth");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_resident_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true,
                                             make_credential_pin_auth, ZF_PIN_AUTH_LEN, true),
                                         response, sizeof(response));

    expect(response_len > 1, "browser-style makeCredential should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "browser-style makeCredential should return success");
    expect(app.store.count == 1, "browser-style makeCredential should persist a credential");
    expect(app.pin_state.pin_token_permissions == 0,
           "browser-style makeCredential should consume mc/ga token permissions");
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 get_assertion_client_data_hash,
                                 sizeof(get_assertion_client_data_hash), get_assertion_pin_auth),
           "derive browser-style getAssertion pinAuth");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_get_assertion_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true,
                                             get_assertion_pin_auth, ZF_PIN_AUTH_LEN, true),
                                         response, sizeof(response));

    expect(response_len == 1, "browser-style getAssertion replay should return only status");
    expect(response[0] == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "permission-scoped token should not remain usable after makeCredential");
    expect(g_approval_request_count == 1,
           "permission-scoped token replay should fail before another approval request");
}

static void test_get_assertion_legacy_pin_token_keeps_mc_ga_after_up(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x7A, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive getAssertion pinAuth for legacy token");

    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, pin_auth, ZF_PIN_AUTH_LEN, true),
        response, sizeof(response));

    expect(response_len > 1, "legacy-token getAssertion should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "legacy-token getAssertion should return success");
    expect(app.pin_state.pin_token_permissions == (ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA),
           "CTAP 2.0 legacy getPinToken permissions should survive GetAssertion UP");
}

static void test_get_assertion_allows_discouraged_uv_when_pin_is_set(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1,
           "GetAssertion should still succeed without pinAuth when UV is discouraged");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "GetAssertion should allow discouraged UV requests without pinAuth");
    expect(g_approval_request_count == 1,
           "GetAssertion without pinAuth should still request approval");
}

static void test_get_assertion_auto_accept_bypasses_approval_prompt(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);
    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "auto-accept GetAssertion should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "auto-accept GetAssertion should return success");
    expect(g_approval_request_count == 0,
           "auto-accept GetAssertion should bypass the approval prompt");
}

static void test_get_assertion_discovers_no_credentials_without_uv_for_cred_protect_2(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    record.cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID;
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "discoverable credProtect=2 without UV should return status only");
    expect(response[0] == ZF_CTAP_ERR_NO_CREDENTIALS,
           "discoverable credProtect=2 without UV should not reveal the credential");
}

static void test_get_assertion_with_pin_auth_allows_discoverable_cred_protect_2(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};
    static const uint8_t client_data_hash[32] = {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    record.cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID;
    app.store.records[0] = record;
    app.store.count = 1;
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state for credProtect assertion");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for credProtect assertion");
    mark_pin_token_issued(&app.pin_state);
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC | ZF_PIN_PERMISSION_GA;
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive pinAuth for discoverable credProtect assertion");

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_pin_auth(request, sizeof(request), false, false,
                                                        true, pin_auth, ZF_PIN_AUTH_LEN, true),
        response, sizeof(response));

    expect(response_len > 1, "discoverable credProtect=2 should succeed with pinAuth");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "discoverable credProtect=2 should succeed when UV is satisfied via pinAuth");
}

static void test_make_credential_overwrites_resident_credential_for_same_user(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_resident_make_credential_ctap_request(request, sizeof(request)), response,
        sizeof(response));
    expect(response_len > 1, "first resident makeCredential should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "first resident makeCredential should return success");
    expect(app.store.count == 1, "first resident makeCredential should store one credential");

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_resident_make_credential_ctap_request(request, sizeof(request)), response,
        sizeof(response));
    expect(response_len > 1, "second resident makeCredential should also succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "second resident makeCredential should return success");
    expect(app.store.count == 1,
           "resident makeCredential should overwrite the previous credential for the same user");
    expect(app.store.records[0].resident_key,
           "resident overwrite should preserve discoverable credential storage");
}

static void test_make_credential_cred_protect_round_trips_into_auth_data_and_store(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t cred_protect = 0;
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_resident_make_credential_ctap_request_with_cred_protect(
            request, sizeof(request), ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID),
        response, sizeof(response));

    expect(response_len > 1, "resident makeCredential with credProtect should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "resident makeCredential with credProtect should return success");
    expect(parse_make_credential_cred_protect_output(response + 1, response_len - 1, &cred_protect),
           "makeCredential response should expose credProtect extension output");
    expect(cred_protect == ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID,
           "makeCredential response should echo the requested credProtect policy");
    expect(app.store.count == 1, "resident makeCredential should persist the credential");
    expect(app.store.records[0].cred_protect == ZF_CRED_PROTECT_UV_OPTIONAL_WITH_CRED_ID,
           "resident credential should persist the requested credProtect policy");
}

static void test_make_credential_hmac_secret_round_trips_into_auth_data_and_store(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    bool hmac_secret = false;
    ZfCredentialRecord stored_record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_resident_make_credential_ctap_request_with_hmac_secret(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "resident makeCredential with hmac-secret should succeed");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "resident makeCredential with hmac-secret should return success");
    expect(parse_make_credential_hmac_secret_output(response + 1, response_len - 1, &hmac_secret),
           "makeCredential response should expose hmac-secret extension output");
    expect(hmac_secret, "makeCredential response should acknowledge hmac-secret creation");
    expect(app.store.count == 1, "resident hmac-secret credential should persist");
    expect(test_zf_store_record_format_load_record(&storage, app.store.records[0].file_name,
                                                   &stored_record),
           "resident hmac-secret credential should load from storage");
    expect(stored_record.hmac_secret, "stored credential should carry hmac-secret material");
}

static void test_get_assertion_hmac_secret_builds_protocol1_output(void) {
    ZfClientPinState pin_state = {0};
    ZfGetAssertionRequest request = {0};
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    ZfCredentialRecord record = {0};
    uint8_t extension[112];
    ZfHmacSecretScratch scratch = {0};
    size_t extension_len = 0;
    uint8_t expected_salt_auth[32];
    uint8_t expected_output[32];
    const uint8_t *hmac_secret_enc = NULL;
    size_t hmac_secret_enc_len = 0;

    request.assertion.has_hmac_secret = true;
    request.assertion.hmac_secret_pin_protocol = ZF_PIN_PROTOCOL_V1;
    memset(request.assertion.hmac_secret_platform_x, 0x11,
           sizeof(request.assertion.hmac_secret_platform_x));
    memset(request.assertion.hmac_secret_platform_y, 0x22,
           sizeof(request.assertion.hmac_secret_platform_y));
    for (size_t i = 0; i < 32U; ++i) {
        request.assertion.hmac_secret_salt_enc[i] = (uint8_t)i;
    }
    request.assertion.hmac_secret_salt_enc_len = 32U;
    expect(zf_crypto_hmac_sha256((const uint8_t[32]){[0 ... 31] = 0xAB}, 32,
                                 request.assertion.hmac_secret_salt_enc,
                                 request.assertion.hmac_secret_salt_enc_len, expected_salt_auth),
           "compute host hmac-secret saltAuth");
    memcpy(request.assertion.hmac_secret_salt_auth, expected_salt_auth, ZF_PIN_AUTH_LEN);
    request.assertion.hmac_secret_salt_auth_len = ZF_PIN_AUTH_LEN;

    record.hmac_secret = true;
    memset(record.hmac_secret_without_uv, 0x55, sizeof(record.hmac_secret_without_uv));
    memset(record.hmac_secret_with_uv, 0x66, sizeof(record.hmac_secret_with_uv));
    expect(zf_crypto_generate_key_agreement_key(&pin_state.key_agreement),
           "generate hmac-secret key agreement");

    expect(zf_ctap_hmac_secret_build_extension(&pin_state, &request.assertion, &record, false,
                                               &scratch, extension, sizeof(extension),
                                               &extension_len) == ZF_CTAP_SUCCESS,
           "hmac-secret assertion extension should build");
    expect(parse_hmac_secret_extension_output(extension, extension_len, &hmac_secret_enc,
                                              &hmac_secret_enc_len),
           "hmac-secret assertion extension should parse");
    expect(hmac_secret_enc_len == sizeof(expected_output),
           "protocol 1 hmac-secret output should contain one encrypted HMAC");
    expect(zf_crypto_hmac_sha256(record.hmac_secret_without_uv,
                                 sizeof(record.hmac_secret_without_uv),
                                 request.assertion.hmac_secret_salt_enc, 32U, expected_output),
           "compute expected hmac-secret output");
    expect(memcmp(hmac_secret_enc, expected_output, sizeof(expected_output)) == 0,
           "protocol 1 hmac-secret output should match credential secret HMAC");
}

static void test_assertion_response_preserves_scratch_hmac_secret_extension(void) {
    ZfClientPinState pin_state = {0};
    ZfGetAssertionRequest request = {0};
    TEST_INIT_GET_ASSERTION_REQUEST(request);
    ZfCredentialRecord record = {0};
    ZfAssertionResponseScratch response_scratch = {0};
    uint8_t response[256];
    size_t response_len = 0;
    size_t extension_len = 0;
    uint8_t expected_salt_auth[32];
    uint8_t expected_output[32];
    const uint8_t *hmac_secret_enc = NULL;
    size_t hmac_secret_enc_len = 0;

    strcpy(request.assertion.rp_id, "example.com");
    memset(request.assertion.client_data_hash, 0xA5, sizeof(request.assertion.client_data_hash));
    request.assertion.has_hmac_secret = true;
    request.assertion.hmac_secret_pin_protocol = ZF_PIN_PROTOCOL_V1;
    memset(request.assertion.hmac_secret_platform_x, 0x11,
           sizeof(request.assertion.hmac_secret_platform_x));
    memset(request.assertion.hmac_secret_platform_y, 0x22,
           sizeof(request.assertion.hmac_secret_platform_y));
    for (size_t i = 0; i < 32U; ++i) {
        request.assertion.hmac_secret_salt_enc[i] = (uint8_t)i;
    }
    request.assertion.hmac_secret_salt_enc_len = 32U;
    expect(zf_crypto_hmac_sha256((const uint8_t[32]){[0 ... 31] = 0xAB}, 32,
                                 request.assertion.hmac_secret_salt_enc,
                                 request.assertion.hmac_secret_salt_enc_len, expected_salt_auth),
           "compute response hmac-secret saltAuth");
    memcpy(request.assertion.hmac_secret_salt_auth, expected_salt_auth, ZF_PIN_AUTH_LEN);
    request.assertion.hmac_secret_salt_auth_len = ZF_PIN_AUTH_LEN;

    memset(record.credential_id, 0x10, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    memcpy(record.user_id, "user-1", 6);
    record.user_id_len = 6;
    record.hmac_secret = true;
    memset(record.hmac_secret_without_uv, 0x55, sizeof(record.hmac_secret_without_uv));
    memset(record.hmac_secret_with_uv, 0x66, sizeof(record.hmac_secret_with_uv));
    expect(zf_crypto_generate_key_agreement_key(&pin_state.key_agreement),
           "generate response hmac-secret key agreement");

    expect(zf_ctap_hmac_secret_build_extension(
               &pin_state, &request.assertion, &record, false, &response_scratch.hmac_secret,
               response_scratch.extension_data, sizeof(response_scratch.extension_data),
               &extension_len) == ZF_CTAP_SUCCESS,
           "hmac-secret extension should build into assertion scratch");
    expect(zf_ctap_build_assertion_response_with_scratch(
               &response_scratch, &request.assertion, &record, true, false, 7, false, false, 1,
               false, false, response_scratch.extension_data, extension_len, response,
               sizeof(response), &response_len) == ZF_CTAP_SUCCESS,
           "assertion response should build with scratch-owned hmac-secret extension");
    expect(parse_assertion_response_hmac_secret_output(response, response_len, &hmac_secret_enc,
                                                       &hmac_secret_enc_len),
           "assertion response should retain hmac-secret extension in authData");
    expect(hmac_secret_enc_len == sizeof(expected_output),
           "assertion hmac-secret output should contain one encrypted HMAC");
    expect(zf_crypto_hmac_sha256(record.hmac_secret_without_uv,
                                 sizeof(record.hmac_secret_without_uv),
                                 request.assertion.hmac_secret_salt_enc, 32U, expected_output),
           "compute expected response hmac-secret output");
    expect(memcmp(hmac_secret_enc, expected_output, sizeof(expected_output)) == 0,
           "assertion response hmac-secret output should match credential secret HMAC");
}

static void test_make_credential_excluded_credential_returns_excluded_after_timeout(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    g_approval_result = false;
    g_approval_state = ZfApprovalTimedOut;

    memset(record.credential_id, 0x44, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    strcpy(record.rp_id, "example.com");
    record.in_use = true;
    app.store.records[0] = record;
    app.store.count = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_make_credential_ctap_request_with_pin_auth(
                                  request, sizeof(request), false, false, false, NULL, 0, false,
                                  true, record.credential_id, record.credential_id_len),
                              response, sizeof(response));

    expect(response_len == 1, "excludeList hits should return only the CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_CREDENTIAL_EXCLUDED,
           "excludeList hits must report credential excluded even after timeout");
    expect(g_approval_request_count == 1,
           "excludeList hits should still wait for one approval/touch");
}

static void test_make_credential_exclude_list_hides_uv_required_credential_without_uv(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    memset(record.credential_id, 0x45, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    strcpy(record.rp_id, "example.com");
    record.in_use = true;
    record.cred_protect = ZF_CRED_PROTECT_UV_REQUIRED;
    app.store.records[0] = record;
    app.store.count = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_make_credential_ctap_request_with_pin_auth(
                                  request, sizeof(request), false, false, false, NULL, 0, false,
                                  true, record.credential_id, record.credential_id_len),
                              response, sizeof(response));

    expect(response_len > 1,
           "uv-required excludeList hit without UV should not reveal the existing credential");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "uv-required excludeList hit without UV should continue credential creation");
    expect(g_approval_request_count == 1,
           "non-excluded MakeCredential should still request registration approval");
}

static void test_make_credential_exclude_list_reveals_uv_required_credential_with_pin_auth(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[32];
    uint8_t pin_auth[32];
    size_t response_len = 0;
    ZfCredentialIndexEntry record = {0};
    static const uint8_t client_data_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.pin_state.pin_set = true;
    memset(app.pin_state.pin_token, 0x5A, sizeof(app.pin_state.pin_token));
    app.pin_state.pin_token_permissions = ZF_PIN_PERMISSION_MC;
    mark_pin_token_issued(&app.pin_state);
    expect(zf_crypto_hmac_sha256(app.pin_state.pin_token, sizeof(app.pin_state.pin_token),
                                 client_data_hash, sizeof(client_data_hash), pin_auth),
           "derive makeCredential pinAuth for uv-required excludeList");

    memset(record.credential_id, 0x46, sizeof(record.credential_id));
    record.credential_id_len = sizeof(record.credential_id);
    strcpy(record.rp_id, "example.com");
    record.in_use = true;
    record.cred_protect = ZF_CRED_PROTECT_UV_REQUIRED;
    app.store.records[0] = record;
    app.store.count = 1;

    response_len = zerofido_handle_ctap2(&app, 0x01020304, request,
                                         encode_make_credential_ctap_request_with_pin_auth(
                                             request, sizeof(request), false, false, true, pin_auth,
                                             ZF_PIN_AUTH_LEN, true, true, record.credential_id,
                                             record.credential_id_len),
                                         response, sizeof(response));

    expect(response_len == 1,
           "uv-required excludeList hit with UV should return only a CTAP status byte");
    expect(response[0] == ZF_CTAP_ERR_CREDENTIAL_EXCLUDED,
           "uv-required excludeList hit with UV should report credential excluded");
    expect(g_approval_request_count == 1,
           "uv-required excludeList hit with UV should still wait for user presence");
}

static void
test_get_assertion_without_matching_credential_waits_for_approval_before_no_credentials(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "GetAssertion error response should only include status");
    expect(response[0] == ZF_CTAP_ERR_NO_CREDENTIALS,
           "GetAssertion without a matching credential should still return no credentials");
    expect(g_approval_request_count == 1,
           "GetAssertion without credentials should require one approval before disclosure");
}

static void test_get_assertion_invalid_allow_list_waits_for_approval_before_no_credentials(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;
    static const uint8_t credential_id[] = {0x44, 0x55, 0x66, 0x77};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, request,
                              encode_get_assertion_ctap_request_with_allow_list(
                                  request, sizeof(request), credential_id, sizeof(credential_id)),
                              response, sizeof(response));

    expect(response_len == 1,
           "GetAssertion invalid allowList error response should only include status");
    expect(response[0] == ZF_CTAP_ERR_NO_CREDENTIALS,
           "GetAssertion invalid allowList should still return no credentials");
    expect(g_approval_request_count == 1, "GetAssertion invalid allowList should require one "
                                          "approval/touch before revealing no credentials");
}

static void run_get_assertion_multi_match_uses_account_selection(bool enable_fido2_1,
                                                                 bool expect_user_selected_key) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t next_response[64];
    size_t response_len = 0;
    size_t next_response_len = 0;
    const uint8_t *credential_id = NULL;
    size_t credential_id_len = 0;
    bool user_selected = false;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    if (enable_fido2_1) {
        test_enable_fido2_1_experimental(&app);
    }
    app.store.count = 4;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    strcpy(app.store.records[0].user_name, "alice");
    app.store.records[0].created_at = 10;
    seed_assertion_queue_record(&app.store.records[2], 0x22, 7);
    strcpy(app.store.records[2].user_display_name, "Bob Example");
    app.store.records[2].created_at = 30;
    seed_assertion_queue_record(&app.store.records[3], 0x33, 9);
    strcpy(app.store.records[3].user_name, "carol");
    app.store.records[3].created_at = 20;
    g_selection_index = 1;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "multi-match discoverable GetAssertion should return an assertion");
    expect(response[0] == ZF_CTAP_SUCCESS, "multi-match discoverable GetAssertion should succeed");
    expect(g_selection_request_count == 1,
           "multi-match discoverable GetAssertion should open chooser");
    expect(g_last_selection_match_count == 3, "chooser should receive every matching credential");
    expect(g_approval_request_count == 0,
           "multi-match discoverable GetAssertion should not also require approval");
    expect(parse_assertion_response_credential_id(response + 1, response_len - 1, &credential_id,
                                                  &credential_id_len),
           "chooser response should include a credential descriptor");
    expect(credential_id_len == app.store.records[3].credential_id_len,
           "chooser response should return the selected credential length");
    expect(memcmp(credential_id, app.store.records[3].credential_id, credential_id_len) == 0,
           "chooser response should return the selected credential");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 5),
           "chooser response should omit numberOfCredentials");
    if (expect_user_selected_key) {
        expect(cbor_map_uint_key_bool_value(response + 1, response_len - 1, 6, &user_selected) &&
                   user_selected,
               "CTAP 2.1 chooser response should include userSelected=true");
    } else {
        expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 6),
               "CTAP 2.0 chooser response should omit userSelected");
    }
    expect(!app.assertion_queue.active,
           "chooser-based GetAssertion should not seed the GetNextAssertion queue");
    expect(app.store.records[0].sign_count == 4,
           "non-selected credential should keep its sign count");
    expect(app.store.records[2].sign_count == 7,
           "newest non-selected credential should be unchanged");
    expect(app.store.records[3].sign_count == 10,
           "selected credential should increment sign count");
    expect(!app.store.records[1].in_use, "sparse store slot should remain unused");

    next_response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              next_response, sizeof(next_response));

    expect(next_response_len == 1, "GetNextAssertion after chooser path should return status only");
    expect(next_response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "GetNextAssertion after chooser path should be rejected");
}

static void test_get_assertion_multi_match_uses_account_selection(void) {
    run_get_assertion_multi_match_uses_account_selection(false, false);
}

static void test_get_assertion_multi_match_experimental_2_1_includes_user_selected(void) {
    run_get_assertion_multi_match_uses_account_selection(true, true);
}

static void test_get_assertion_up_false_multi_match_stays_silent(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    uint8_t flags = 0xFFU;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 3;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    app.store.records[0].created_at = 10;
    seed_assertion_queue_record(&app.store.records[1], 0x22, 7);
    app.store.records[1].created_at = 30;
    seed_assertion_queue_record(&app.store.records[2], 0x33, 9);
    app.store.records[2].created_at = 20;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_up(request, sizeof(request), false), response,
        sizeof(response));

    expect(response_len > 1, "silent multi-match GetAssertion should return an assertion");
    expect(response[0] == ZF_CTAP_SUCCESS, "silent multi-match GetAssertion should succeed");
    expect(g_selection_request_count == 0, "silent GetAssertion should not open chooser");
    expect(g_approval_request_count == 0, "silent GetAssertion should not request approval");
    expect(parse_make_credential_auth_flags(response + 1, response_len - 1, &flags),
           "silent assertion response should contain authData flags");
    expect((flags & 0x01U) == 0, "silent assertion must not set the UP flag");
    expect(!app.assertion_queue.active, "silent multi-match GetAssertion should not seed a queue");
}

static void test_get_assertion_multi_match_selection_denied_returns_operation_denied(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    g_selection_request_ok = false;
    g_approval_state = ZfApprovalDenied;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "denied chooser GetAssertion should return status only");
    expect(response[0] == ZF_CTAP_ERR_OPERATION_DENIED,
           "denied chooser GetAssertion should return operation denied");
    expect(g_selection_request_count == 1, "denied chooser should still use the selection flow");
    expect(g_approval_request_count == 0, "denied chooser should not fall back to approval");
}

static void test_get_assertion_multi_match_selection_cancel_returns_keepalive_cancel(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    g_selection_request_ok = false;
    g_approval_state = ZfApprovalCanceled;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "cancelled chooser GetAssertion should return status only");
    expect(response[0] == ZF_CTAP_ERR_KEEPALIVE_CANCEL,
           "cancelled chooser GetAssertion should return keepalive cancel");
}

static void test_get_assertion_multi_match_selection_timeout_returns_operation_denied(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[64];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    g_selection_request_ok = false;
    g_approval_state = ZfApprovalTimedOut;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len == 1, "timed out chooser GetAssertion should return status only");
    expect(response[0] == ZF_CTAP_ERR_OPERATION_DENIED,
           "timed out chooser GetAssertion should return operation denied");
}

static void test_get_assertion_multi_match_keeps_account_selection_when_auto_accept_is_on(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    test_enable_auto_accept_requests(&app);
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    g_selection_index = 0;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "chooser GetAssertion should still succeed with auto-accept");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "chooser GetAssertion should still return success with auto-accept");
    expect(g_selection_request_count == 1,
           "auto-accept should not bypass discoverable account selection");
    expect(g_approval_request_count == 0,
           "chooser flow should not route through the approval prompt");
}

static void test_get_assertion_allow_list_does_not_open_account_selection(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    uint8_t next_response[512];
    size_t response_len = 0;
    size_t next_response_len = 0;
    const uint8_t *credential_id = NULL;
    size_t credential_id_len = 0;
    bool user_selected = true;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    app.store.records[0].created_at = 20;
    app.store.records[1].created_at = 10;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request,
        encode_get_assertion_ctap_request_with_two_allow_list_entries(
            request, sizeof(request), app.store.records[0].credential_id,
            app.store.records[0].credential_id_len, app.store.records[1].credential_id,
            app.store.records[1].credential_id_len),
        response, sizeof(response));

    expect(response_len > 1, "allowList GetAssertion should still succeed");
    expect(response[0] == ZF_CTAP_SUCCESS, "allowList GetAssertion should return success");
    expect(g_selection_request_count == 0,
           "allowList GetAssertion should not use account selection");
    expect(g_approval_request_count == 1,
           "allowList GetAssertion should keep the approval-only path");
    expect(parse_assertion_response_credential_id(response + 1, response_len - 1, &credential_id,
                                                  &credential_id_len),
           "allowList GetAssertion should include a credential descriptor");
    expect(credential_id_len == app.store.records[0].credential_id_len,
           "allowList GetAssertion should return the selected credential length");
    expect(memcmp(credential_id, app.store.records[0].credential_id, credential_id_len) == 0,
           "allowList GetAssertion should return one matching credential");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 5),
           "allowList GetAssertion should omit numberOfCredentials for multiple matches");
    expect(!cbor_map_uint_key_bool_value(response + 1, response_len - 1, 6, &user_selected),
           "allowList GetAssertion should omit userSelected");
    expect(!app.assertion_queue.active,
           "allowList GetAssertion should not seed the GetNextAssertion queue");

    next_response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              next_response, sizeof(next_response));

    expect(next_response_len == 1, "allowList GetNextAssertion should return status only");
    expect(next_response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "allowList GetNextAssertion should be rejected when no queue was seeded");
}

static void seed_assertion_queue_record_full(ZfCredentialRecord *record, uint8_t id_byte,
                                             uint32_t sign_count) {
    memset(record, 0, sizeof(*record));
    record->in_use = true;
    record->resident_key = true;
    strcpy(record->file_name, "test-record");
    strcpy(record->rp_id, "example.com");
    memcpy(record->user_id, "user", 4);
    record->user_id_len = 4;
    record->credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(record->credential_id, id_byte, ZF_CREDENTIAL_ID_LEN);
    record->sign_count = sign_count;
}

static void seed_assertion_queue_record_index(ZfCredentialIndexEntry *record, uint8_t id_byte,
                                              uint32_t sign_count) {
    memset(record, 0, sizeof(*record));
    record->in_use = true;
    record->resident_key = true;
    strcpy(record->rp_id, "example.com");
    strcpy(record->file_name, "test-record");
    memcpy(record->user_id, "user", 4);
    record->user_id_len = 4;
    record->credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(record->credential_id, id_byte, ZF_CREDENTIAL_ID_LEN);
    record->sign_count = sign_count;
}

static void test_get_next_assertion_rejects_wrong_cid(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x5A}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0xAABBCCDD, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len == 1, "wrong-CID GetNextAssertion should only return status");
    expect(response[0] == ZF_CTAP_ERR_INVALID_CHANNEL,
           "wrong-CID GetNextAssertion should be rejected as invalid channel");
    expect(app.assertion_queue.active,
           "wrong-CID rejection should preserve the queued assertion state");
}

static void test_get_next_assertion_refreshes_queue_expiry(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 3;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);
    seed_assertion_queue_record(&app.store.records[2], 0x33, 6);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 3;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + 50;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x6B}, ZF_CLIENT_DATA_HASH_LEN);
    for (size_t i = 0; i < app.store.count; ++i) {
        app.assertion_queue.record_indices[i] = (uint16_t)i;
    }

    g_fake_tick = 1025;
    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len > 1, "GetNextAssertion should return a response body on success");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetNextAssertion should succeed for the active CID");
    expect(app.assertion_queue.active, "queue should remain active while more assertions remain");
    expect(app.assertion_queue.index == 2, "GetNextAssertion should advance the queue index");
    expect(app.assertion_queue.expires_at == g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS,
           "GetNextAssertion should refresh the queue expiry after success");
}

static void test_get_next_assertion_rejects_empty_queue(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len == 1, "empty GetNextAssertion queue should only return status");
    expect(response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "empty GetNextAssertion queue should be rejected");
    expect(!app.assertion_queue.active, "empty queue rejection should leave the queue cleared");
}

static void test_get_next_assertion_rejects_expired_queue(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick - 1;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x6C}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len == 1, "expired GetNextAssertion queue should only return status");
    expect(response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "expired GetNextAssertion queue should be rejected");
    expect(!app.assertion_queue.active, "expired queue rejection should clear queue state");
    expect(app.assertion_queue.count == 0, "expired queue rejection should reset queue count");
}

static void test_get_next_assertion_clears_final_queue_state(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x6D}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len > 1, "final queued GetNextAssertion should still return a body");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "final queued GetNextAssertion should succeed for the active CID");
    expect(!app.assertion_queue.active, "final queued assertion should clear queue state");
    expect(app.assertion_queue.index == 0, "final queued assertion should reset queue index");
    expect(app.store.records[1].sign_count == 6,
           "final queued assertion should persist the advanced sign counter");
}

static void test_get_next_assertion_missing_record_clears_queue(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 1;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x6E}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 99;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len == 1,
           "missing queued credential state should only return a GetNextAssertion status");
    expect(response[0] == ZF_CTAP_ERR_NOT_ALLOWED,
           "missing queued credential state should fail closed");
    expect(!app.assertion_queue.active,
           "missing queued credential state should clear the queue before returning");
}

static void test_get_next_assertion_rejects_trailing_payload(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x7C}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 1;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion, 0xAA},
                              2, response, sizeof(response));

    expect(response_len == 1, "GetNextAssertion trailing payload should return only status");
    expect(response[0] == ZF_CTAP_ERR_INVALID_LENGTH,
           "GetNextAssertion trailing payload should be rejected");
    expect(app.assertion_queue.active,
           "queue should remain intact after malformed GetNextAssertion");
    expect(app.assertion_queue.index == 1,
           "malformed GetNextAssertion should not consume queued assertions");
    expect(app.store.records[1].sign_count == 5,
           "malformed GetNextAssertion should not advance sign counters");
}

static void test_get_info_rejects_trailing_payload(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[128];
    size_t response_len = 0;

    test_storage_reset();
    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo, 0x00}, 2,
                              response, sizeof(response));

    expect(response_len == 1, "GetInfo trailing payload should return only status");
    expect(response[0] == ZF_CTAP_ERR_INVALID_LENGTH,
           "GetInfo trailing payload should be rejected");
    expect(test_log_contains("cmd=GI status=LEN body=0"),
           "failed GetInfo should emit a serial diagnostic");
    expect(g_status_update_count == 0, "failed GetInfo diagnostic should not update UI status");
}

static void test_get_info_success_updates_status_banner(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetInfo should succeed");
    expect(test_log_contains("cmd=GI status=OK"),
           "successful GetInfo should emit a serial diagnostic");
    expect(g_status_update_count == 0, "successful GetInfo diagnostic should not update UI status");
}

static void test_get_info_advertises_cred_protect_extension(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetInfo should succeed");
    expect(get_info_has_cred_protect_extension(response + 1, response_len - 1),
           "GetInfo should advertise the credProtect extension");
}

static void test_get_info_advertises_hmac_secret_extension(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetInfo should succeed");
    expect(get_info_has_extension(response + 1, response_len - 1, "hmac-secret"),
           "GetInfo should advertise the hmac-secret extension");
}

static void test_get_info_advertises_fido_2_0_without_fido_2_1(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;
    bool pin_uv_auth_token = true;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetInfo should succeed");
    expect(get_info_has_version(response + 1, response_len - 1, "FIDO_2_0"),
           "GetInfo should advertise FIDO_2_0");
    expect(!get_info_has_version(response + 1, response_len - 1, "FIDO_2_1"),
           "CTAP 2.0 profile should not advertise FIDO_2_1");
    expect(
        !get_info_option_bool(response + 1, response_len - 1, "pinUvAuthToken", &pin_uv_auth_token),
        "CTAP 2.0 profile should not advertise pinUvAuthToken");
    expect(get_info_has_pin_uv_auth_protocol(response + 1, response_len - 1, 1),
           "CTAP 2.0 profile should advertise PIN/UV auth protocol 1");
    expect(!get_info_has_pin_uv_auth_protocol(response + 1, response_len - 1, 2),
           "CTAP 2.0 profile should not advertise PIN/UV auth protocol 2");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 9),
           "CTAP 2.0 profile should omit CTAP 2.1 transports");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 10),
           "CTAP 2.0 profile should omit CTAP 2.1 algorithms");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 13),
           "CTAP 2.0 profile should omit CTAP 2.1 minPINLength");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 14),
           "CTAP 2.0 profile should omit CTAP 2.1 firmwareVersion");
}

static void test_get_info_nfc_ctap2_0_advertises_transport_compactly(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.runtime_config.transport_mode = ZfTransportModeNfc;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "NFC GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "NFC GetInfo should succeed");
    expect(get_info_has_version(response + 1, response_len - 1, "FIDO_2_0"),
           "NFC CTAP 2.0 profile should advertise FIDO_2_0");
    expect(!get_info_has_version(response + 1, response_len - 1, "FIDO_2_1"),
           "NFC CTAP 2.0 profile should not advertise FIDO_2_1");
    expect(cbor_map_contains_uint_key(response + 1, response_len - 1, 9),
           "NFC CTAP 2.0 profile should advertise transports");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 10),
           "NFC CTAP 2.0 profile should keep optional algorithms out of compact GetInfo");
    expect(contains_text(response + 1, response_len - 1, "nfc"),
           "NFC GetInfo transport list should include nfc");
    expect(response_len + 2U <= 120U,
           "NFC CTAP 2.0 GetInfo APDU response should stay below the conservative frame cap");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 13),
           "NFC CTAP 2.0 profile should omit CTAP 2.1 minPINLength");
    expect(!cbor_map_contains_uint_key(response + 1, response_len - 1, 14),
           "NFC CTAP 2.0 profile should omit CTAP 2.1 firmwareVersion");
}

static void test_get_info_experimental_2_1_advertises_pin_uv_auth_token(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;
    bool pin_uv_auth_token = false;
    bool make_cred_uv_not_rqd = false;
    bool client_pin = false;
    const uint64_t expected_protocols[] = {2, 1};

    test_storage_reset();
    test_enable_fido2_1_experimental(&app);
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "experimental 2.1 GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "experimental 2.1 GetInfo should succeed");
    expect(get_info_has_version(response + 1, response_len - 1, "FIDO_2_0"),
           "experimental 2.1 GetInfo should keep CTAP 2.0 compatibility");
    expect(get_info_has_version(response + 1, response_len - 1, "FIDO_2_1"),
           "experimental 2.1 GetInfo should advertise FIDO_2_1");
    expect(get_info_option_bool(response + 1, response_len - 1, "pinUvAuthToken",
                                &pin_uv_auth_token) &&
               pin_uv_auth_token,
           "experimental 2.1 GetInfo should advertise pinUvAuthToken=true");
    expect(get_info_option_bool(response + 1, response_len - 1, "makeCredUvNotRqd",
                                &make_cred_uv_not_rqd) &&
               make_cred_uv_not_rqd,
           "experimental 2.1 GetInfo should advertise makeCredUvNotRqd=true");
    expect(get_info_option_bool(response + 1, response_len - 1, "clientPin", &client_pin) &&
               client_pin,
           "experimental 2.1 GetInfo should require and advertise a configured PIN");
    expect(get_info_pin_uv_auth_protocols_equal(response + 1, response_len - 1, expected_protocols,
                                                sizeof(expected_protocols) /
                                                    sizeof(expected_protocols[0])),
           "experimental 2.1 GetInfo should prefer protocol 2 before protocol 1");
    expect(cbor_map_contains_uint_key(response + 1, response_len - 1, 9),
           "experimental 2.1 GetInfo should advertise transports");
    expect(cbor_map_contains_uint_key(response + 1, response_len - 1, 10),
           "experimental 2.1 GetInfo should advertise algorithms");
    expect(get_info_has_uint_field(response + 1, response_len - 1, 13, ZF_MIN_PIN_LENGTH),
           "experimental 2.1 GetInfo should advertise minPINLength");
    expect(get_info_has_uint_field(response + 1, response_len - 1, 14, ZF_FIRMWARE_VERSION),
           "experimental 2.1 GetInfo should advertise firmwareVersion");
}

static void test_get_info_advertises_u2f(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "GetInfo should succeed");
    expect(get_info_has_version(response + 1, response_len - 1, "U2F_V2"),
           "GetInfo should advertise legacy U2F compatibility");
}

static void test_get_info_reports_firmware_version(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[512];
    size_t response_len = 0;

    test_storage_reset();
    test_enable_fido2_1_experimental(&app);
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetInfo}, 1,
                                         response, sizeof(response));

    expect(response_len > 1, "experimental 2.1 GetInfo should return a CBOR body");
    expect(response[0] == ZF_CTAP_SUCCESS, "experimental 2.1 GetInfo should succeed");
    expect(get_info_has_uint_field(response + 1, response_len - 1, 14, ZF_FIRMWARE_VERSION),
           "experimental 2.1 GetInfo should report the firmwareVersion field");
}

static void test_ctap_reset_succeeds_and_wipes_runtime_state(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    Storage storage = {0};
    uint8_t response[128];
    size_t response_len = 0;
    ZfCredentialRecord record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = (FuriMutex *)0x1;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(test_zf_store_init(&storage, &app.store), "init store before reset");
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state before reset");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN before reset");
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential before reset");
    expect(test_zf_store_add_record(&storage, &app.store, &record),
           "persist credential before reset");
    app.assertion_queue.active = true;
    app.assertion_queue.count = 1;

    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdReset}, 1,
                                         response, sizeof(response));

    expect(response_len == 1, "Reset should return status only");
    expect(response[0] == ZF_CTAP_SUCCESS, "Reset should succeed after approval");
    expect(g_approval_request_count == 1, "Reset should require user presence approval");
    expect(zf_store_count_saved(&app.store) == 0, "Reset should wipe stored credentials");
    expect(!app.pin_state.pin_set, "Reset should clear the PIN state");
    expect(!g_pin_file_exists, "Reset should remove persisted PIN state");
    expect(!app.assertion_queue.active && app.assertion_queue.count == 0,
           "Reset should clear pending assertion queue state");
    expect(test_log_contains("cmd=RST status=OK"),
           "successful Reset should emit a serial diagnostic");
    expect(g_status_update_count == 0, "Reset diagnostic should not update UI status");
}

static void test_ctap_reset_auto_accept_bypasses_approval_prompt(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    Storage storage = {0};
    uint8_t response[128];
    size_t response_len = 0;
    ZfCredentialRecord record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = (FuriMutex *)0x1;
    test_enable_auto_accept_requests(&app);

    expect(test_zf_store_init(&storage, &app.store), "init store before auto-accept reset");
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state before auto-accept reset");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN before auto-accept reset");
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential before auto-accept reset");
    expect(test_zf_store_add_record(&storage, &app.store, &record),
           "persist credential before auto-accept reset");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdReset}, 1,
                                         response, sizeof(response));

    expect(response_len == 1, "auto-accept Reset should return status only");
    expect(response[0] == ZF_CTAP_SUCCESS, "auto-accept Reset should succeed");
    expect(g_approval_request_count == 0, "auto-accept Reset should bypass the approval prompt");
}

static void test_ctap_reset_succeeds_when_u2f_reinit_fails(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    Storage storage = {0};
    uint8_t response[128];
    size_t response_len = 0;
    ZfCredentialRecord record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = (FuriMutex *)0x1;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    app.capabilities.u2f_enabled = true;
    g_u2f_adapter_init_ok = false;

    expect(test_zf_store_init(&storage, &app.store), "init store before U2F-failing reset");
    expect(zerofido_pin_init(&storage, &app.pin_state), "init PIN state before U2F-failing reset");
    expect(zerofido_pin_set_plaintext(&storage, &app.pin_state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN before U2F-failing reset");
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential before U2F-failing reset");
    expect(test_zf_store_add_record(&storage, &app.store, &record),
           "persist credential before U2F-failing reset");

    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdReset}, 1,
                                         response, sizeof(response));

    expect(response_len == 1, "Reset with failed U2F reinit should return status only");
    expect(response[0] == ZF_CTAP_SUCCESS, "Reset should not fail when U2F reinit fails");
    expect(zf_store_count_saved(&app.store) == 0,
           "Reset should still wipe stored credentials when U2F reinit fails");
    expect(!app.pin_state.pin_set, "Reset should still clear PIN when U2F reinit fails");
    expect(g_u2f_adapter_deinit_count == 1, "Reset should deinit U2F before wiping");
    expect(g_u2f_adapter_init_count == 1, "Reset should attempt best-effort U2F reinit");
}

static void test_ctap_reset_rejects_trailing_payload(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[128];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdReset, 0xAA},
                                         2, response, sizeof(response));

    expect(response_len == 1, "Reset trailing payload should return status only");
    expect(response[0] == ZF_CTAP_ERR_INVALID_LENGTH, "Reset trailing payload should be rejected");
    expect(g_approval_request_count == 0, "malformed Reset should fail before approval");
}

static void test_client_pin_get_key_agreement_updates_status_banner(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t request[128];
    uint8_t response[512];
    size_t request_len = 0;

    test_storage_reset();
    request[0] = ZfCtapeCmdClientPin;
    request_len = encode_client_pin_get_key_agreement_request(request + 1, sizeof(request) - 1) + 1;
    zerofido_handle_ctap2(&app, 0x01020304, request, request_len, response, sizeof(response));

    expect(response[0] == ZF_CTAP_SUCCESS, "ClientPIN getKeyAgreement should succeed");
    expect(test_log_contains("cmd=CP-GA status=OK"),
           "ClientPIN getKeyAgreement should emit a serial diagnostic");
    expect(g_status_update_count == 0, "ClientPIN diagnostic should not update UI status");
}

static void test_selection_touch_succeeds_and_updates_status_banner(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[128];
    size_t response_len = 0;

    test_storage_reset();
    test_enable_fido2_1_experimental(&app);
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdSelection},
                                         1, response, sizeof(response));

    expect(response_len == 1, "Selection should return status only");
    expect(response[0] == ZF_CTAP_SUCCESS, "Selection should succeed after approval");
    expect(g_approval_request_count == 1, "Selection should request touch approval");
    expect(test_log_contains("cmd=SEL status=OK"), "Selection should emit a serial diagnostic");
    expect(g_status_update_count == 0, "Selection diagnostic should not update UI status");
}

static void test_selection_touch_rejects_default_ctap2_0_profile(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[128];
    size_t response_len = 0;

    test_storage_reset();
    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdSelection},
                                         1, response, sizeof(response));

    expect(response_len == 1, "CTAP 2.0 Selection should return status only");
    expect(response[0] == ZF_CTAP_ERR_INVALID_COMMAND,
           "CTAP 2.0 Selection should be rejected as an unsupported command");
    expect(g_approval_request_count == 0, "CTAP 2.0 Selection should fail before approval");
}

static void test_selection_touch_auto_accept_bypasses_approval_prompt(void) {
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    uint8_t response[128];
    size_t response_len = 0;

    test_storage_reset();
    test_enable_auto_accept_fido2_1_experimental(&app);

    response_len = zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdSelection},
                                         1, response, sizeof(response));

    expect(response_len == 1, "auto-accept Selection should return status only");
    expect(response[0] == ZF_CTAP_SUCCESS, "auto-accept Selection should succeed");
    expect(g_approval_request_count == 0,
           "auto-accept Selection should bypass the approval prompt");
}

static void test_store_cleanup_restores_backup_when_primary_is_missing(void) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t size = 0;
    TestStorageFile *primary = NULL;
    TestStorageFile *backup = NULL;
    char primary_path[160];
    char backup_path[160];

    test_storage_reset();
    size = encode_complete_record(buffer, sizeof(buffer));
    snprintf(primary_path, sizeof(primary_path), "%s/%s", ZF_APP_DATA_DIR,
             k_repeated_credential_file_name);
    snprintf(backup_path, sizeof(backup_path), "%s/%s.bak", ZF_APP_DATA_DIR,
             k_repeated_credential_file_name);

    primary = test_storage_file_slot(primary_path, true);
    backup = test_storage_file_slot(backup_path, true);
    expect(primary && backup, "allocate storage slots for cleanup recovery");
    memcpy(backup->data, buffer, size);
    backup->size = size;
    backup->exists = true;
    primary->size = 0;
    primary->exists = false;

    zf_store_recovery_cleanup_temp_files(NULL);

    expect(primary->exists, "cleanup should restore the backup into the primary path");
    expect(!backup->exists, "cleanup should remove the restored backup file");
}

static void test_store_remove_record_paths_deletes_atomic_backups(void) {
    Storage storage = {0};
    TestStorageFile *record = NULL;
    TestStorageFile *record_temp = NULL;
    TestStorageFile *record_backup = NULL;
    TestStorageFile *counter = NULL;
    TestStorageFile *counter_temp = NULL;
    TestStorageFile *counter_backup = NULL;
    char record_path[128];
    char record_temp_path[128];
    char record_backup_path[128];
    char counter_path[128];
    char counter_temp_path[128];
    char counter_backup_path[128];

    test_storage_reset();
    zf_store_build_record_path(k_repeated_credential_file_name, record_path, sizeof(record_path));
    zf_store_build_temp_path(k_repeated_credential_file_name, record_temp_path,
                             sizeof(record_temp_path));
    zf_store_build_counter_floor_path(k_repeated_credential_file_name, counter_path,
                                      sizeof(counter_path));
    zf_store_build_counter_floor_temp_path(k_repeated_credential_file_name, counter_temp_path,
                                           sizeof(counter_temp_path));
    snprintf(record_backup_path, sizeof(record_backup_path), "%s.bak", record_path);
    snprintf(counter_backup_path, sizeof(counter_backup_path), "%s.bak", counter_path);

    record = test_storage_file_slot(record_path, true);
    record_temp = test_storage_file_slot(record_temp_path, true);
    record_backup = test_storage_file_slot(record_backup_path, true);
    counter = test_storage_file_slot(counter_path, true);
    counter_temp = test_storage_file_slot(counter_temp_path, true);
    counter_backup = test_storage_file_slot(counter_backup_path, true);
    expect(record && record_temp && record_backup && counter && counter_temp && counter_backup,
           "allocate record remove slots");
    record->exists = true;
    record_temp->exists = true;
    record_backup->exists = true;
    counter->exists = true;
    counter_temp->exists = true;
    counter_backup->exists = true;

    expect(zf_store_recovery_remove_record_paths(&storage, k_repeated_credential_file_name),
           "record path removal should include atomic companions");
    expect(!record->exists, "record removal should delete primary record");
    expect(!record_temp->exists, "record removal should delete temp record");
    expect(!record_backup->exists, "record removal should delete backup record");
    expect(!counter->exists, "record removal should delete counter floor");
    expect(!counter_temp->exists, "record removal should delete counter temp");
    expect(!counter_backup->exists, "record removal should delete counter backup");
}

static void test_atomic_file_write_overwrites_primary_without_predelete(void) {
    Storage storage = {0};
    TestStorageFile *primary = NULL;
    static const char path[] = ZF_APP_DATA_DIR "/atomic.bin";
    static const char temp_path[] = ZF_APP_DATA_DIR "/atomic.tmp";
    static const uint8_t old_value[] = {0x10, 0x11, 0x12};
    static const uint8_t new_value[] = {0x20, 0x21, 0x22, 0x23};

    test_storage_reset();
    primary = test_storage_file_slot(path, true);
    expect(primary != NULL, "allocate primary slot for atomic write overwrite");
    memcpy(primary->data, old_value, sizeof(old_value));
    primary->size = sizeof(old_value);
    primary->exists = true;

    expect(zf_storage_write_file_atomic(&storage, path, temp_path, new_value, sizeof(new_value)),
           "atomic write should publish temp over existing primary");
    expect(primary->exists, "atomic write should leave a primary file after overwrite");
    expect(primary->size == sizeof(new_value), "atomic write should replace primary size");
    expect(memcmp(primary->data, new_value, sizeof(new_value)) == 0,
           "atomic write should replace primary contents");
}

static void test_atomic_file_write_failure_keeps_primary(void) {
    Storage storage = {0};
    TestStorageFile *primary = NULL;
    TestStorageFile *temp = NULL;
    static const char path[] = ZF_APP_DATA_DIR "/atomic.bin";
    static const char temp_path[] = ZF_APP_DATA_DIR "/atomic.tmp";
    static const uint8_t old_value[] = {0x30, 0x31, 0x32};
    static const uint8_t new_value[] = {0x40, 0x41, 0x42, 0x43};

    test_storage_reset();
    primary = test_storage_file_slot(path, true);
    temp = test_storage_file_slot(temp_path, true);
    expect(primary != NULL && temp != NULL, "allocate slots for failed atomic write");
    memcpy(primary->data, old_value, sizeof(old_value));
    primary->size = sizeof(old_value);
    primary->exists = true;

    g_storage_fail_copy_match = temp_path;
    expect(!zf_storage_write_file_atomic(&storage, path, temp_path, new_value, sizeof(new_value)),
           "atomic write should report failed publish");
    g_storage_fail_copy_match = NULL;

    expect(primary->exists, "failed atomic publish should keep the old primary");
    expect(primary->size == sizeof(old_value), "failed atomic publish should keep primary size");
    expect(memcmp(primary->data, old_value, sizeof(old_value)) == 0,
           "failed atomic publish should keep primary contents");
    expect(!temp->exists, "failed atomic publish should clean up the temp file");
}

static void test_atomic_file_recovery_restores_backup_when_primary_missing(void) {
    Storage storage = {0};
    TestStorageFile *primary = NULL;
    TestStorageFile *backup = NULL;
    TestStorageFile *temp = NULL;
    static const char path[] = ZF_APP_DATA_DIR "/atomic.bin";
    static const char temp_path[] = ZF_APP_DATA_DIR "/atomic.tmp";
    static const char backup_path[] = ZF_APP_DATA_DIR "/atomic.bin.bak";
    static const uint8_t old_value[] = {0x50, 0x51, 0x52};
    static const uint8_t temp_value[] = {0x60, 0x61, 0x62};

    test_storage_reset();
    primary = test_storage_file_slot(path, true);
    backup = test_storage_file_slot(backup_path, true);
    temp = test_storage_file_slot(temp_path, true);
    expect(primary != NULL && backup != NULL && temp != NULL,
           "allocate slots for atomic backup recovery");
    memcpy(backup->data, old_value, sizeof(old_value));
    backup->size = sizeof(old_value);
    backup->exists = true;
    memcpy(temp->data, temp_value, sizeof(temp_value));
    temp->size = sizeof(temp_value);
    temp->exists = true;

    expect(zf_storage_recover_atomic_file(&storage, path, temp_path),
           "atomic recovery should restore the backup");
    expect(primary->exists, "atomic recovery should restore primary existence");
    expect(primary->size == sizeof(old_value), "atomic recovery should restore primary size");
    expect(memcmp(primary->data, old_value, sizeof(old_value)) == 0,
           "atomic recovery should restore old primary contents");
    expect(!backup->exists, "atomic recovery should consume the backup");
    expect(!temp->exists, "atomic recovery should remove stale temp data");
}

static void test_atomic_file_remove_deletes_primary_temp_and_backup(void) {
    Storage storage = {0};
    TestStorageFile *primary = NULL;
    TestStorageFile *backup = NULL;
    TestStorageFile *temp = NULL;
    static const char path[] = ZF_APP_DATA_DIR "/atomic.bin";
    static const char temp_path[] = ZF_APP_DATA_DIR "/atomic.tmp";
    static const char backup_path[] = ZF_APP_DATA_DIR "/atomic.bin.bak";

    test_storage_reset();
    primary = test_storage_file_slot(path, true);
    backup = test_storage_file_slot(backup_path, true);
    temp = test_storage_file_slot(temp_path, true);
    expect(primary != NULL && backup != NULL && temp != NULL, "allocate slots for atomic remove");
    primary->exists = true;
    primary->size = 1U;
    backup->exists = true;
    backup->size = 1U;
    temp->exists = true;
    temp->size = 1U;

    expect(zf_storage_remove_atomic_file(&storage, path, temp_path),
           "atomic remove should remove all related paths");
    expect(!primary->exists, "atomic remove should remove primary");
    expect(!backup->exists, "atomic remove should remove backup");
    expect(!temp->exists, "atomic remove should remove temp");
}

static void test_pin_auth_mismatch_keeps_block_state_when_persist_fails(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0};
    uint8_t pin_auth[ZF_PIN_AUTH_LEN];
    bool uv_verified = false;

    test_storage_reset();
    memset(pin_auth, 0x01, sizeof(pin_auth));
    expect(zerofido_pin_init(&storage, &state), "init PIN state for pinAuth persistence failure");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for pinAuth persistence failure");
    mark_pin_token_issued(&state);

    g_storage_fail_rename_match = "client_pin";
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "first pinAuth mismatch should stay invalid when persistence fails");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "second pinAuth mismatch should stay invalid when persistence fails");
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_BLOCKED,
           "third pinAuth mismatch should still block when persistence fails");
    expect(state.pin_consecutive_mismatches == 3,
           "in-memory pinAuth mismatch count should still advance");
    expect(state.pin_auth_blocked, "in-memory pinAuth block should stick");
}

static void test_wrong_pin_keeps_retry_state_when_persist_fails(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for wrong PIN persistence failure");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for wrong PIN persistence failure");

    g_storage_fail_rename_match = "client_pin";
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "first wrong PIN should stay invalid when persistence fails");
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "second wrong PIN should stay invalid when persistence fails");
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_AUTH_BLOCKED,
           "third wrong PIN should still auth-block when persistence fails");
    expect(state.pin_retries == (ZF_PIN_RETRIES_MAX - 3),
           "in-memory PIN retries should still decrement");
    expect(state.pin_consecutive_mismatches == 3,
           "in-memory wrong-PIN mismatch count should still advance");
    expect(state.pin_auth_blocked, "in-memory wrong-PIN auth block should stick");
}

static void test_pin_persist_failure_poison_blocks_reinit_after_wrong_pin(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for fail-closed wrong-PIN test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for fail-closed wrong-PIN test");

    g_storage_fail_rename_match = "client_pin";
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "wrong PIN should still return pin invalid under persistence failure");
    expect(!zerofido_pin_init(&storage, &restored),
           "re-init should fail closed after wrong-PIN persistence failure");
}

static void test_pin_persist_failure_poison_blocks_reinit_after_pin_auth_mismatch(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0};
    uint8_t pin_auth[ZF_PIN_AUTH_LEN];
    bool uv_verified = false;

    test_storage_reset();
    memset(pin_auth, 0x01, sizeof(pin_auth));
    expect(zerofido_pin_init(&storage, &state), "init PIN state for fail-closed pinAuth test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for fail-closed pinAuth test");
    mark_pin_token_issued(&state);

    g_storage_fail_rename_match = "client_pin";
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     sizeof(pin_auth), true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_PIN_AUTH_INVALID,
           "pinAuth mismatch should still report invalid under persistence failure");
    expect(!zerofido_pin_init(&storage, &restored),
           "re-init should fail closed after pinAuth persistence failure");
}

static void test_pin_persist_failure_falls_back_to_remove_when_poison_write_fails(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    ZfClientPinState restored = {0};

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state), "init PIN state for poison-write fallback test");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for poison-write fallback test");

    g_storage_fail_rename_match = "client_pin";
    g_storage_fail_write_match = "client_pin";
    expect(zerofido_pin_verify_plaintext(&storage, &state, "9999") == ZF_CTAP_ERR_PIN_INVALID,
           "wrong PIN should stay invalid when persistence and poison write both fail");
    expect(zerofido_pin_init(&storage, &restored),
           "re-init should succeed once the persisted PIN file has been removed");
    expect(!restored.pin_set, "poison-write fallback should leave no persisted PIN state behind");
}

static void test_correct_pin_auth_keeps_retry_state_when_persist_fails(void) {
    Storage storage = {0};
    ZfClientPinState state = {0};
    uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN] = {0x5A};
    uint8_t pin_auth[32];
    bool uv_verified = false;

    test_storage_reset();
    expect(zerofido_pin_init(&storage, &state),
           "init PIN state for successful pinAuth persistence failure");
    expect(zerofido_pin_set_plaintext(&storage, &state, "1234") == ZF_CTAP_SUCCESS,
           "set PIN for successful pinAuth persistence failure");
    mark_pin_token_issued(&state);
    state.pin_consecutive_mismatches = 2;
    state.pin_auth_blocked = false;
    expect(zf_pin_persist_state(&storage, &state), "persist mismatch state before successful auth");
    expect(zf_crypto_hmac_sha256(state.pin_token, sizeof(state.pin_token), client_data_hash,
                                 sizeof(client_data_hash), pin_auth),
           "derive valid pinAuth before persistence failure");

    g_storage_fail_rename_match = "client_pin";
    expect(zerofido_pin_require_auth(&storage, &state, false, true, client_data_hash, pin_auth,
                                     ZF_PIN_AUTH_LEN, true, 1, NULL, 0,
                                     &uv_verified) == ZF_CTAP_ERR_OTHER,
           "successful pinAuth should fail closed when clearing retry state cannot persist");
    expect(state.pin_consecutive_mismatches == 2,
           "failed clear should preserve in-memory pinAuth mismatch count");
    expect(!state.pin_auth_blocked, "failed clear should preserve in-memory auth block flag");
}

static void test_get_assertion_polls_control_without_holding_ui_mutex(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t request[256];
    uint8_t response[512];
    size_t response_len = 0;
    ZfCredentialRecord record = {0};

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    seed_assertion_queue_record(&record, 0xAB, 4);
    strcpy(record.rp_id, "example.com");
    zf_store_index_entry_from_record(&record, &app.store.records[0]);
    app.store.count = 1;
    g_transport_poll_requires_unlocked = true;

    response_len = zerofido_handle_ctap2(
        &app, 0x01020304, request, encode_get_assertion_ctap_request(request, sizeof(request)),
        response, sizeof(response));

    expect(response_len > 1, "GetAssertion should still succeed when poll requires unlocked state");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "GetAssertion should poll transport control without holding the UI mutex");
}

static void test_get_next_assertion_polls_control_without_holding_ui_mutex(void) {
    Storage storage = {0};
    ZerofidoApp app = {0};
    ZfCredentialIndexEntry app_store_records[ZF_MAX_CREDENTIALS] = {0};
    app.store.records = app_store_records;
    FuriMutex ui_mutex = {0};
    uint8_t response[256];
    size_t response_len = 0;

    test_storage_reset();
    app.storage = &storage;
    app.ui_mutex = &ui_mutex;
    app.store.count = 2;
    seed_assertion_queue_record(&app.store.records[0], 0x11, 4);
    seed_assertion_queue_record(&app.store.records[1], 0x22, 5);

    app.assertion_queue.active = true;
    app.assertion_queue.session_id = 0x01020304;
    app.assertion_queue.count = 2;
    app.assertion_queue.index = 1;
    app.assertion_queue.expires_at = g_fake_tick + ZF_ASSERTION_QUEUE_TIMEOUT_MS;
    strcpy(app.assertion_queue.request.rp_id, "example.com");
    memcpy(app.assertion_queue.request.client_data_hash,
           (const uint8_t[ZF_CLIENT_DATA_HASH_LEN]){0x7D}, ZF_CLIENT_DATA_HASH_LEN);
    app.assertion_queue.record_indices[0] = 0;
    app.assertion_queue.record_indices[1] = 1;
    g_transport_poll_requires_unlocked = true;

    response_len =
        zerofido_handle_ctap2(&app, 0x01020304, (const uint8_t[]){ZfCtapeCmdGetNextAssertion}, 1,
                              response, sizeof(response));

    expect(response_len > 1, "GetNextAssertion should still succeed when poll needs unlocked UI");
    expect(response[0] == ZF_CTAP_SUCCESS,
           "GetNextAssertion should poll transport control without holding the UI mutex");
}

static void test_store_add_record_failure_keeps_original_record(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    store.records = store_records;
    ZfCredentialRecord first = {0};
    ZfCredentialRecord second = {0};
    ZfCredentialRecord loaded = {0};

    test_storage_reset();
    strcpy(first.rp_id, "example.com");
    strcpy(second.rp_id, "example.com");
    memcpy(first.user_id, "user", 4);
    memcpy(second.user_id, "user", 4);
    first.user_id_len = 4;
    second.user_id_len = 4;
    first.in_use = true;
    second.in_use = true;
    first.resident_key = true;
    second.resident_key = true;
    first.credential_id_len = ZF_CREDENTIAL_ID_LEN;
    second.credential_id_len = ZF_CREDENTIAL_ID_LEN;
    memset(first.credential_id, 0x10, ZF_CREDENTIAL_ID_LEN);
    memset(second.credential_id, 0x20, ZF_CREDENTIAL_ID_LEN);
    strcpy(first.file_name, k_repeated_credential_file_name);
    strcpy(second.file_name, "2020202020202020202020202020202020202020202020202020202020202020");

    expect(test_zf_store_add_record(&storage, &store, &first), "write original resident record");

    g_storage_fail_rename_match = second.file_name;
    expect(!test_zf_store_add_record(&storage, &store, &second),
           "adding a second resident record should fail when its rename fails");
    expect(store.count == 1, "failed add must keep in-memory store unchanged");
    expect(memcmp(store.records[0].credential_id, first.credential_id, ZF_CREDENTIAL_ID_LEN) == 0,
           "failed add must keep original credential in memory");
    expect(test_zf_store_record_format_load_record(&storage, first.file_name, &loaded),
           "failed add should keep original file on disk");
    expect(!test_zf_store_record_format_load_record(&storage, second.file_name, &loaded),
           "failed add must not leave the second record committed");
}

static void test_store_file_advances_record_rollback_to_counter_high_water(void) {
    Storage storage = {0};
    ZfCredentialRecord record = {0};
    ZfCredentialRecord loaded = {0};
    TestStorageFile *record_slot = NULL;
    TestStorageFile *counter_slot = NULL;
    uint8_t original_bytes[TEST_STORAGE_MAX_FILE_SIZE];
    size_t original_size = 0;
    char record_path[128];
    char counter_path[128];

    test_storage_reset();
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare rollback test credential");
    record.sign_count = 3;
    expect(test_zf_store_record_format_write_record(&storage, &record),
           "write initial credential record for rollback test");

    snprintf(record_path, sizeof(record_path), "%s/%s", ZF_APP_DATA_DIR, record.file_name);
    snprintf(counter_path, sizeof(counter_path), "%s/%s.counter", ZF_APP_DATA_DIR,
             record.file_name);
    record_slot = test_storage_file_slot(record_path, false);
    counter_slot = test_storage_file_slot(counter_path, false);
    expect(record_slot != NULL && record_slot->exists,
           "initial credential record should exist in storage");
    expect(counter_slot != NULL && counter_slot->exists,
           "initial counter floor should exist in storage");

    memcpy(original_bytes, record_slot->data, record_slot->size);
    original_size = record_slot->size;

    record.sign_count = 9;
    expect(test_zf_store_record_format_write_record(&storage, &record),
           "write updated credential record for rollback test");
    expect(counter_slot->exists && counter_slot->size > 0,
           "updated counter floor should remain present");

    memcpy(record_slot->data, original_bytes, original_size);
    record_slot->size = original_size;
    record_slot->exists = true;

    expect(test_zf_store_record_format_load_record(&storage, record.file_name, &loaded),
           "rolled-back records should load using the counter high-water mark");
    expect(loaded.sign_count == 9,
           "rolled-back record sign count should advance to the counter high-water mark");
}

static void test_store_advance_counter_uses_reserved_counter_window(void) {
    Storage storage = {0};
    ZfCredentialStore store = {0};
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS] = {0};
    ZfCredentialRecord record = {0};

    test_storage_reset();
    store.records = store_records;
    store.count = 1;
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential for counter high-water test");
    zf_store_index_entry_from_record(&record, &store.records[0]);
    store.records[0].counter_high_water = 2;

    record.sign_count = 1;
    expect(zf_store_advance_counter(&storage, &store, &record),
           "counter inside high-water window should advance in memory");
    expect(g_storage_counter_rename_count == 0,
           "counter inside high-water window should not rewrite the counter file");
    expect(store.records[0].sign_count == 1, "in-memory sign count should advance");

    record.sign_count = 3;
    expect(zf_store_advance_counter(&storage, &store, &record),
           "counter past high-water window should reserve a new window");
    expect(g_storage_counter_rename_count == 1,
           "crossing high-water should rewrite only the small counter file");
    expect(store.records[0].counter_high_water > record.sign_count,
           "new counter high-water should reserve future assertions");

    record.sign_count = 4;
    expect(zf_store_advance_counter(&storage, &store, &record),
           "counter inside the new high-water window should advance");
    expect(g_storage_counter_rename_count == 1,
           "counter file should not be rewritten again inside the new window");
}

static void test_store_file_write_and_load_fail_closed_without_counter_floor_crypto(void) {
    Storage storage = {0};
    ZfCredentialRecord record = {0};
    ZfCredentialRecord loaded = {0};
    char record_path[128];
    char counter_path[128];
    TestStorageFile *record_slot = NULL;
    TestStorageFile *counter_slot = NULL;

    test_storage_reset();
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential for counter floor crypto failure test");
    record.sign_count = 4;
    g_fail_crypto_enclave_load_key = true;
    expect(!test_zf_store_record_format_write_record(&storage, &record),
           "record write should fail closed without counter floor encryption");

    snprintf(record_path, sizeof(record_path), "%s/%s", ZF_APP_DATA_DIR, record.file_name);
    snprintf(counter_path, sizeof(counter_path), "%s/%s.counter", ZF_APP_DATA_DIR,
             record.file_name);
    record_slot = test_storage_file_slot(record_path, false);
    counter_slot = test_storage_file_slot(counter_path, false);
    expect(record_slot == NULL || !record_slot->exists,
           "record file must not be committed when counter floor encryption fails");
    expect(counter_slot == NULL || !counter_slot->exists,
           "counter floor should be absent when encryption is unavailable");

    expect(!test_zf_store_record_format_load_record(&storage, record.file_name, &loaded),
           "record load should fail closed without a committed record");
}

static void test_store_file_write_counter_floor_failure_prevents_record_commit(void) {
    Storage storage = {0};
    ZfCredentialRecord record = {0};
    char record_path[128];
    char counter_path[128];
    TestStorageFile *record_slot = NULL;
    TestStorageFile *counter_slot = NULL;

    test_storage_reset();
    expect(zf_store_prepare_credential(&record, "example.com", (const uint8_t *)"user-1", 6,
                                       "alice", "Alice", true),
           "prepare credential for counter floor failure test");
    record.sign_count = 4;
    g_storage_fail_rename_match = ".counter";

    expect(!test_zf_store_record_format_write_record(&storage, &record),
           "record write should fail when counter floor commit fails");

    snprintf(record_path, sizeof(record_path), "%s/%s", ZF_APP_DATA_DIR, record.file_name);
    snprintf(counter_path, sizeof(counter_path), "%s/%s.counter", ZF_APP_DATA_DIR,
             record.file_name);
    record_slot = test_storage_file_slot(record_path, false);
    counter_slot = test_storage_file_slot(counter_path, false);
    expect(record_slot == NULL || !record_slot->exists,
           "record file must not be committed before the counter floor");
    expect(counter_slot == NULL || !counter_slot->exists,
           "failed counter floor commit must not publish a counter file");
}

int main(void) {
    test_command_scratch_is_fixed_lifetime_and_single_owner();
    test_record_decode_rejects_partial_record();
    test_record_decode_accepts_complete_record();
    test_record_encode_accepts_large_resident_record_with_hmac_secret();
    test_record_decode_rejects_embedded_nul_text();
    test_record_decode_rejects_file_name_mismatch();
    test_record_decode_rejects_oversized_version();
    test_record_decode_rejects_unsupported_record_version();
    test_store_init_ignores_unsupported_record_file();
    test_cbor_text_read_rejects_declared_length_past_buffer();
    test_cbor_skip_rejects_declared_length_past_buffer();
    test_cbor_skip_accepts_single_precision_float();
    test_cbor_read_uint_rejects_noncanonical_encoding();
    test_cbor_read_text_rejects_noncanonical_length();
    test_get_assertion_parse_treats_empty_allow_list_as_omitted();
    test_get_assertion_parse_skips_unknown_float_member();
    test_get_assertion_parse_rejects_duplicate_top_level_key();
    test_get_assertion_parse_rejects_duplicate_option_key();
    test_get_assertion_parse_ignores_unknown_true_option();
    test_get_assertion_parse_ignores_unknown_false_option();
    test_get_assertion_parse_rejects_zero_length_descriptor_id();
    test_get_assertion_parse_accepts_oversized_descriptor_id();
    test_get_assertion_parse_rejects_duplicate_descriptor_type_after_invalid_value();
    test_get_assertion_parse_rejects_embedded_nul_rp_id();
    test_get_assertion_parse_rejects_invalid_utf8_rp_id();
    test_get_assertion_parse_accepts_rk_false_option();
    test_get_assertion_parse_rejects_rk_true_option_with_unsupported_option();
    test_make_credential_parse_skips_unknown_simple_value();
    test_make_credential_parse_ignores_unknown_true_option();
    test_make_credential_parse_rejects_duplicate_user_name();
    test_make_credential_parse_accepts_64_byte_display_name();
    test_make_credential_parse_rejects_non_text_rp_name();
    test_make_credential_parse_rejects_non_text_rp_icon();
    test_make_credential_parse_rejects_non_text_user_icon();
    test_get_assertion_parse_accepts_253_byte_rp_id();
    test_assertion_response_user_fields_follow_uv();
    test_client_pin_parse_rejects_trailing_bytes();
    test_client_pin_get_retries_accepts_missing_pin_protocol();
    test_client_pin_get_key_agreement_requires_pin_protocol();
    test_client_pin_parse_rejects_duplicate_top_level_keys();
    test_client_pin_parse_rejects_duplicate_key_agreement_keys();
    test_client_pin_key_agreement_requires_alg();
    test_make_credential_parse_rejects_malformed_pubkey_cred_params();
    test_make_credential_parse_rejects_non_public_key_pubkey_cred_param_as_unsupported_algorithm();
    test_make_credential_parse_rejects_zero_length_exclude_id();
    test_make_credential_parse_rejects_duplicate_exclude_descriptors();
    test_make_credential_parse_accepts_oversized_exclude_id();
    test_make_credential_parse_ignores_non_public_key_exclude_descriptor();
    test_make_credential_parse_rejects_empty_user_id();
    test_get_assertion_parse_rejects_duplicate_allow_list_descriptors();
    test_get_assertion_parse_rejects_too_many_allow_list_descriptors();
    test_get_assertion_parse_rejects_duplicate_oversized_allow_list_descriptors();
    test_get_assertion_parse_ignores_non_public_key_allow_list_descriptor();
    test_store_find_by_rp_orders_records_by_newest_first();
    test_store_descriptor_list_ignores_oversized_descriptor_ids();
    test_pin_auth_block_state_clears_on_reinit_but_keeps_retries();
    test_pin_plaintext_accepts_ctap_max_utf8_length();
    test_pin_resume_auth_attempts_clears_persisted_block();
    test_pin_clear_removes_persisted_state_and_resets_runtime();
    test_pin_init_rejects_unsupported_format_state();
    test_pin_init_rejects_unsupported_current_format_version();
    test_pin_init_rejects_tampered_retry_state();
    test_pin_auth_blocks_after_three_mismatches();
    test_ui_format_approval_header_prefixes_protocol();
    test_ui_format_approval_body_uses_protocol_specific_target_label();
    test_ui_format_fido2_credential_label_uses_passkey_text();
    test_ui_format_fido2_credential_detail_uses_user_facing_text();
    test_ui_hex_encode_truncated_limits_output();
    test_get_pin_token_wrong_pin_regenerates_key_agreement();
    test_get_key_agreement_does_not_rotate_runtime_secrets();
    test_get_pin_token_success_rotates_pin_token();
    test_get_pin_token_experimental_2_1_requires_consent();
    test_get_pin_token_protocol2_returns_iv_prefixed_token();
    test_client_pin_protocol2_requires_experimental_profile();
    test_get_pin_token_decrypt_failure_consumes_retry();
    test_get_pin_token_rejects_permissions_fields();
    test_client_pin_permissions_subcommand_requires_permissions();
    test_client_pin_permissions_subcommand_rejects_zero_permissions();
    test_client_pin_permissions_subcommand_rejects_unsupported_permissions();
    test_client_pin_permissions_subcommand_requires_rp_id_for_mc_ga();
    test_client_pin_permissions_subcommand_experimental_validates_parameters();
    test_client_pin_permissions_subcommand_stores_permissions_and_rp_id();
    test_client_pin_permissions_subcommand_issued_token_consumes_mc_after_up();
    test_client_pin_permissions_subcommand_denied_consent_does_not_issue_token();
    test_client_pin_permissions_subcommand_rejects_unsupported_be_permission();
    test_pin_auth_rejects_expired_pin_token();
    test_pin_auth_protocol2_accepts_full_hmac();
    test_legacy_pin_token_allows_reuse_without_rp_binding();
    test_pin_auth_rejects_missing_required_permission();
    test_change_pin_invalid_new_pin_after_correct_current_pin_resets_retries();
    test_change_pin_preserves_key_agreement_on_success();
    test_set_pin_invalid_new_pin_block_is_rejected();
    test_set_pin_new_pin_decrypt_failure_returns_pin_auth_invalid();
    test_set_pin_rejects_oversized_new_pin_block();
    test_set_pin_preserves_key_agreement_on_success();
    test_set_pin_creates_app_data_dir_before_persisting();
    test_change_pin_pin_hash_decrypt_failure_consumes_retry();
    test_change_pin_new_pin_decrypt_failure_returns_pin_auth_invalid();
    test_pin_init_cleans_temp_file();
    test_store_resident_records_for_same_user_coexist_after_reload();
    test_store_wipe_app_data_clears_credentials_and_pin_state();
    test_runtime_config_load_defaults_auto_accept_off();
    test_runtime_config_persist_round_trips_auto_accept_setting();
    test_runtime_config_persist_round_trips_transport_mode();
    test_runtime_config_persist_round_trips_fido2_profile();
    test_runtime_config_persist_round_trips_attestation_mode();
    test_runtime_config_set_attestation_mode_updates_capabilities();
    test_runtime_config_set_fido2_profile_updates_capabilities();
    test_runtime_config_set_fido2_profile_requires_pin_for_2_1();
    test_runtime_config_apply_downgrades_2_1_when_pin_is_unset();
    test_runtime_config_pin_refresh_restores_requested_2_1_profile();
    test_runtime_config_persist_preserves_requested_2_1_after_pin_clear();
    test_runtime_config_load_invalid_file_falls_back_to_defaults();
    test_runtime_config_load_rejects_unsupported_version();
    test_runtime_config_set_auto_accept_preserves_runtime_state_on_persist_failure();
    test_runtime_config_set_fido2_preserves_runtime_state_on_persist_failure();
    test_runtime_config_set_fido2_profile_preserves_runtime_state_on_persist_failure();
    test_runtime_config_set_attestation_preserves_runtime_state_on_persist_failure();
    test_ctap_error_response_omits_body_when_store_add_fails();
    test_make_credential_rejects_local_maintenance_window();
    test_make_credential_empty_pin_auth_requires_pin_protocol();
    test_get_assertion_empty_pin_auth_requires_pin_protocol();
    test_make_credential_empty_pin_auth_probe_returns_pin_status_after_touch();
    test_get_assertion_empty_pin_auth_probe_returns_pin_status_after_touch();
    test_get_assertion_uv_without_pin_auth_returns_unsupported_option();
    test_make_credential_uv_without_pin_auth_returns_unsupported_option();
    test_make_credential_pin_auth_takes_precedence_over_uv();
    test_make_credential_pin_auth_clears_permission_scoped_token_after_up();
    test_make_credential_legacy_pin_token_keeps_mc_ga_after_up();
    test_make_credential_requires_pin_auth_when_pin_is_set();
    test_make_credential_auto_accept_bypasses_approval_prompt();
    test_make_credential_unknown_option_succeeds();
    test_make_credential_returns_packed_attestation();
    test_make_credential_runtime_none_returns_none_attestation();
    test_make_credential_attestation_preference_overrides_runtime_default();
    test_make_credential_attestation_preference_uses_lowest_supported_index();
    test_make_credential_response_does_not_downgrade_required_packed();
    test_make_credential_nfc_auto_accept_keeps_uv_clear();
    test_make_credential_nfc_auto_accept_rejects_uv_option_without_pin();
    test_get_assertion_pin_auth_takes_precedence_over_uv();
    test_get_assertion_pin_auth_clears_permission_scoped_token_after_up();
    test_permission_scoped_pin_token_rejects_browser_style_replay_after_mc();
    test_get_assertion_legacy_pin_token_keeps_mc_ga_after_up();
    test_get_assertion_allows_discouraged_uv_when_pin_is_set();
    test_get_assertion_auto_accept_bypasses_approval_prompt();
    test_get_assertion_discovers_no_credentials_without_uv_for_cred_protect_2();
    test_get_assertion_with_pin_auth_allows_discoverable_cred_protect_2();
    test_make_credential_overwrites_resident_credential_for_same_user();
    test_make_credential_cred_protect_round_trips_into_auth_data_and_store();
    test_make_credential_hmac_secret_round_trips_into_auth_data_and_store();
    test_get_assertion_hmac_secret_builds_protocol1_output();
    test_assertion_response_preserves_scratch_hmac_secret_extension();
    test_make_credential_excluded_credential_returns_excluded_after_timeout();
    test_make_credential_exclude_list_hides_uv_required_credential_without_uv();
    test_make_credential_exclude_list_reveals_uv_required_credential_with_pin_auth();
    test_get_assertion_without_matching_credential_waits_for_approval_before_no_credentials();
    test_get_assertion_invalid_allow_list_waits_for_approval_before_no_credentials();
    test_get_assertion_multi_match_uses_account_selection();
    test_get_assertion_multi_match_experimental_2_1_includes_user_selected();
    test_get_assertion_up_false_multi_match_stays_silent();
    test_get_assertion_multi_match_selection_denied_returns_operation_denied();
    test_get_assertion_multi_match_selection_cancel_returns_keepalive_cancel();
    test_get_assertion_multi_match_selection_timeout_returns_operation_denied();
    test_get_assertion_multi_match_keeps_account_selection_when_auto_accept_is_on();
    test_get_assertion_allow_list_does_not_open_account_selection();
    test_get_next_assertion_rejects_wrong_cid();
    test_get_next_assertion_refreshes_queue_expiry();
    test_get_next_assertion_rejects_empty_queue();
    test_get_next_assertion_rejects_expired_queue();
    test_get_next_assertion_clears_final_queue_state();
    test_get_next_assertion_missing_record_clears_queue();
    test_get_next_assertion_rejects_trailing_payload();
    test_get_info_rejects_trailing_payload();
    test_get_info_success_updates_status_banner();
    test_get_info_advertises_cred_protect_extension();
    test_get_info_advertises_hmac_secret_extension();
    test_get_info_advertises_fido_2_0_without_fido_2_1();
    test_get_info_nfc_ctap2_0_advertises_transport_compactly();
    test_get_info_experimental_2_1_advertises_pin_uv_auth_token();
    test_get_info_advertises_u2f();
    test_get_info_reports_firmware_version();
    test_ctap_reset_succeeds_and_wipes_runtime_state();
    test_ctap_reset_auto_accept_bypasses_approval_prompt();
    test_ctap_reset_succeeds_when_u2f_reinit_fails();
    test_ctap_reset_rejects_trailing_payload();
    test_client_pin_get_key_agreement_updates_status_banner();
    test_selection_touch_succeeds_and_updates_status_banner();
    test_selection_touch_rejects_default_ctap2_0_profile();
    test_selection_touch_auto_accept_bypasses_approval_prompt();
    test_store_cleanup_restores_backup_when_primary_is_missing();
    test_store_remove_record_paths_deletes_atomic_backups();
    test_atomic_file_write_overwrites_primary_without_predelete();
    test_atomic_file_write_failure_keeps_primary();
    test_atomic_file_recovery_restores_backup_when_primary_missing();
    test_atomic_file_remove_deletes_primary_temp_and_backup();
    test_pin_auth_mismatch_keeps_block_state_when_persist_fails();
    test_wrong_pin_keeps_retry_state_when_persist_fails();
    test_pin_persist_failure_poison_blocks_reinit_after_wrong_pin();
    test_pin_persist_failure_poison_blocks_reinit_after_pin_auth_mismatch();
    test_pin_persist_failure_falls_back_to_remove_when_poison_write_fails();
    test_correct_pin_auth_keeps_retry_state_when_persist_fails();
    test_get_assertion_polls_control_without_holding_ui_mutex();
    test_get_next_assertion_polls_control_without_holding_ui_mutex();
    test_store_add_record_failure_keeps_original_record();
    test_store_file_advances_record_rollback_to_counter_high_water();
    test_store_advance_counter_uses_reserved_counter_window();
    test_store_file_write_and_load_fail_closed_without_counter_floor_crypto();
    test_store_file_write_counter_floor_failure_prevents_record_commit();
    puts("native protocol regressions passed");
    return 0;
}
