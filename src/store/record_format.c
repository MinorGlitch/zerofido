#include "record_format.h"

#include <furi.h>
#include <furi_hal.h>
#include <string.h>

#include "../zerofido_cbor.h"
#include "../zerofido_crypto.h"
#include "internal.h"
#include "record_format_internal.h"

#define ZF_STORE_VERSION ZF_STORE_FORMAT_VERSION
#define ZF_COUNTER_SEAL_SIZE 32
#define ZF_COUNTER_SEAL_MAGIC 0x53434631UL
#define ZF_COUNTER_FLOOR_MAGIC 0x53434632UL
#define ZF_COUNTER_FLOOR_VERSION 1U

enum {
    ZfRecordKeyVersion = 1,
    ZfRecordKeyCredentialId = 2,
    ZfRecordKeyRpId = 3,
    ZfRecordKeyUserId = 4,
    ZfRecordKeyUserName = 5,
    ZfRecordKeyDisplayName = 6,
    ZfRecordKeyPublicX = 7,
    ZfRecordKeyPublicY = 8,
    ZfRecordKeyPrivateWrapped = 9,
    ZfRecordKeyPrivateIv = 10,
    ZfRecordKeySignCount = 11,
    ZfRecordKeyCreatedAt = 12,
    ZfRecordKeyResidentKey = 13,
    ZfRecordKeyCounterSealIv = 14,
    ZfRecordKeyCounterSeal = 15,
    ZfRecordKeyCredProtect = 16,
};

typedef struct {
    uint32_t magic;
    uint32_t sign_count;
    uint8_t digest[24];
} ZfRecordCounterSeal;

typedef struct {
    uint32_t magic;
    uint32_t sign_count;
    uint8_t binding[24];
} ZfCounterFloorSeal;

typedef struct {
    uint32_t version;
    uint8_t iv[ZF_WRAP_IV_LEN];
    uint8_t sealed[sizeof(ZfCounterFloorSeal)];
} ZfCounterFloorFile;

static void zf_record_compute_counter_binding(const ZfCredentialRecord *record,
                                              uint8_t binding[24]) {
    uint8_t material[ZF_CREDENTIAL_ID_LEN + sizeof(record->created_at)];
    uint8_t full_digest[ZF_COUNTER_SEAL_SIZE];
    size_t offset = 0;

    memcpy(material + offset, record->credential_id, sizeof(record->credential_id));
    offset += sizeof(record->credential_id);
    memcpy(material + offset, &record->created_at, sizeof(record->created_at));
    offset += sizeof(record->created_at);
    zf_crypto_sha256(material, offset, full_digest);
    memcpy(binding, full_digest, 24);
    memset(full_digest, 0, sizeof(full_digest));
}

static void zf_record_compute_counter_digest(const ZfCredentialRecord *record, uint8_t digest[24]) {
    uint8_t material[24 + sizeof(record->sign_count)];
    uint8_t binding[24];
    uint8_t full_digest[ZF_COUNTER_SEAL_SIZE];
    size_t offset = 0;

    zf_record_compute_counter_binding(record, binding);
    memcpy(material + offset, binding, sizeof(binding));
    offset += sizeof(binding);
    memcpy(material + offset, &record->sign_count, sizeof(record->sign_count));
    offset += sizeof(record->sign_count);
    zf_crypto_sha256(material, offset, full_digest);
    memcpy(digest, full_digest, 24);
    memset(binding, 0, sizeof(binding));
    memset(full_digest, 0, sizeof(full_digest));
}

static bool zf_record_seal_counter(const ZfCredentialRecord *record, uint8_t iv[ZF_WRAP_IV_LEN],
                                   uint8_t sealed[ZF_COUNTER_SEAL_SIZE]) {
    ZfRecordCounterSeal plain = {
        .magic = ZF_COUNTER_SEAL_MAGIC,
        .sign_count = record->sign_count,
    };

    zf_record_compute_counter_digest(record, plain.digest);
    furi_hal_random_fill_buf(iv, ZF_WRAP_IV_LEN);
    if (!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_encrypt((const uint8_t *)&plain, sealed, sizeof(plain));
    furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    memset(&plain, 0, sizeof(plain));
    return ok;
}

static bool zf_record_verify_counter_seal(const ZfCredentialRecord *record,
                                          const uint8_t iv[ZF_WRAP_IV_LEN],
                                          const uint8_t sealed[ZF_COUNTER_SEAL_SIZE]) {
    ZfRecordCounterSeal plain = {0};
    uint8_t expected_digest[24];

    if (!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_decrypt(sealed, (uint8_t *)&plain, sizeof(plain));
    furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    if (!ok || plain.magic != ZF_COUNTER_SEAL_MAGIC || plain.sign_count != record->sign_count) {
        memset(&plain, 0, sizeof(plain));
        return false;
    }

    zf_record_compute_counter_digest(record, expected_digest);
    ok = zf_crypto_constant_time_equal(plain.digest, expected_digest, sizeof(plain.digest));
    memset(expected_digest, 0, sizeof(expected_digest));
    memset(&plain, 0, sizeof(plain));
    return ok;
}

static bool zf_counter_floor_encode(const ZfCredentialRecord *record,
                                    ZfCounterFloorFile *out_file) {
    ZfCounterFloorSeal plain = {
        .magic = ZF_COUNTER_FLOOR_MAGIC,
        .sign_count = record->sign_count,
    };

    memset(out_file, 0, sizeof(*out_file));
    out_file->version = ZF_COUNTER_FLOOR_VERSION;
    zf_record_compute_counter_binding(record, plain.binding);
    furi_hal_random_fill_buf(out_file->iv, sizeof(out_file->iv));
    if (!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT, out_file->iv)) {
        memset(&plain, 0, sizeof(plain));
        memset(out_file, 0, sizeof(*out_file));
        return false;
    }

    bool ok = furi_hal_crypto_encrypt((const uint8_t *)&plain, out_file->sealed, sizeof(plain));
    furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    memset(&plain, 0, sizeof(plain));
    if (!ok) {
        memset(out_file, 0, sizeof(*out_file));
    }
    return ok;
}

static bool zf_counter_floor_decode(const ZfCredentialRecord *record,
                                    const ZfCounterFloorFile *counter_file,
                                    uint32_t *stored_sign_count) {
    ZfCounterFloorSeal plain = {0};
    uint8_t expected_binding[24];

    if (!record || !counter_file || !stored_sign_count ||
        counter_file->version != ZF_COUNTER_FLOOR_VERSION) {
        return false;
    }
    if (!furi_hal_crypto_enclave_load_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT,
                                          counter_file->iv)) {
        return false;
    }

    bool ok = furi_hal_crypto_decrypt(counter_file->sealed, (uint8_t *)&plain, sizeof(plain));
    furi_hal_crypto_enclave_unload_key(FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT);
    if (!ok || plain.magic != ZF_COUNTER_FLOOR_MAGIC) {
        memset(&plain, 0, sizeof(plain));
        return false;
    }

    zf_record_compute_counter_binding(record, expected_binding);
    ok = zf_crypto_constant_time_equal(plain.binding, expected_binding, sizeof(plain.binding));
    if (ok) {
        *stored_sign_count = plain.sign_count;
    }
    memset(expected_binding, 0, sizeof(expected_binding));
    memset(&plain, 0, sizeof(plain));
    return ok;
}

static bool zf_store_counter_floor_write(Storage *storage, const ZfCredentialRecord *record) {
    ZfCounterFloorFile counter_file;
    char path[128];
    char temp_path[128];
    File *file = NULL;
    bool opened = false;
    bool wrote = false;
    bool renamed = false;

    if (!storage || !record) {
        return false;
    }
    if (!zf_counter_floor_encode(record, &counter_file)) {
        return false;
    }

    file = storage_file_alloc(storage);
    if (!file) {
        memset(&counter_file, 0, sizeof(counter_file));
        return false;
    }

    zf_store_build_counter_floor_path(record->file_name, path, sizeof(path));
    zf_store_build_counter_floor_temp_path(record->file_name, temp_path, sizeof(temp_path));
    storage_common_remove(storage, temp_path);
    opened = storage_file_open(file, temp_path, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    wrote = opened &&
            (storage_file_write(file, &counter_file, sizeof(counter_file)) == sizeof(counter_file));
    storage_file_close(file);
    renamed = wrote && (storage_common_rename(storage, temp_path, path) == FSE_OK);
    storage_common_remove(storage, temp_path);
    storage_file_free(file);
    memset(&counter_file, 0, sizeof(counter_file));
    return renamed;
}

static bool zf_store_counter_floor_validate(Storage *storage, const ZfCredentialRecord *record) {
    char path[128];
    uint8_t buffer[sizeof(ZfCounterFloorFile)] = {0};
    size_t size = 0;
    uint32_t stored_sign_count = 0;
    File *file = NULL;

    if (!storage || !record) {
        return false;
    }

    zf_store_build_counter_floor_path(record->file_name, path, sizeof(path));
    if (!storage_file_exists(storage, path)) {
        (void)zf_store_counter_floor_write(storage, record);
        return true;
    }

    file = storage_file_alloc(storage);
    if (!file) {
        return false;
    }
    if (!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return true;
    }

    size = storage_file_size(file);
    if (size != sizeof(ZfCounterFloorFile) || storage_file_read(file, buffer, size) != size) {
        storage_file_close(file);
        storage_file_free(file);
        return true;
    }

    storage_file_close(file);
    storage_file_free(file);
    if (!zf_counter_floor_decode(record, (const ZfCounterFloorFile *)buffer, &stored_sign_count)) {
        return true;
    }
    if (stored_sign_count > record->sign_count) {
        return false;
    }
    if (stored_sign_count < record->sign_count) {
        (void)zf_store_counter_floor_write(storage, record);
    }
    return true;
}

bool zf_store_record_format_encode(const ZfCredentialRecord *record, uint8_t *out,
                                   size_t *out_size) {
    ZfCborEncoder enc;
    uint8_t counter_iv[ZF_WRAP_IV_LEN];
    uint8_t counter_seal[ZF_COUNTER_SEAL_SIZE];
    uint8_t effective_cred_protect =
        record->cred_protect == 0 ? ZF_CRED_PROTECT_UV_OPTIONAL : record->cred_protect;
    bool have_counter_seal = false;

    if (!zf_cbor_encoder_init(&enc, out, ZF_STORE_RECORD_MAX_SIZE)) {
        return false;
    }
    have_counter_seal = zf_record_seal_counter(record, counter_iv, counter_seal);

    bool ok =
        zf_cbor_encode_map(&enc, have_counter_seal ? 16 : 14) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyVersion) &&
        zf_cbor_encode_uint(&enc, ZF_STORE_VERSION) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyCredentialId) &&
        zf_cbor_encode_bytes(&enc, record->credential_id, record->credential_id_len) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyRpId) && zf_cbor_encode_text(&enc, record->rp_id) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyUserId) &&
        zf_cbor_encode_bytes(&enc, record->user_id, record->user_id_len) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyUserName) &&
        zf_cbor_encode_text(&enc, record->user_name) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyDisplayName) &&
        zf_cbor_encode_text(&enc, record->user_display_name) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyPublicX) &&
        zf_cbor_encode_bytes(&enc, record->public_x, sizeof(record->public_x)) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyPublicY) &&
        zf_cbor_encode_bytes(&enc, record->public_y, sizeof(record->public_y)) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyPrivateWrapped) &&
        zf_cbor_encode_bytes(&enc, record->private_wrapped, sizeof(record->private_wrapped)) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyPrivateIv) &&
        zf_cbor_encode_bytes(&enc, record->private_iv, sizeof(record->private_iv)) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeySignCount) &&
        zf_cbor_encode_uint(&enc, record->sign_count) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyCreatedAt) &&
        zf_cbor_encode_uint(&enc, record->created_at) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyResidentKey) &&
        zf_cbor_encode_bool(&enc, record->resident_key) &&
        zf_cbor_encode_uint(&enc, ZfRecordKeyCredProtect) &&
        zf_cbor_encode_uint(&enc, effective_cred_protect);

    if (ok && have_counter_seal) {
        ok = zf_cbor_encode_uint(&enc, ZfRecordKeyCounterSealIv) &&
             zf_cbor_encode_bytes(&enc, counter_iv, sizeof(counter_iv)) &&
             zf_cbor_encode_uint(&enc, ZfRecordKeyCounterSeal) &&
             zf_cbor_encode_bytes(&enc, counter_seal, sizeof(counter_seal));
    }

    if (!ok) {
        memset(counter_iv, 0, sizeof(counter_iv));
        memset(counter_seal, 0, sizeof(counter_seal));
        return false;
    }

    *out_size = zf_cbor_encoder_size(&enc);
    memset(counter_iv, 0, sizeof(counter_iv));
    memset(counter_seal, 0, sizeof(counter_seal));
    return true;
}

static bool zf_copy_text_field(char *out, size_t out_size, const uint8_t *data, size_t size) {
    if (size >= out_size || memchr(data, '\0', size) != NULL) {
        return false;
    }

    memcpy(out, data, size);
    out[size] = '\0';
    return true;
}

void zf_store_record_format_hex_encode(const uint8_t *data, size_t size, char *out) {
    static const char *hex = "0123456789abcdef";

    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = hex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[size * 2] = '\0';
}

static bool zf_record_file_name_matches_id(const ZfCredentialRecord *record,
                                           const char *file_name) {
    char expected_name[(ZF_CREDENTIAL_ID_LEN * 2) + 1];

    if (record->credential_id_len != ZF_CREDENTIAL_ID_LEN) {
        return false;
    }

    zf_store_record_format_hex_encode(record->credential_id, record->credential_id_len,
                                      expected_name);
    return strcmp(expected_name, file_name) == 0;
}

static bool zf_record_decode_text(char *out, size_t out_size, ZfCborCursor *cursor) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    return zf_cbor_read_text_ptr(cursor, &ptr, &size) &&
           zf_copy_text_field(out, out_size, ptr, size);
}

static bool zf_record_decode_bytes(uint8_t *target, size_t expected_size, ZfCborCursor *cursor) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    if (!zf_cbor_read_bytes_ptr(cursor, &ptr, &size) || size != expected_size) {
        return false;
    }

    memcpy(target, ptr, size);
    return true;
}

static bool zf_record_decode_version(ZfCborCursor *cursor, uint32_t *version) {
    uint64_t raw = 0;
    if (!zf_cbor_read_uint(cursor, &raw)) {
        return false;
    }
    if (raw > UINT32_MAX) {
        return false;
    }

    *version = (uint32_t)raw;
    return true;
}

static bool zf_record_decode_user_id(ZfCborCursor *cursor, ZfCredentialRecord *record) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    if (!zf_cbor_read_bytes_ptr(cursor, &ptr, &size) || size > ZF_MAX_USER_ID_LEN) {
        return false;
    }

    memcpy(record->user_id, ptr, size);
    record->user_id_len = size;
    return true;
}

static bool zf_record_decode_counter(ZfCborCursor *cursor, uint32_t *value) {
    uint64_t raw = 0;
    if (!zf_cbor_read_uint(cursor, &raw)) {
        return false;
    }
    if (raw > UINT32_MAX) {
        return false;
    }

    *value = (uint32_t)raw;
    return true;
}

static bool zf_record_decode_field(ZfCborCursor *cursor, uint64_t key, ZfCredentialRecord *record,
                                   uint32_t *version, uint8_t counter_iv[ZF_WRAP_IV_LEN],
                                   uint8_t counter_seal[ZF_COUNTER_SEAL_SIZE]) {
    switch (key) {
    case ZfRecordKeyVersion:
        return zf_record_decode_version(cursor, version);
    case ZfRecordKeyCredentialId:
        return zf_record_decode_bytes(record->credential_id, ZF_CREDENTIAL_ID_LEN, cursor);
    case ZfRecordKeyRpId:
        return zf_record_decode_text(record->rp_id, sizeof(record->rp_id), cursor);
    case ZfRecordKeyUserId:
        return zf_record_decode_user_id(cursor, record);
    case ZfRecordKeyUserName:
        return zf_record_decode_text(record->user_name, sizeof(record->user_name), cursor);
    case ZfRecordKeyDisplayName:
        return zf_record_decode_text(record->user_display_name, sizeof(record->user_display_name),
                                     cursor);
    case ZfRecordKeyPublicX:
        return zf_record_decode_bytes(record->public_x, sizeof(record->public_x), cursor);
    case ZfRecordKeyPublicY:
        return zf_record_decode_bytes(record->public_y, sizeof(record->public_y), cursor);
    case ZfRecordKeyPrivateWrapped:
        return zf_record_decode_bytes(record->private_wrapped, sizeof(record->private_wrapped),
                                      cursor);
    case ZfRecordKeyPrivateIv:
        return zf_record_decode_bytes(record->private_iv, sizeof(record->private_iv), cursor);
    case ZfRecordKeySignCount:
        return zf_record_decode_counter(cursor, &record->sign_count);
    case ZfRecordKeyCreatedAt:
        return zf_record_decode_counter(cursor, &record->created_at);
    case ZfRecordKeyResidentKey:
        return zf_cbor_read_bool(cursor, &record->resident_key);
    case ZfRecordKeyCredProtect: {
        uint64_t raw = 0;
        if (!zf_cbor_read_uint(cursor, &raw) || raw < ZF_CRED_PROTECT_UV_OPTIONAL ||
            raw > ZF_CRED_PROTECT_UV_REQUIRED) {
            return false;
        }
        record->cred_protect = (uint8_t)raw;
        return true;
    }
    case ZfRecordKeyCounterSealIv:
        return zf_record_decode_bytes(counter_iv, ZF_WRAP_IV_LEN, cursor);
    case ZfRecordKeyCounterSeal:
        return zf_record_decode_bytes(counter_seal, ZF_COUNTER_SEAL_SIZE, cursor);
    default:
        return zf_cbor_skip(cursor);
    }
}

static bool zf_record_decode(const uint8_t *data, size_t data_size, const char *file_name,
                             ZfCredentialRecord *out_record) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint32_t version = 0;
    uint8_t counter_iv[ZF_WRAP_IV_LEN] = {0};
    uint8_t counter_seal[ZF_COUNTER_SEAL_SIZE] = {0};
    bool saw_version = false;
    bool saw_credential_id = false;
    bool saw_rp_id = false;
    bool saw_user_id = false;
    bool saw_public_x = false;
    bool saw_public_y = false;
    bool saw_private_wrapped = false;
    bool saw_private_iv = false;
    bool saw_sign_count = false;
    bool saw_created_at = false;
    bool saw_resident_key = false;
    bool saw_cred_protect = false;
    bool saw_counter_iv = false;
    bool saw_counter_seal = false;

    memset(out_record, 0, sizeof(*out_record));
    strncpy(out_record->file_name, file_name, sizeof(out_record->file_name) - 1);
    out_record->credential_id_len = ZF_CREDENTIAL_ID_LEN;

    zf_cbor_cursor_init(&cursor, data, data_size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (!zf_record_decode_field(&cursor, key, out_record, &version, counter_iv, counter_seal)) {
            return false;
        }
        switch (key) {
        case ZfRecordKeyVersion:
            saw_version = true;
            break;
        case ZfRecordKeyCredentialId:
            saw_credential_id = true;
            break;
        case ZfRecordKeyRpId:
            saw_rp_id = true;
            break;
        case ZfRecordKeyUserId:
            saw_user_id = true;
            break;
        case ZfRecordKeyPublicX:
            saw_public_x = true;
            break;
        case ZfRecordKeyPublicY:
            saw_public_y = true;
            break;
        case ZfRecordKeyPrivateWrapped:
            saw_private_wrapped = true;
            break;
        case ZfRecordKeyPrivateIv:
            saw_private_iv = true;
            break;
        case ZfRecordKeySignCount:
            saw_sign_count = true;
            break;
        case ZfRecordKeyCreatedAt:
            saw_created_at = true;
            break;
        case ZfRecordKeyResidentKey:
            saw_resident_key = true;
            break;
        case ZfRecordKeyCredProtect:
            saw_cred_protect = true;
            break;
        case ZfRecordKeyCounterSealIv:
            saw_counter_iv = true;
            break;
        case ZfRecordKeyCounterSeal:
            saw_counter_seal = true;
            break;
        default:
            break;
        }
    }

    if (cursor.ptr != cursor.end) {
        return false;
    }
    if (!saw_version || !saw_credential_id || !saw_rp_id || !saw_user_id || !saw_public_x ||
        !saw_public_y || !saw_private_wrapped || !saw_private_iv || !saw_sign_count ||
        !saw_created_at || !saw_resident_key) {
        return false;
    }
    if (saw_counter_iv != saw_counter_seal) {
        return false;
    }
    if (version != ZF_STORE_VERSION || out_record->rp_id[0] == '\0' ||
        !zf_record_file_name_matches_id(out_record, file_name)) {
        return false;
    }
    if (!saw_cred_protect) {
        out_record->cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL;
    }
    if (saw_counter_iv && !zf_record_verify_counter_seal(out_record, counter_iv, counter_seal)) {
        return false;
    }

    out_record->storage_version = version;
    out_record->in_use = true;
    return true;
}

static bool zf_record_decode_user_id_index(ZfCborCursor *cursor, ZfCredentialIndexEntry *entry) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    if (!zf_cbor_read_bytes_ptr(cursor, &ptr, &size) || size > ZF_MAX_USER_ID_LEN) {
        return false;
    }

    memcpy(entry->user_id, ptr, size);
    entry->user_id_len = size;
    return true;
}

static bool zf_record_decode_index_field(ZfCborCursor *cursor, uint64_t key,
                                         ZfCredentialIndexEntry *entry, uint32_t *version,
                                         uint8_t counter_iv[ZF_WRAP_IV_LEN],
                                         uint8_t counter_seal[ZF_COUNTER_SEAL_SIZE]) {
    switch (key) {
    case ZfRecordKeyVersion:
        return zf_record_decode_version(cursor, version);
    case ZfRecordKeyCredentialId:
        return zf_record_decode_bytes(entry->credential_id, ZF_CREDENTIAL_ID_LEN, cursor);
    case ZfRecordKeyRpId:
        return zf_record_decode_text(entry->rp_id, sizeof(entry->rp_id), cursor);
    case ZfRecordKeyUserId:
        return zf_record_decode_user_id_index(cursor, entry);
    case ZfRecordKeyUserName:
        return zf_record_decode_text(entry->user_name, sizeof(entry->user_name), cursor);
    case ZfRecordKeyDisplayName:
        return zf_record_decode_text(entry->user_display_name, sizeof(entry->user_display_name),
                                     cursor);
    case ZfRecordKeySignCount:
        return zf_record_decode_counter(cursor, &entry->sign_count);
    case ZfRecordKeyCreatedAt:
        return zf_record_decode_counter(cursor, &entry->created_at);
    case ZfRecordKeyResidentKey:
        return zf_cbor_read_bool(cursor, &entry->resident_key);
    case ZfRecordKeyCredProtect: {
        uint64_t raw = 0;
        if (!zf_cbor_read_uint(cursor, &raw) || raw < ZF_CRED_PROTECT_UV_OPTIONAL ||
            raw > ZF_CRED_PROTECT_UV_REQUIRED) {
            return false;
        }
        entry->cred_protect = (uint8_t)raw;
        return true;
    }
    case ZfRecordKeyCounterSealIv:
        return zf_record_decode_bytes(counter_iv, ZF_WRAP_IV_LEN, cursor);
    case ZfRecordKeyCounterSeal:
        return zf_record_decode_bytes(counter_seal, ZF_COUNTER_SEAL_SIZE, cursor);
    default:
        return zf_cbor_skip(cursor);
    }
}

static void zf_record_index_to_stub_record(const char *file_name, const ZfCredentialIndexEntry *entry,
                                           ZfCredentialRecord *record) {
    memset(record, 0, sizeof(*record));
    record->in_use = entry->in_use;
    record->resident_key = entry->resident_key;
    strncpy(record->file_name, file_name, sizeof(record->file_name) - 1);
    memcpy(record->credential_id, entry->credential_id, sizeof(record->credential_id));
    record->credential_id_len = entry->credential_id_len;
    memcpy(record->rp_id, entry->rp_id, sizeof(record->rp_id));
    memcpy(record->user_id, entry->user_id, sizeof(record->user_id));
    record->user_id_len = entry->user_id_len;
    memcpy(record->user_name, entry->user_name, sizeof(record->user_name));
    memcpy(record->user_display_name, entry->user_display_name, sizeof(record->user_display_name));
    record->sign_count = entry->sign_count;
    record->created_at = entry->created_at;
    record->cred_protect = entry->cred_protect;
}

static bool zf_record_decode_index(const uint8_t *data, size_t data_size, const char *file_name,
                                   ZfCredentialIndexEntry *out_entry) {
    ZfCborCursor cursor;
    size_t pairs = 0;
    uint32_t version = 0;
    uint8_t counter_iv[ZF_WRAP_IV_LEN] = {0};
    uint8_t counter_seal[ZF_COUNTER_SEAL_SIZE] = {0};
    bool saw_version = false;
    bool saw_credential_id = false;
    bool saw_rp_id = false;
    bool saw_user_id = false;
    bool saw_sign_count = false;
    bool saw_created_at = false;
    bool saw_resident_key = false;
    bool saw_cred_protect = false;
    bool saw_counter_iv = false;
    bool saw_counter_seal = false;
    ZfCredentialRecord stub_record;

    memset(out_entry, 0, sizeof(*out_entry));
    strncpy(out_entry->file_name, file_name, sizeof(out_entry->file_name) - 1);
    out_entry->credential_id_len = ZF_CREDENTIAL_ID_LEN;

    zf_cbor_cursor_init(&cursor, data, data_size);
    if (!zf_cbor_read_map_start(&cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        uint64_t key = 0;
        if (!zf_cbor_read_uint(&cursor, &key)) {
            return false;
        }
        if (!zf_record_decode_index_field(&cursor, key, out_entry, &version, counter_iv,
                                          counter_seal)) {
            return false;
        }
        switch (key) {
        case ZfRecordKeyVersion:
            saw_version = true;
            break;
        case ZfRecordKeyCredentialId:
            saw_credential_id = true;
            break;
        case ZfRecordKeyRpId:
            saw_rp_id = true;
            break;
        case ZfRecordKeyUserId:
            saw_user_id = true;
            break;
        case ZfRecordKeySignCount:
            saw_sign_count = true;
            break;
        case ZfRecordKeyCreatedAt:
            saw_created_at = true;
            break;
        case ZfRecordKeyResidentKey:
            saw_resident_key = true;
            break;
        case ZfRecordKeyCredProtect:
            saw_cred_protect = true;
            break;
        case ZfRecordKeyCounterSealIv:
            saw_counter_iv = true;
            break;
        case ZfRecordKeyCounterSeal:
            saw_counter_seal = true;
            break;
        default:
            break;
        }
    }

    if (cursor.ptr != cursor.end) {
        return false;
    }
    if (!saw_version || !saw_credential_id || !saw_rp_id || !saw_user_id || !saw_sign_count ||
        !saw_created_at || !saw_resident_key) {
        return false;
    }
    if (saw_counter_iv != saw_counter_seal) {
        return false;
    }
    if (version != ZF_STORE_VERSION || out_entry->rp_id[0] == '\0') {
        return false;
    }
    if (!saw_cred_protect) {
        out_entry->cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL;
    }

    zf_record_index_to_stub_record(file_name, out_entry, &stub_record);
    if (!zf_record_file_name_matches_id(&stub_record, file_name)) {
        return false;
    }
    if (saw_counter_iv && !zf_record_verify_counter_seal(&stub_record, counter_iv, counter_seal)) {
        return false;
    }

    out_entry->in_use = true;
    return true;
}

bool zf_store_record_format_is_record_name(const char *name) {
    size_t expected_len = ZF_CREDENTIAL_ID_LEN * 2;
    if (strlen(name) != expected_len) {
        return false;
    }

    for (size_t i = 0; i < expected_len; ++i) {
        char ch = name[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool zf_store_record_format_load_record(Storage *storage, const char *file_name,
                                        ZfCredentialRecord *record) {
    char path[128];
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t size = 0;
    File *file = storage_file_alloc(storage);

    if (!file) {
        return false;
    }
    zf_store_build_record_path(file_name, path, sizeof(path));
    if (!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return false;
    }

    size = storage_file_size(file);
    if (size == 0 || size > sizeof(buffer)) {
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }
    if (storage_file_read(file, buffer, size) != size) {
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }

    storage_file_close(file);
    storage_file_free(file);
    if (!zf_record_decode(buffer, size, file_name, record)) {
        return false;
    }
    return zf_store_counter_floor_validate(storage, record);
}

bool zf_store_record_format_load_index(Storage *storage, const char *file_name,
                                       ZfCredentialIndexEntry *entry) {
    char path[128];
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t size = 0;
    File *file = storage_file_alloc(storage);
    ZfCredentialRecord stub_record;

    if (!file) {
        return false;
    }
    zf_store_build_record_path(file_name, path, sizeof(path));
    if (!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return false;
    }

    size = storage_file_size(file);
    if (size == 0 || size > sizeof(buffer)) {
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }
    if (storage_file_read(file, buffer, size) != size) {
        storage_file_close(file);
        storage_file_free(file);
        return false;
    }

    storage_file_close(file);
    storage_file_free(file);
    if (!zf_record_decode_index(buffer, size, file_name, entry)) {
        return false;
    }

    zf_record_index_to_stub_record(file_name, entry, &stub_record);
    return zf_store_counter_floor_validate(storage, &stub_record);
}

bool zf_store_record_format_write_record(Storage *storage, const ZfCredentialRecord *record) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t encoded_size = 0;
    char path[128];
    char temp_path[128];
    File *file = storage_file_alloc(storage);

    if (!file) {
        return false;
    }
    if (!zf_store_record_format_encode(record, buffer, &encoded_size)) {
        storage_file_free(file);
        return false;
    }

    zf_store_build_record_path(record->file_name, path, sizeof(path));
    zf_store_build_temp_path(record->file_name, temp_path, sizeof(temp_path));
    storage_common_remove(storage, temp_path);

    bool opened = storage_file_open(file, temp_path, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    bool wrote = opened && (storage_file_write(file, buffer, encoded_size) == encoded_size);
    storage_file_close(file);
    bool renamed = wrote && (storage_common_rename(storage, temp_path, path) == FSE_OK);
    storage_common_remove(storage, temp_path);
    storage_file_free(file);
    if (renamed) {
        (void)zf_store_counter_floor_write(storage, record);
    }
    return renamed;
}
