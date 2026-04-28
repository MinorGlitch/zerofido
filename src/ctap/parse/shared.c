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

#include "internal.h"

#include <string.h>

#include "../../zerofido_crypto.h"

bool zf_ctap_text_equals(const uint8_t *ptr, size_t size, const char *text) {
    size_t expected = strlen(text);
    return size == expected && memcmp(ptr, text, size) == 0;
}

bool zf_ctap_mark_seen_key(uint16_t *seen_keys, uint64_t key) {
    if (key >= 16) {
        return true;
    }

    uint16_t mask = (uint16_t)(1U << key);
    if ((*seen_keys & mask) != 0) {
        return false;
    }

    *seen_keys |= mask;
    return true;
}

static bool zf_ctap_utf8_is_valid(const uint8_t *ptr, size_t size) {
    for (size_t i = 0; i < size;) {
        uint8_t lead = ptr[i];

        if (lead <= 0x7F) {
            ++i;
            continue;
        }
        if (lead >= 0xC2 && lead <= 0xDF) {
            if (i + 1 >= size || (ptr[i + 1] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 2;
            continue;
        }
        if (lead == 0xE0) {
            if (i + 2 >= size || ptr[i + 1] < 0xA0 || ptr[i + 1] > 0xBF ||
                (ptr[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 3;
            continue;
        }
        if ((lead >= 0xE1 && lead <= 0xEC) || (lead >= 0xEE && lead <= 0xEF)) {
            if (i + 2 >= size || (ptr[i + 1] & 0xC0U) != 0x80U || (ptr[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 3;
            continue;
        }
        if (lead == 0xED) {
            if (i + 2 >= size || ptr[i + 1] < 0x80 || ptr[i + 1] > 0x9F ||
                (ptr[i + 2] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 3;
            continue;
        }
        if (lead == 0xF0) {
            if (i + 3 >= size || ptr[i + 1] < 0x90 || ptr[i + 1] > 0xBF ||
                (ptr[i + 2] & 0xC0U) != 0x80U || (ptr[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 4;
            continue;
        }
        if (lead >= 0xF1 && lead <= 0xF3) {
            if (i + 3 >= size || (ptr[i + 1] & 0xC0U) != 0x80U || (ptr[i + 2] & 0xC0U) != 0x80U ||
                (ptr[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 4;
            continue;
        }
        if (lead == 0xF4) {
            if (i + 3 >= size || ptr[i + 1] < 0x80 || ptr[i + 1] > 0x8F ||
                (ptr[i + 2] & 0xC0U) != 0x80U || (ptr[i + 3] & 0xC0U) != 0x80U) {
                return false;
            }
            i += 4;
            continue;
        }
        return false;
    }

    return true;
}

bool zf_ctap_cbor_read_text_copy(ZfCborCursor *cursor, char *out, size_t out_size) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    if (!zf_cbor_read_text_ptr(cursor, &ptr, &size) || size >= out_size ||
        memchr(ptr, '\0', size) != NULL || !zf_ctap_utf8_is_valid(ptr, size)) {
        return false;
    }

    memcpy(out, ptr, size);
    out[size] = '\0';
    return true;
}

bool zf_ctap_cbor_read_text_discard(ZfCborCursor *cursor) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    return zf_cbor_read_text_ptr(cursor, &ptr, &size) && memchr(ptr, '\0', size) == NULL &&
           zf_ctap_utf8_is_valid(ptr, size);
}

bool zf_ctap_cbor_read_bytes_copy(ZfCborCursor *cursor, uint8_t *out, size_t out_capacity,
                                  size_t *out_size) {
    const uint8_t *ptr = NULL;
    size_t size = 0;

    if (!zf_cbor_read_bytes_ptr(cursor, &ptr, &size) || size > out_capacity) {
        return false;
    }

    memcpy(out, ptr, size);
    *out_size = size;
    return true;
}

uint8_t zf_ctap_parse_options_map(ZfCborCursor *cursor, bool *up, bool *has_up, bool *uv,
                                  bool *has_uv, bool *rk, bool *has_rk) {
    size_t pairs = 0;
    bool saw_up = false;
    bool saw_uv = false;
    bool saw_rk = false;
    if (!zf_cbor_read_map_start(cursor, &pairs)) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    for (size_t i = 0; i < pairs; ++i) {
        const uint8_t *key = NULL;
        size_t key_size = 0;
        bool value = false;

        if (!zf_cbor_read_text_ptr(cursor, &key, &key_size) || !zf_cbor_read_bool(cursor, &value)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }

        if (zf_ctap_text_equals(key, key_size, "up")) {
            if (saw_up) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            *up = value;
            *has_up = true;
            saw_up = true;
        } else if (zf_ctap_text_equals(key, key_size, "uv")) {
            if (saw_uv) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            *uv = value;
            *has_uv = true;
            saw_uv = true;
        } else if (zf_ctap_text_equals(key, key_size, "rk")) {
            if (saw_rk) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            *rk = value;
            *has_rk = true;
            saw_rk = true;
        } else if (value) {
            return ZF_CTAP_ERR_UNSUPPORTED_OPTION;
        }
    }

    return ZF_CTAP_SUCCESS;
}

uint8_t zf_ctap_parse_make_credential_extensions_map(ZfCborCursor *cursor,
                                                     bool *has_cred_protect,
                                                     uint8_t *cred_protect,
                                                     bool *hmac_secret_requested) {
    size_t pairs = 0;
    bool saw_cred_protect = false;
    bool saw_hmac_secret = false;

    if (!zf_cbor_read_map_start(cursor, &pairs)) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    for (size_t i = 0; i < pairs; ++i) {
        const uint8_t *key = NULL;
        size_t key_size = 0;

        if (!zf_cbor_read_text_ptr(cursor, &key, &key_size)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }

        if (zf_ctap_text_equals(key, key_size, "credProtect")) {
            uint64_t raw = 0;
            if (saw_cred_protect || !zf_cbor_read_uint(cursor, &raw)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            if (raw < ZF_CRED_PROTECT_UV_OPTIONAL || raw > ZF_CRED_PROTECT_UV_REQUIRED) {
                return ZF_CTAP_ERR_INVALID_OPTION;
            }

            *has_cred_protect = true;
            *cred_protect = (uint8_t)raw;
            saw_cred_protect = true;
            continue;
        }

        if (zf_ctap_text_equals(key, key_size, "hmac-secret")) {
            bool requested = false;
            if (saw_hmac_secret || !zf_cbor_read_bool(cursor, &requested)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
            *hmac_secret_requested = requested;
            saw_hmac_secret = true;
            continue;
        }

        if (!zf_cbor_skip(cursor)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }
    }

    return ZF_CTAP_SUCCESS;
}

static bool zf_ctap_parse_credential_descriptor(ZfCborCursor *cursor,
                                                ZfCredentialDescriptor *descriptor,
                                                bool *include_entry) {
    size_t pairs = 0;
    bool saw_id = false;
    bool saw_type = false;
    bool public_key = false;

    if (!zf_cbor_read_map_start(cursor, &pairs)) {
        return false;
    }

    for (size_t i = 0; i < pairs; ++i) {
        const uint8_t *key = NULL;
        size_t key_size = 0;
        if (!zf_cbor_read_text_ptr(cursor, &key, &key_size)) {
            return false;
        }

        if (zf_ctap_text_equals(key, key_size, "id")) {
            if (saw_id) {
                return false;
            }
            const uint8_t *id_ptr = NULL;
            size_t id_size = 0;
            if (!zf_cbor_read_bytes_ptr(cursor, &id_ptr, &id_size)) {
                return false;
            }
            if (!descriptor || id_size == 0 || id_size > ZF_MAX_DESCRIPTOR_ID_LEN ||
                id_size > UINT16_MAX) {
                return false;
            }
            descriptor->credential_id_len = (uint16_t)id_size;
            zf_crypto_sha256(id_ptr, id_size, descriptor->credential_id_digest);
            saw_id = true;
            continue;
        }

        if (zf_ctap_text_equals(key, key_size, "type")) {
            if (saw_type) {
                return false;
            }
            const uint8_t *type_ptr = NULL;
            size_t type_size = 0;
            if (!zf_cbor_read_text_ptr(cursor, &type_ptr, &type_size)) {
                return false;
            }
            saw_type = true;
            public_key = zf_ctap_text_equals(type_ptr, type_size, "public-key");
            continue;
        }

        if (!zf_cbor_skip(cursor)) {
            return false;
        }
    }

    *include_entry = public_key;
    return saw_id && saw_type;
}

uint8_t zf_ctap_parse_pubkey_cred_params(ZfCborCursor *cursor, bool *es256_supported) {
    size_t items = 0;
    if (!zf_cbor_read_array_start(cursor, &items)) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    for (size_t i = 0; i < items; ++i) {
        size_t pairs = 0;
        int64_t alg = 0;
        bool have_alg = false;
        bool have_type = false;
        bool public_key = false;

        if (!zf_cbor_read_map_start(cursor, &pairs)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }

        for (size_t j = 0; j < pairs; ++j) {
            const uint8_t *key = NULL;
            size_t key_size = 0;
            if (!zf_cbor_read_text_ptr(cursor, &key, &key_size)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }

            if (zf_ctap_text_equals(key, key_size, "alg")) {
                if (have_alg) {
                    return ZF_CTAP_ERR_INVALID_CBOR;
                }
                if (!zf_cbor_read_int(cursor, &alg)) {
                    return ZF_CTAP_ERR_INVALID_CBOR;
                }
                have_alg = true;
                continue;
            }

            if (zf_ctap_text_equals(key, key_size, "type")) {
                if (have_type) {
                    return ZF_CTAP_ERR_INVALID_CBOR;
                }
                const uint8_t *value = NULL;
                size_t value_size = 0;
                if (!zf_cbor_read_text_ptr(cursor, &value, &value_size)) {
                    return ZF_CTAP_ERR_INVALID_CBOR;
                }
                have_type = true;
                public_key = zf_ctap_text_equals(value, value_size, "public-key");
                continue;
            }

            if (!zf_cbor_skip(cursor)) {
                return ZF_CTAP_ERR_INVALID_CBOR;
            }
        }

        if (!have_alg || !have_type) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }
        if (!public_key) {
            continue;
        }
        if (alg == -7) {
            *es256_supported = true;
        }
    }

    return ZF_CTAP_SUCCESS;
}

/*
 * Descriptor IDs are stored as SHA-256 digests plus original length in
 * caller-provided storage. Duplicate descriptors with the same length and
 * digest are rejected.
 */
uint8_t zf_ctap_parse_descriptor_array(ZfCborCursor *cursor, ZfCredentialDescriptorList *list) {
    size_t items = 0;

    if (!list || !zf_cbor_read_array_start(cursor, &items)) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    list->count = 0;

    for (size_t j = 0; j < items; ++j) {
        ZfCredentialDescriptor parsed;
        bool include_entry = false;

        memset(&parsed, 0, sizeof(parsed));
        if (!zf_ctap_parse_credential_descriptor(cursor, &parsed, &include_entry)) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }
        if (parsed.credential_id_len == 0) {
            return ZF_CTAP_ERR_INVALID_CBOR;
        }
        if (!include_entry) {
            continue;
        }
        if (!list->entries || list->count >= list->capacity) {
            return ZF_CTAP_ERR_INVALID_PARAMETER;
        }
        for (size_t i = 0; i < list->count; ++i) {
            const ZfCredentialDescriptor *existing = &list->entries[i];
            if (existing->credential_id_len == parsed.credential_id_len &&
                memcmp(existing->credential_id_digest, parsed.credential_id_digest,
                       sizeof(existing->credential_id_digest)) == 0) {
                return ZF_CTAP_ERR_INVALID_PARAMETER;
            }
        }
        list->entries[list->count] = parsed;
        list->count++;
    }

    return ZF_CTAP_SUCCESS;
}

bool zf_ctap_descriptor_list_contains_id(const ZfCredentialDescriptorList *list,
                                         const uint8_t *credential_id, size_t credential_id_len) {
    uint8_t credential_id_digest[ZF_DESCRIPTOR_ID_DIGEST_LEN];

    if (!list || !credential_id || list->count == 0 || credential_id_len == 0 ||
        credential_id_len > ZF_CREDENTIAL_ID_LEN) {
        return false;
    }

    zf_crypto_sha256(credential_id, credential_id_len, credential_id_digest);
    for (size_t i = 0; i < list->count; ++i) {
        const ZfCredentialDescriptor *entry = &list->entries[i];
        if (entry->credential_id_len == credential_id_len &&
            memcmp(entry->credential_id_digest, credential_id_digest,
                   sizeof(entry->credential_id_digest)) == 0) {
            zf_crypto_secure_zero(credential_id_digest, sizeof(credential_id_digest));
            return true;
        }
    }

    zf_crypto_secure_zero(credential_id_digest, sizeof(credential_id_digest));
    return false;
}
