#include "response.h"

#include <string.h>

#include "../zerofido_attestation.h"
#include "../zerofido_cbor.h"
#include "../zerofido_crypto.h"

static void zf_write_be16(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void zf_write_be32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static bool zf_encode_cose_key(const ZfCredentialRecord *record, uint8_t *out, size_t out_capacity,
                               size_t *out_len) {
    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return false;
    }

    bool ok = zf_cbor_encode_map(&enc, 5) && zf_cbor_encode_int(&enc, 1) &&
              zf_cbor_encode_int(&enc, 2) && zf_cbor_encode_int(&enc, 3) &&
              zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_int(&enc, -1) &&
              zf_cbor_encode_int(&enc, 1) && zf_cbor_encode_int(&enc, -2) &&
              zf_cbor_encode_bytes(&enc, record->public_x, sizeof(record->public_x)) &&
              zf_cbor_encode_int(&enc, -3) &&
              zf_cbor_encode_bytes(&enc, record->public_y, sizeof(record->public_y));
    if (!ok) {
        return false;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return true;
}

static bool zf_encode_cert_chain(ZfCborEncoder *enc, const uint8_t **certs, const size_t *cert_lens,
                                 size_t cert_count) {
    if (!zf_cbor_encode_array(enc, cert_count)) {
        return false;
    }

    for (size_t i = 0; i < cert_count; ++i) {
        if (!zf_cbor_encode_bytes(enc, certs[i], cert_lens[i])) {
            return false;
        }
    }

    return true;
}

static bool zf_encode_cred_protect_extension(uint8_t cred_protect, uint8_t *out,
                                             size_t out_capacity, size_t *out_len) {
    ZfCborEncoder enc;
    uint8_t effective_cred_protect = cred_protect == 0 ? ZF_CRED_PROTECT_UV_OPTIONAL : cred_protect;

    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return false;
    }

    if (!(zf_cbor_encode_map(&enc, 1) && zf_cbor_encode_text(&enc, "credProtect") &&
          zf_cbor_encode_uint(&enc, effective_cred_protect))) {
        return false;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return true;
}

static size_t zf_build_auth_data(const char *rp_id, bool user_present, bool user_verified,
                                 bool include_attested_data, bool include_extension_data,
                                 const ZfCredentialRecord *record, uint32_t sign_count,
                                 const uint8_t *extension_data, size_t extension_data_len,
                                 uint8_t *out, size_t out_capacity) {
    uint8_t flags = user_present ? 0x01 : 0x00;
    uint8_t rp_hash[32];
    size_t offset = 0;
    const uint8_t *aaguid = zf_attestation_get_aaguid();

    zf_crypto_sha256((const uint8_t *)rp_id, strlen(rp_id), rp_hash);
    if (user_verified) {
        flags |= 0x04;
    }
    if (include_attested_data) {
        flags |= 0x40;
    }
    if (include_extension_data) {
        flags |= 0x80;
    }
    if (out_capacity < 37) {
        return 0;
    }

    memcpy(&out[offset], rp_hash, sizeof(rp_hash));
    offset += sizeof(rp_hash);
    out[offset++] = flags;
    zf_write_be32(&out[offset], sign_count);
    offset += 4;

    if (include_attested_data) {
        uint8_t cose[128];
        size_t cose_len = 0;
        if (!record || !zf_encode_cose_key(record, cose, sizeof(cose), &cose_len)) {
            return 0;
        }
        if (offset + ZF_AAGUID_LEN + 2 + record->credential_id_len + cose_len > out_capacity) {
            return 0;
        }

        memcpy(&out[offset], aaguid, ZF_AAGUID_LEN);
        offset += ZF_AAGUID_LEN;
        zf_write_be16(&out[offset], (uint16_t)record->credential_id_len);
        offset += 2;
        memcpy(&out[offset], record->credential_id, record->credential_id_len);
        offset += record->credential_id_len;
        memcpy(&out[offset], cose, cose_len);
        offset += cose_len;
    }

    if (include_extension_data) {
        if (!extension_data || offset + extension_data_len > out_capacity) {
            return 0;
        }
        memcpy(&out[offset], extension_data, extension_data_len);
        offset += extension_data_len;
    }

    return offset;
}

uint8_t zf_ctap_build_get_info_response(const ZfResolvedCapabilities *capabilities,
                                        bool client_pin_set, uint8_t *out, size_t out_capacity,
                                        size_t *out_len) {
    ZfCborEncoder enc;
    const uint8_t *aaguid = zf_attestation_get_aaguid();
    size_t versions_count = 0;
    size_t options_count = 3;
    size_t transports_count = 0;

    if (!capabilities || !zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    if (capabilities->advertise_fido_2_1) {
        versions_count++;
    }
    if (capabilities->advertise_fido_2_0) {
        versions_count++;
    }
    if (capabilities->advertise_u2f_v2) {
        versions_count++;
    }
    if (capabilities->client_pin_enabled) {
        options_count++;
    }
    if (capabilities->advertise_usb_transport) {
        transports_count++;
    }

    bool ok = zf_cbor_encode_map(&enc, 10) && zf_cbor_encode_uint(&enc, 1) &&
              zf_cbor_encode_array(&enc, versions_count) &&
              (!capabilities->advertise_fido_2_1 || zf_cbor_encode_text(&enc, "FIDO_2_1")) &&
              (!capabilities->advertise_fido_2_0 || zf_cbor_encode_text(&enc, "FIDO_2_0")) &&
              (!capabilities->advertise_u2f_v2 || zf_cbor_encode_text(&enc, "U2F_V2")) &&
              zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_array(&enc, 1) &&
              zf_cbor_encode_text(&enc, "credProtect") && zf_cbor_encode_uint(&enc, 3) &&
              zf_cbor_encode_bytes(&enc, aaguid, ZF_AAGUID_LEN) && zf_cbor_encode_uint(&enc, 4) &&
              zf_cbor_encode_map(&enc, options_count) && zf_cbor_encode_text(&enc, "rk") &&
              zf_cbor_encode_bool(&enc, true) && zf_cbor_encode_text(&enc, "up") &&
              zf_cbor_encode_bool(&enc, true) && zf_cbor_encode_text(&enc, "plat") &&
              zf_cbor_encode_bool(&enc, false) &&
              (!capabilities->client_pin_enabled || (zf_cbor_encode_text(&enc, "clientPin") &&
                                                     zf_cbor_encode_bool(&enc, client_pin_set))) &&
              zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_uint(&enc, ZF_MAX_MSG_SIZE) &&
              zf_cbor_encode_uint(&enc, 6) && zf_cbor_encode_array(&enc, 1) &&
              zf_cbor_encode_uint(&enc, 1) && zf_cbor_encode_uint(&enc, 9) &&
              zf_cbor_encode_array(&enc, transports_count) &&
              (!capabilities->advertise_usb_transport || zf_cbor_encode_text(&enc, "usb")) &&
              zf_cbor_encode_uint(&enc, 10) && zf_cbor_encode_array(&enc, 1) &&
              zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
              zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
              zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 13) &&
              zf_cbor_encode_uint(&enc, ZF_MIN_PIN_LENGTH) && zf_cbor_encode_uint(&enc, 14) &&
              zf_cbor_encode_uint(&enc, ZF_FIRMWARE_VERSION);

    if (!ok) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

uint8_t
zf_ctap_build_make_credential_response(const char *rp_id, const ZfCredentialRecord *record,
                                       const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN],
                                       bool user_verified, bool include_cred_protect, uint8_t *out,
                                       size_t out_capacity, size_t *out_len) {
    uint8_t auth_data[288];
    uint8_t attestation_input[320];
    uint8_t signature[80];
    uint8_t extension_data[32];
    const uint8_t *attestation_certs[2] = {0};
    size_t attestation_cert_lens[2] = {0};
    size_t signature_len = 0;
    size_t cert_count = 0;
    size_t extension_data_len = 0;

    if (include_cred_protect &&
        !zf_encode_cred_protect_extension(record->cred_protect, extension_data,
                                          sizeof(extension_data), &extension_data_len)) {
        return ZF_CTAP_ERR_OTHER;
    }

    size_t auth_data_len = zf_build_auth_data(
        rp_id, true, user_verified, true, include_cred_protect, record, record->sign_count,
        extension_data, extension_data_len, auth_data, sizeof(auth_data));
    if (auth_data_len == 0) {
        return ZF_CTAP_ERR_OTHER;
    }

    if (!zf_attestation_validate_consistency()) {
        return ZF_CTAP_ERR_OTHER;
    }
    memcpy(attestation_input, auth_data, auth_data_len);
    memcpy(attestation_input + auth_data_len, client_data_hash, ZF_CLIENT_DATA_HASH_LEN);
    if (!zf_attestation_sign_input(attestation_input, auth_data_len + ZF_CLIENT_DATA_HASH_LEN,
                                   signature, sizeof(signature), &signature_len)) {
        return ZF_CTAP_ERR_OTHER;
    }
    cert_count =
        zf_attestation_get_cert_chain(attestation_certs, attestation_cert_lens,
                                      sizeof(attestation_certs) / sizeof(attestation_certs[0]));
    if (cert_count == 0) {
        return ZF_CTAP_ERR_OTHER;
    }

    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    bool ok =
        zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
        zf_cbor_encode_text(&enc, "packed") && zf_cbor_encode_uint(&enc, 2) &&
        zf_cbor_encode_bytes(&enc, auth_data, auth_data_len) && zf_cbor_encode_uint(&enc, 3) &&
        zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_text(&enc, "alg") &&
        zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "sig") &&
        zf_cbor_encode_bytes(&enc, signature, signature_len) && zf_cbor_encode_text(&enc, "x5c") &&
        zf_encode_cert_chain(&enc, attestation_certs, attestation_cert_lens, cert_count);
    if (!ok) {
        return ZF_CTAP_ERR_OTHER;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

uint8_t zf_ctap_build_assertion_response(const ZfGetAssertionRequest *request,
                                         const ZfCredentialRecord *record, bool user_present,
                                         bool user_verified, uint32_t sign_count,
                                         bool include_user_details, bool include_count,
                                         size_t match_count, uint8_t *out, size_t out_capacity,
                                         size_t *out_len) {
    uint8_t auth_data[128];
    uint8_t sign_input[160];
    uint8_t sign_hash[32];
    uint8_t signature[80];
    size_t auth_data_len =
        zf_build_auth_data(request->rp_id, user_present, user_verified, false, false, NULL,
                           sign_count, NULL, 0, auth_data, sizeof(auth_data));
    if (auth_data_len == 0) {
        return ZF_CTAP_ERR_OTHER;
    }

    memcpy(sign_input, auth_data, auth_data_len);
    memcpy(sign_input + auth_data_len, request->client_data_hash,
           sizeof(request->client_data_hash));
    zf_crypto_sha256(sign_input, auth_data_len + sizeof(request->client_data_hash), sign_hash);

    size_t signature_len = 0;
    if (!zf_crypto_sign_hash(record, sign_hash, signature, sizeof(signature), &signature_len)) {
        return ZF_CTAP_ERR_OTHER;
    }

    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    bool include_user_name = include_user_details && record->user_name[0] != '\0';
    bool include_display_name = include_user_details && record->user_display_name[0] != '\0';
    size_t user_pairs = 1;
    if (include_user_name) {
        user_pairs++;
    }
    if (include_display_name) {
        user_pairs++;
    }

    size_t pairs = include_count ? 5 : 4;
    bool ok =
        zf_cbor_encode_map(&enc, pairs) && zf_cbor_encode_uint(&enc, 1) &&
        zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
        zf_cbor_encode_bytes(&enc, record->credential_id, record->credential_id_len) &&
        zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
        zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_bytes(&enc, auth_data, auth_data_len) &&
        zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_bytes(&enc, signature, signature_len) &&
        zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_map(&enc, user_pairs) &&
        zf_cbor_encode_text(&enc, "id") &&
        zf_cbor_encode_bytes(&enc, record->user_id, record->user_id_len);
    if (!ok) {
        return ZF_CTAP_ERR_OTHER;
    }
    if (include_user_name) {
        ok = zf_cbor_encode_text(&enc, "name") && zf_cbor_encode_text(&enc, record->user_name);
    }
    if (ok && include_display_name) {
        ok = zf_cbor_encode_text(&enc, "displayName") &&
             zf_cbor_encode_text(&enc, record->user_display_name);
    }
    if (include_count) {
        ok = zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_uint(&enc, match_count);
    }
    if (!ok) {
        return ZF_CTAP_ERR_OTHER;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}
