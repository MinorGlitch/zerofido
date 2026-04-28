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

static bool zf_encode_make_credential_extensions(uint8_t cred_protect, bool include_cred_protect,
                                                 bool include_hmac_secret, bool hmac_secret_created,
                                                 uint8_t *out, size_t out_capacity,
                                                 size_t *out_len) {
    ZfCborEncoder enc;
    uint8_t effective_cred_protect = cred_protect == 0 ? ZF_CRED_PROTECT_UV_OPTIONAL : cred_protect;
    size_t pairs = (include_cred_protect ? 1U : 0U) + (include_hmac_secret ? 1U : 0U);

    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return false;
    }
    if (!zf_cbor_encode_map(&enc, pairs)) {
        return false;
    }
    if (include_cred_protect &&
        !(zf_cbor_encode_text(&enc, "credProtect") &&
          zf_cbor_encode_uint(&enc, effective_cred_protect))) {
        return false;
    }
    if (include_hmac_secret &&
        !(zf_cbor_encode_text(&enc, "hmac-secret") &&
          zf_cbor_encode_bool(&enc, hmac_secret_created))) {
        return false;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return true;
}

/*
 * Builds WebAuthn authenticatorData:
 *   SHA256(rpId) || flags || signCount || attestedCredentialData? || extensions?
 *
 * Flags are derived from UP/UV plus AT/ED inclusion. The caller supplies the
 * sign counter value that will be committed if the response succeeds.
 */
static size_t zf_build_auth_data(const char *rp_id, bool user_present, bool user_verified,
                                 bool include_attested_data, bool include_extension_data,
                                 const ZfCredentialRecord *record, uint32_t sign_count,
                                 const uint8_t *extension_data, size_t extension_data_len,
                                 uint8_t *cose, size_t cose_capacity, uint8_t *out,
                                 size_t out_capacity) {
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
        size_t cose_len = 0;
        if (!record || !cose || !zf_encode_cose_key(record, cose, cose_capacity, &cose_len)) {
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
    size_t pin_uv_auth_protocols_count = 1;
    bool include_ctap21_info_fields = false;
    size_t get_info_pairs = 6;

    if (!capabilities || !zf_cbor_encoder_init(&enc, out, out_capacity)) {
        return ZF_CTAP_ERR_OTHER;
    }

    include_ctap21_info_fields = capabilities->advertise_fido_2_1;
    if (include_ctap21_info_fields) {
        get_info_pairs += 4;
    }
    pin_uv_auth_protocols_count = capabilities->pin_uv_auth_protocol_2_enabled ? 2 : 1;
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
    if (capabilities->pin_uv_auth_token_enabled) {
        options_count++;
    }
    if (capabilities->make_cred_uv_not_required) {
        options_count++;
    }
    if (capabilities->advertise_usb_transport) {
        transports_count++;
    }
    if (capabilities->advertise_nfc_transport) {
        transports_count++;
    }

    bool ok = zf_cbor_encode_map(&enc, get_info_pairs) && zf_cbor_encode_uint(&enc, 1) &&
              zf_cbor_encode_array(&enc, versions_count) &&
              (!capabilities->advertise_fido_2_1 || zf_cbor_encode_text(&enc, "FIDO_2_1")) &&
              (!capabilities->advertise_fido_2_0 || zf_cbor_encode_text(&enc, "FIDO_2_0")) &&
              (!capabilities->advertise_u2f_v2 || zf_cbor_encode_text(&enc, "U2F_V2")) &&
              zf_cbor_encode_uint(&enc, 2) && zf_cbor_encode_array(&enc, 2) &&
              zf_cbor_encode_text(&enc, "credProtect") &&
              zf_cbor_encode_text(&enc, "hmac-secret") && zf_cbor_encode_uint(&enc, 3) &&
              zf_cbor_encode_bytes(&enc, aaguid, ZF_AAGUID_LEN) && zf_cbor_encode_uint(&enc, 4) &&
              zf_cbor_encode_map(&enc, options_count) && zf_cbor_encode_text(&enc, "rk") &&
              zf_cbor_encode_bool(&enc, true) && zf_cbor_encode_text(&enc, "up") &&
              zf_cbor_encode_bool(&enc, true) && zf_cbor_encode_text(&enc, "plat") &&
              zf_cbor_encode_bool(&enc, false) &&
              (!capabilities->client_pin_enabled || (zf_cbor_encode_text(&enc, "clientPin") &&
                                                     zf_cbor_encode_bool(&enc, client_pin_set))) &&
              (!capabilities->pin_uv_auth_token_enabled ||
               (zf_cbor_encode_text(&enc, "pinUvAuthToken") && zf_cbor_encode_bool(&enc, true))) &&
              (!capabilities->make_cred_uv_not_required ||
               (zf_cbor_encode_text(&enc, "makeCredUvNotRqd") &&
                zf_cbor_encode_bool(&enc, true))) &&
              zf_cbor_encode_uint(&enc, 5) && zf_cbor_encode_uint(&enc, ZF_MAX_MSG_SIZE) &&
              zf_cbor_encode_uint(&enc, 6) &&
              zf_cbor_encode_array(&enc, pin_uv_auth_protocols_count) &&
              (!capabilities->pin_uv_auth_protocol_2_enabled || zf_cbor_encode_uint(&enc, 2)) &&
              zf_cbor_encode_uint(&enc, 1);

    if (ok && include_ctap21_info_fields) {
        ok = zf_cbor_encode_uint(&enc, 9) && zf_cbor_encode_array(&enc, transports_count) &&
             (!capabilities->advertise_usb_transport || zf_cbor_encode_text(&enc, "usb")) &&
             (!capabilities->advertise_nfc_transport || zf_cbor_encode_text(&enc, "nfc")) &&
             zf_cbor_encode_uint(&enc, 10) && zf_cbor_encode_array(&enc, 1) &&
             zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "alg") &&
             zf_cbor_encode_int(&enc, -7) && zf_cbor_encode_text(&enc, "type") &&
             zf_cbor_encode_text(&enc, "public-key") && zf_cbor_encode_uint(&enc, 13) &&
             zf_cbor_encode_uint(&enc, ZF_MIN_PIN_LENGTH) && zf_cbor_encode_uint(&enc, 14) &&
             zf_cbor_encode_uint(&enc, ZF_FIRMWARE_VERSION);
    }

    if (!ok) {
        return ZF_CTAP_ERR_INVALID_CBOR;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return ZF_CTAP_SUCCESS;
}

uint8_t
zf_ctap_build_make_credential_response_with_scratch(
    ZfMakeCredentialResponseScratch *scratch, const char *rp_id, const ZfCredentialRecord *record,
    const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN], bool user_verified,
    bool include_cred_protect, bool include_hmac_secret, uint8_t *out, size_t out_capacity,
    size_t *out_len) {
    uint8_t status = ZF_CTAP_ERR_OTHER;
    size_t extension_data_len = 0;
    size_t attestation_input_len = 0;
    bool wrote_attestation_input = false;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    memset(scratch, 0, sizeof(*scratch));

    if ((include_cred_protect || include_hmac_secret) &&
        !zf_encode_make_credential_extensions(record->cred_protect, include_cred_protect,
                                              include_hmac_secret, record->hmac_secret,
                                              scratch->extension_data,
                                              sizeof(scratch->extension_data),
                                              &extension_data_len)) {
        goto cleanup;
    }

    size_t auth_data_len =
        zf_build_auth_data(rp_id, true, user_verified, true,
                           include_cred_protect || include_hmac_secret, record, record->sign_count,
                           scratch->extension_data, extension_data_len, scratch->cose,
                           sizeof(scratch->cose), scratch->auth_data, sizeof(scratch->auth_data));
    if (auth_data_len == 0) {
        goto cleanup;
    }

#if !ZF_FIDO2_NONE_ATTESTATION
    /*
     * Packed attestation signs authenticatorData || clientDataHash. Non-dev
     * builds load per-install local attestation assets; the alternate build
     * path emits "none" attestation for conformance/debug profiles.
     */
    attestation_input_len = auth_data_len + ZF_CLIENT_DATA_HASH_LEN;
    if (!out || attestation_input_len > out_capacity) {
        goto cleanup;
    }
    memcpy(out, scratch->auth_data, auth_data_len);
    memcpy(out + auth_data_len, client_data_hash, ZF_CLIENT_DATA_HASH_LEN);
    wrote_attestation_input = true;

    size_t signature_len = 0;
    size_t cert_len = 0;
    if (!zf_attestation_ensure_ready() ||
        !zf_attestation_load_leaf_cert_der(scratch->attestation_cert,
                                           sizeof(scratch->attestation_cert), &cert_len) ||
        !zf_attestation_sign_input(out, attestation_input_len, scratch->signature,
                                   sizeof(scratch->signature), &signature_len)) {
        goto cleanup;
    }
#endif

    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        goto cleanup;
    }

#if !ZF_FIDO2_NONE_ATTESTATION
    bool ok = zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
              zf_cbor_encode_text(&enc, "packed") && zf_cbor_encode_uint(&enc, 2) &&
              zf_cbor_encode_bytes(&enc, scratch->auth_data, auth_data_len) &&
              zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 3) &&
              zf_cbor_encode_text(&enc, "alg") && zf_cbor_encode_int(&enc, -7) &&
              zf_cbor_encode_text(&enc, "sig") &&
              zf_cbor_encode_bytes(&enc, scratch->signature, signature_len) &&
              zf_cbor_encode_text(&enc, "x5c") && zf_cbor_encode_array(&enc, 1) &&
              zf_cbor_encode_bytes(&enc, scratch->attestation_cert, cert_len);
#else
    (void)client_data_hash;
    bool ok = zf_cbor_encode_map(&enc, 3) && zf_cbor_encode_uint(&enc, 1) &&
              zf_cbor_encode_text(&enc, "none") && zf_cbor_encode_uint(&enc, 2) &&
              zf_cbor_encode_bytes(&enc, scratch->auth_data, auth_data_len) &&
              zf_cbor_encode_uint(&enc, 3) && zf_cbor_encode_map(&enc, 0);
#endif
    if (!ok) {
        goto cleanup;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    status = ZF_CTAP_SUCCESS;

cleanup:
    if (status != ZF_CTAP_SUCCESS && wrote_attestation_input) {
        zf_crypto_secure_zero(out, attestation_input_len);
    }
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return status;
}

/*
 * Assertion signatures cover SHA256(authenticatorData || clientDataHash). The
 * optional user, numberOfCredentials, and userSelected fields are controlled by
 * the getAssertion branch that selected the credential.
 */
uint8_t zf_ctap_build_assertion_response_with_scratch(
    ZfAssertionResponseScratch *scratch, const ZfAssertionRequestData *request,
    const ZfCredentialRecord *record, bool user_present, bool user_verified, uint32_t sign_count,
    bool include_user_details, bool include_count, size_t match_count, bool include_user_selected,
    bool user_selected, const uint8_t *extension_data, size_t extension_data_len,
    uint8_t *out, size_t out_capacity, size_t *out_len) {
    uint8_t status = ZF_CTAP_ERR_OTHER;
    size_t signature_len = 0;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    size_t auth_data_len =
        zf_build_auth_data(request->rp_id, user_present, user_verified, false,
                           extension_data_len > 0U, NULL, sign_count, extension_data,
                           extension_data_len, NULL, 0, scratch->auth_data,
                           sizeof(scratch->auth_data));
    if (auth_data_len == 0) {
        goto cleanup;
    }

    zf_crypto_sha256_concat(scratch->auth_data, auth_data_len, request->client_data_hash,
                            sizeof(request->client_data_hash), scratch->sign_hash);

    if (!zf_crypto_sign_hash(record, scratch->sign_hash, scratch->signature,
                             sizeof(scratch->signature), &signature_len)) {
        goto cleanup;
    }

    ZfCborEncoder enc;
    if (!zf_cbor_encoder_init(&enc, out, out_capacity)) {
        goto cleanup;
    }

    bool include_user_name = include_user_details && record->user_name[0] != '\0';
    bool include_display_name = include_user_details && record->user_display_name[0] != '\0';
    bool emit_user_selected = include_user_selected && user_selected;
    size_t user_pairs = 1;
    if (include_user_name) {
        user_pairs++;
    }
    if (include_display_name) {
        user_pairs++;
    }

    size_t pairs = 4;
    if (include_count) {
        pairs++;
    }
    if (emit_user_selected) {
        pairs++;
    }
    bool ok = zf_cbor_encode_map(&enc, pairs) && zf_cbor_encode_uint(&enc, 1) &&
              zf_cbor_encode_map(&enc, 2) && zf_cbor_encode_text(&enc, "id") &&
              zf_cbor_encode_bytes(&enc, record->credential_id, record->credential_id_len) &&
              zf_cbor_encode_text(&enc, "type") && zf_cbor_encode_text(&enc, "public-key") &&
              zf_cbor_encode_uint(&enc, 2) &&
              zf_cbor_encode_bytes(&enc, scratch->auth_data, auth_data_len) &&
              zf_cbor_encode_uint(&enc, 3) &&
              zf_cbor_encode_bytes(&enc, scratch->signature, signature_len) &&
              zf_cbor_encode_uint(&enc, 4) && zf_cbor_encode_map(&enc, user_pairs) &&
              zf_cbor_encode_text(&enc, "id") &&
              zf_cbor_encode_bytes(&enc, record->user_id, record->user_id_len);
    if (!ok) {
        goto cleanup;
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
    if (ok && emit_user_selected) {
        ok = zf_cbor_encode_uint(&enc, 6) && zf_cbor_encode_bool(&enc, true);
    }
    if (!ok) {
        goto cleanup;
    }

    *out_len = zf_cbor_encoder_size(&enc);
    status = ZF_CTAP_SUCCESS;

cleanup:
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return status;
}
