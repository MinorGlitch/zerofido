/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "hmac_secret.h"

#include <string.h>

#include "../../pin/protocol.h"
#include "../../zerofido_cbor.h"
#include "../../zerofido_crypto.h"

static uint8_t zf_hmac_secret_finish(ZfHmacSecretScratch *scratch, uint8_t status) {
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    return status;
}

/*
 * Implements hmac-secret output generation. The platform ECDH key derives PIN
 * protocol keys, saltAuth authenticates saltEnc, saltEnc decrypts to one or two
 * 32-byte salts, and the selected credential secret depends on UV state. All
 * intermediate key/salt/output material lives in scratch and is zeroed.
 */
uint8_t zf_ctap_hmac_secret_build_extension(const ZfClientPinState *pin_state,
                                            const ZfAssertionRequestData *request,
                                            const ZfCredentialRecord *record, bool user_verified,
                                            ZfHmacSecretScratch *scratch, uint8_t *out,
                                            size_t out_capacity, size_t *out_len) {
    const uint8_t *cred_random = NULL;
    size_t salt_plain_len = 0;
    size_t output_plain_len = 0;
    size_t output_enc_len = 0;
    ZfCborEncoder enc;

    if (!out_len) {
        return ZF_CTAP_ERR_OTHER;
    }
    *out_len = 0;
    if (!request || !request->has_hmac_secret || !record || !record->hmac_secret) {
        return ZF_CTAP_SUCCESS;
    }
    if (!pin_state || !scratch || !out) {
        return ZF_CTAP_ERR_OTHER;
    }

    memset(scratch, 0, sizeof(*scratch));
    if (!zf_pin_protocol_supported(request->hmac_secret_pin_protocol) ||
        !zf_pin_protocol_derive_keys(pin_state, request->hmac_secret_pin_protocol,
                                     request->hmac_secret_platform_x,
                                     request->hmac_secret_platform_y, scratch->protocol_keys)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_INVALID_PARAMETER);
    }
    if (!zf_pin_protocol_hmac_matches(
            &scratch->hmac_scratch, request->hmac_secret_pin_protocol,
            zf_pin_protocol_hmac_key(scratch->protocol_keys), request->hmac_secret_salt_enc,
            request->hmac_secret_salt_enc_len, NULL, 0, request->hmac_secret_salt_auth,
            request->hmac_secret_salt_auth_len)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_PIN_AUTH_INVALID);
    }
    if (!zf_pin_protocol_decrypt(request->hmac_secret_pin_protocol, scratch->protocol_keys,
                                 request->hmac_secret_salt_enc, request->hmac_secret_salt_enc_len,
                                 scratch->salt_plain, &salt_plain_len) ||
        (salt_plain_len != 32U && salt_plain_len != 64U)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_INVALID_PARAMETER);
    }

    cred_random = user_verified ? record->hmac_secret_with_uv : record->hmac_secret_without_uv;
    if (!zf_crypto_hmac_sha256_parts_with_scratch(&scratch->hmac_scratch, cred_random,
                                                  ZF_HMAC_SECRET_LEN, scratch->salt_plain, 32U,
                                                  NULL, 0, scratch->output_plain)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_OTHER);
    }
    output_plain_len = 32U;
    if (salt_plain_len == 64U) {
        if (!zf_crypto_hmac_sha256_parts_with_scratch(&scratch->hmac_scratch, cred_random,
                                                      ZF_HMAC_SECRET_LEN, scratch->salt_plain + 32U,
                                                      32U, NULL, 0, scratch->output_plain + 32U)) {
            return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_OTHER);
        }
        output_plain_len = 64U;
    }

    if (!zf_pin_protocol_encrypt(request->hmac_secret_pin_protocol, scratch->protocol_keys,
                                 scratch->output_plain, output_plain_len, scratch->output_enc,
                                 sizeof(scratch->output_enc), &output_enc_len)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_OTHER);
    }

    if (!zf_cbor_encoder_init(&enc, out, out_capacity) || !zf_cbor_encode_map(&enc, 1) ||
        !zf_cbor_encode_text(&enc, "hmac-secret") ||
        !zf_cbor_encode_bytes(&enc, scratch->output_enc, output_enc_len)) {
        return zf_hmac_secret_finish(scratch, ZF_CTAP_ERR_OTHER);
    }

    *out_len = zf_cbor_encoder_size(&enc);
    return zf_hmac_secret_finish(scratch, ZF_CTAP_SUCCESS);
}
