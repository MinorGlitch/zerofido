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

#include "../zerofido_pin.h"

#include "../zerofido_app_i.h"
#include "client_pin/internal.h"

static ZfClientPinCommandScratch *zf_pin_command_scratch(ZerofidoApp *app) {
    return zf_app_command_scratch_acquire(app, sizeof(ZfClientPinCommandScratch));
}

static void zf_pin_lock_if_present(ZerofidoApp *app, bool *locked) {
    *locked = false;
    if (app && app->ui_mutex) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        *locked = true;
    }
}

static void zf_pin_unlock_if_present(ZerofidoApp *app, bool locked) {
    if (locked) {
        furi_mutex_release(app->ui_mutex);
    }
}

static void zf_pin_snapshot_state(ZerofidoApp *app, ZfClientPinState *state) {
    bool locked = false;

    zf_pin_lock_if_present(app, &locked);
    *state = app->pin_state;
    zf_pin_unlock_if_present(app, locked);
}

static void zf_pin_publish_state(ZerofidoApp *app, const ZfClientPinState *state) {
    bool locked = false;

    zf_pin_lock_if_present(app, &locked);
    app->pin_state = *state;
    zf_pin_unlock_if_present(app, locked);
}

#if ZF_RELEASE_DIAGNOSTICS
static const char *zf_pin_status_name(uint8_t status) {
    switch (status) {
    case ZF_CTAP_SUCCESS:
        return "OK";
    case ZF_CTAP_ERR_INVALID_CBOR:
        return "CBOR";
    case ZF_CTAP_ERR_MISSING_PARAMETER:
        return "MISS";
    case ZF_CTAP_ERR_INVALID_PARAMETER:
        return "IPRM";
    case ZF_CTAP_ERR_INVALID_SUBCOMMAND:
        return "SUB";
    case ZF_CTAP_ERR_PIN_INVALID:
        return "PIN";
    case ZF_CTAP_ERR_PIN_BLOCKED:
        return "PBLK";
    case ZF_CTAP_ERR_PIN_AUTH_INVALID:
        return "PAUTH";
    case ZF_CTAP_ERR_PIN_AUTH_BLOCKED:
        return "PABLK";
    case ZF_CTAP_ERR_PIN_NOT_SET:
        return "PNONE";
    case ZF_CTAP_ERR_PIN_POLICY_VIOLATION:
        return "PPOL";
    case ZF_CTAP_ERR_OTHER:
        return "OTHER";
    default:
        return "UNK";
    }
}

static void zf_pin_log_result(const char *tag, uint8_t status) {
    FURI_LOG_I("ZeroFIDO:CTAP", "cmd=%s status=%s", tag ? tag : "CP", zf_pin_status_name(status));
}
#else
static void zf_pin_log_result(const char *tag, uint8_t status) {
    (void)tag;
    (void)status;
}
#endif

uint8_t zerofido_pin_handle_command(ZerofidoApp *app, const uint8_t *request, size_t request_len,
                                    uint8_t *out, size_t out_capacity, size_t *out_len) {
    ZfClientPinCommandScratch *scratch = zf_pin_command_scratch(app);
    ZfClientPinRequest *parsed = NULL;
    ZfClientPinState *state = NULL;
    const char *diagnostic_tag = "CP-PARSE";
    uint8_t status = ZF_CTAP_ERR_OTHER;

    if (!scratch) {
        return ZF_CTAP_ERR_OTHER;
    }
    parsed = &scratch->request;
    state = &scratch->state;

    status = zf_client_pin_parse_request(request, request_len, parsed);
    if (status != ZF_CTAP_SUCCESS) {
        goto cleanup;
    }
    diagnostic_tag = zerofido_pin_subcommand_tag(parsed->subcommand);
    zf_pin_snapshot_state(app, state);

    switch (parsed->subcommand) {
    case ZF_CLIENT_PIN_SUBCMD_GET_RETRIES:
        status = zf_client_pin_response_retries(state, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_KEY_AGREEMENT:
        status = zf_client_pin_response_key_agreement(state, out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_SET_PIN:
        status = zf_client_pin_handle_set_pin(app->storage, state, parsed, scratch, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_TOKEN:
        status = zf_client_pin_handle_get_pin_token(app->storage, state, parsed, scratch, false,
                                                    out, out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
        status = zf_client_pin_handle_get_pin_token(app->storage, state, parsed, scratch, true, out,
                                                    out_capacity, out_len);
        break;
    case ZF_CLIENT_PIN_SUBCMD_CHANGE_PIN:
        status = zf_client_pin_handle_change_pin(app->storage, state, parsed, scratch, out_len);
        break;
    default:
        status = ZF_CTAP_ERR_INVALID_SUBCOMMAND;
        break;
    }
    zf_pin_publish_state(app, state);
cleanup:
    zf_pin_log_result(diagnostic_tag, status);
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
    zf_app_command_scratch_release(app);
    return status;
}
