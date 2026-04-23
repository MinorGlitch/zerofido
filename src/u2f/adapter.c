#include "adapter.h"

#include <stdio.h>
#include <string.h>

#include "apdu.h"
#include "session.h"
#include "persistence.h"
#include "../zerofido_app_i.h"
#include "../zerofido_attestation.h"
#include "../zerofido_notify.h"
#include "../zerofido_runtime_config.h"
#include "../zerofido_ui.h"

#define ZF_U2F_REGISTER_REQ_LEN 71
#define ZF_U2F_APP_ID_OFFSET 39
#define ZF_U2F_APP_ID_SIZE 32
#define ZF_U2F_VERSION_RESPONSE_LEN 8

static const uint8_t zf_u2f_adapter_state_user_missing[] = {0x69, 0x85};
static const uint8_t zf_u2f_adapter_state_wrong_length[] = {0x67, 0x00};
static const uint8_t zf_u2f_adapter_state_not_supported[] = {0x6D, 0x00};
static const uint8_t zf_u2f_adapter_version_response[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};

static uint16_t zf_u2f_adapter_reply_status(uint8_t *response, const uint8_t status[2]) {
    memcpy(response, status, 2);
    return 2;
}

static uint16_t zf_u2f_adapter_reply_version(uint8_t *response, size_t response_capacity) {
    if (response_capacity < sizeof(zf_u2f_adapter_version_response)) {
        return zf_u2f_adapter_reply_status(response, zf_u2f_adapter_state_wrong_length);
    }

    memcpy(response, zf_u2f_adapter_version_response, sizeof(zf_u2f_adapter_version_response));
    return sizeof(zf_u2f_adapter_version_response);
}

static bool zf_u2f_adapter_ensure_attestation_assets(const uint8_t *cert, size_t cert_len,
                                                     const uint8_t *cert_key,
                                                     size_t cert_key_len) {
    uint8_t loaded_cert_key[ZF_PRIVATE_KEY_LEN];
    bool assets_ready = false;

    if (cert_key_len != sizeof(loaded_cert_key)) {
        return false;
    }

    memset(loaded_cert_key, 0, sizeof(loaded_cert_key));
    if (u2f_data_check(true) && u2f_data_cert_check() && u2f_data_cert_key_load(loaded_cert_key) &&
        u2f_data_cert_key_matches(loaded_cert_key)) {
        assets_ready = true;
    }
    memset(loaded_cert_key, 0, sizeof(loaded_cert_key));

    if (assets_ready) {
        return true;
    }

    return u2f_data_bootstrap_attestation_assets(cert, cert_len, cert_key, cert_key_len);
}

static void zf_u2f_format_app_id(const uint8_t *request, size_t request_len, char *out,
                                 size_t out_len) {
    if (request_len < ZF_U2F_APP_ID_OFFSET + ZF_U2F_APP_ID_SIZE || out_len < 3) {
        strncpy(out, "U2F", out_len - 1);
        out[out_len - 1] = '\0';
        return;
    }

    snprintf(out, out_len, "app %02x%02x%02x%02x%02x%02x%02x%02x...",
             request[ZF_U2F_APP_ID_OFFSET + 0], request[ZF_U2F_APP_ID_OFFSET + 1],
             request[ZF_U2F_APP_ID_OFFSET + 2], request[ZF_U2F_APP_ID_OFFSET + 3],
             request[ZF_U2F_APP_ID_OFFSET + 4], request[ZF_U2F_APP_ID_OFFSET + 5],
             request[ZF_U2F_APP_ID_OFFSET + 6], request[ZF_U2F_APP_ID_OFFSET + 7]);
}

static bool zf_u2f_request_approval(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                                    uint16_t request_len) {
    const char *operation = NULL;
    if (!zf_u2f_adapter_is_available(app)) {
        return false;
    }
    if (!u2f_request_needs_user_presence(request, request_len, &operation)) {
        return true;
    }

    char rp_text[48];
    bool approved = false;
    zf_u2f_format_app_id(request, request_len, rp_text, sizeof(rp_text));
    if (!zerofido_ui_request_approval(app, ZfUiProtocolU2f, operation, rp_text, "Touch required",
                                      cid, &approved)) {
        return false;
    }

    if (!approved) {
        return false;
    }

    u2f_confirm_user_present(app->u2f);
    return true;
}

static void zf_u2f_event_callback(U2fNotifyEvent evt, void *context) {
    ZerofidoApp *app = context;

    furi_assert(app);

    switch (evt) {
    case U2fNotifyAuthSuccess:
        zerofido_notify_success(app);
        break;
    case U2fNotifyWink:
        zerofido_notify_wink(app);
        break;
    case U2fNotifyError:
        zerofido_notify_error(app);
        break;
    case U2fNotifyRegister:
    case U2fNotifyAuth:
    case U2fNotifyConnect:
    case U2fNotifyDisconnect:
    default:
        break;
    }
}

bool zf_u2f_adapter_init(ZerofidoApp *app) {
    size_t cert_len = 0;
    const uint8_t *cert = zf_attestation_get_leaf_cert_der(&cert_len);
    const uint8_t *cert_key = zf_attestation_get_leaf_private_key();
    ZfResolvedCapabilities capabilities;

    if (!app) {
        return false;
    }
    zf_runtime_get_effective_capabilities(app, &capabilities);
    if (!capabilities.u2f_enabled) {
        return true;
    }

    app->u2f = u2f_alloc();
    if (!app->u2f) {
        return false;
    }

    if (!zf_u2f_adapter_ensure_attestation_assets(cert, cert_len, cert_key, ZF_PRIVATE_KEY_LEN)) {
        u2f_free(app->u2f);
        app->u2f = NULL;
        return false;
    }

    if (!u2f_init(app->u2f)) {
        u2f_free(app->u2f);
        app->u2f = NULL;
        return false;
    }

    u2f_set_event_callback(app->u2f, zf_u2f_event_callback, app);
    return true;
}

void zf_u2f_adapter_deinit(ZerofidoApp *app) {
    if (!app->u2f) {
        return;
    }

    u2f_free(app->u2f);
    app->u2f = NULL;
}

bool zf_u2f_adapter_is_available(const ZerofidoApp *app) {
    return app && app->u2f;
}

void zf_u2f_adapter_set_connected(ZerofidoApp *app, bool connected) {
    if (!app->u2f) {
        return;
    }

    u2f_set_state(app->u2f, connected ? 1 : 0);
}

size_t zf_u2f_adapter_handle_msg(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                                 size_t request_len, uint8_t *response, size_t response_capacity) {
    ZfResolvedCapabilities capabilities;
    uint16_t validation_status = 0;

    zf_runtime_get_effective_capabilities(app, &capabilities);
    if (!capabilities.u2f_enabled || request_len == 0 || response_capacity < 2) {
        return 0;
    }
    if (request_len > UINT16_MAX) {
        return zf_u2f_adapter_reply_status(response, zf_u2f_adapter_state_wrong_length);
    }

    validation_status =
        u2f_validate_request_into_response(request, (uint16_t)request_len, response,
                                          (uint16_t)response_capacity);
    if (validation_status != 0) {
        return validation_status;
    }
    if (request_len > response_capacity) {
        return zf_u2f_adapter_reply_status(response, zf_u2f_adapter_state_wrong_length);
    }
    if (request[1] == U2F_CMD_VERSION && !zf_u2f_adapter_is_available(app)) {
        return zf_u2f_adapter_reply_version(response, response_capacity);
    }

    memcpy(response, request, request_len);
    if (!zf_u2f_adapter_is_available(app)) {
        return zf_u2f_adapter_reply_status(response, zf_u2f_adapter_state_not_supported);
    }
    if (response_capacity < ZF_U2F_VERSION_RESPONSE_LEN) {
        return 0;
    }
    if (!zf_u2f_request_approval(app, cid, response, (uint16_t)request_len)) {
        memcpy(response, zf_u2f_adapter_state_user_missing,
               sizeof(zf_u2f_adapter_state_user_missing));
        return sizeof(zf_u2f_adapter_state_user_missing);
    }

    return u2f_msg_parse(app->u2f, response, (uint16_t)request_len, (uint16_t)response_capacity);
}

void zf_u2f_adapter_wink(ZerofidoApp *app) {
    if (app->u2f) {
        u2f_wink(app->u2f);
    }
}
