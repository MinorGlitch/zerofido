#include "zerofido_ctap.h"

#include "ctap/dispatch.h"
#include "ctap/policy.h"
#include "zerofido_app_i.h"
#include "zerofido_runtime_config.h"
#include "zerofido_ui.h"

static const char *zf_ctap_command_name(ZerofidoApp *app, uint8_t cmd) {
    switch (cmd) {
    case ZfCtapeCmdGetInfo:
        return "GI";
    case ZfCtapeCmdClientPin:
        return app->last_ctap_command_tag[0] ? app->last_ctap_command_tag : "CP";
    case ZfCtapeCmdReset:
        return "RST";
    case ZfCtapeCmdMakeCredential:
        return "MC";
    case ZfCtapeCmdGetAssertion:
        return "GA";
    case ZfCtapeCmdGetNextAssertion:
        return "GN";
    case ZfCtapeCmdSelection:
        return "SEL";
    default:
        return "UK";
    }
}

static const char *zf_ctap_status_name(uint8_t status) {
    switch (status) {
    case ZF_CTAP_SUCCESS:
        return "OK";
    case ZF_CTAP_ERR_INVALID_COMMAND:
        return "ICMD";
    case ZF_CTAP_ERR_INVALID_PARAMETER:
        return "IPRM";
    case ZF_CTAP_ERR_INVALID_LENGTH:
        return "LEN";
    case ZF_CTAP_ERR_INVALID_CHANNEL:
        return "CHAN";
    case ZF_CTAP_ERR_CBOR_UNEXPECTED_TYPE:
    case ZF_CTAP_ERR_INVALID_CBOR:
        return "CBOR";
    case ZF_CTAP_ERR_MISSING_PARAMETER:
        return "MISS";
    case ZF_CTAP_ERR_CREDENTIAL_EXCLUDED:
        return "EXCL";
    case ZF_CTAP_ERR_UNSUPPORTED_ALGORITHM:
        return "ALG";
    case ZF_CTAP_ERR_OPERATION_DENIED:
        return "DENY";
    case ZF_CTAP_ERR_KEY_STORE_FULL:
        return "FULL";
    case ZF_CTAP_ERR_UNSUPPORTED_OPTION:
        return "UOPT";
    case ZF_CTAP_ERR_INVALID_OPTION:
        return "IOPT";
    case ZF_CTAP_ERR_KEEPALIVE_CANCEL:
        return "CANCEL";
    case ZF_CTAP_ERR_NO_CREDENTIALS:
        return "NOCRED";
    case ZF_CTAP_ERR_USER_ACTION_TIMEOUT:
        return "TIME";
    case ZF_CTAP_ERR_NOT_ALLOWED:
        return "NALLOW";
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
    case ZF_CTAP_ERR_PIN_REQUIRED:
        return "PREQ";
    case ZF_CTAP_ERR_PIN_POLICY_VIOLATION:
        return "PPOL";
    case ZF_CTAP_ERR_PIN_TOKEN_EXPIRED:
        return "PTOK";
    case ZF_CTAP_ERR_INVALID_SUBCOMMAND:
        return "SUB";
    case ZF_CTAP_ERR_OTHER:
        return "OTHER";
    default:
        return "UNK";
    }
}

static void zf_ctap_note_result(ZerofidoApp *app, uint8_t cmd, uint8_t status) {
    char step[24];
    char text[96];

    if (!app) {
        return;
    }

    snprintf(step, sizeof(step), "%s %s", zf_ctap_command_name(app, cmd),
             zf_ctap_status_name(status));
    if (app->last_ctap_step[0]) {
        snprintf(text, sizeof(text), "CTAP: %s > %s", app->last_ctap_step, step);
    } else {
        snprintf(text, sizeof(text), "CTAP: %s", step);
    }
    strncpy(app->last_ctap_step, step, sizeof(app->last_ctap_step) - 1);
    app->last_ctap_step[sizeof(app->last_ctap_step) - 1] = '\0';
    app->last_ctap_command_tag[0] = '\0';
    zerofido_ui_set_status(app, text);
}

size_t zerofido_handle_ctap2(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                             size_t request_len, uint8_t *response, size_t response_capacity) {
    uint8_t status = ZF_CTAP_ERR_INVALID_COMMAND;
    size_t body_len = 0;
    size_t body_capacity = response_capacity - 1;
    ZfResolvedCapabilities capabilities;

    if (request_len == 0 || response_capacity <= 1) {
        return 0;
    }

    zf_runtime_get_effective_capabilities(app, &capabilities);
    if (!zf_runtime_ctap_command_enabled(app, request[0])) {
        response[0] = ZF_CTAP_ERR_INVALID_COMMAND;
        zf_ctap_note_result(app, request[0], ZF_CTAP_ERR_INVALID_COMMAND);
        return 1;
    }

    status = zf_ctap_dispatch_command(app, &capabilities, cid, request[0], request + 1,
                                      request_len - 1, response + 1, body_capacity, &body_len);

    if (status != ZF_CTAP_SUCCESS) {
        body_len = 0;
    }

    response[0] = status;
    zf_ctap_note_result(app, request[0], status);
    return body_len + 1;
}
