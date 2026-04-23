#include "zerofido_ui_format.h"

#include <stdio.h>

void zf_ui_hex_encode_truncated(const uint8_t *data, size_t size, char *out, size_t out_size) {
    static const char *hex = "0123456789abcdef";
    size_t limit = (out_size > 0) ? (out_size - 1) / 2 : 0;

    if (out_size == 0) {
        return;
    }

    if (size > limit) {
        size = limit;
    }

    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = hex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[data[i] & 0x0F];
    }
    out[size * 2] = '\0';
}

const char *zf_ui_protocol_label(ZfUiProtocol protocol) {
    return protocol == ZfUiProtocolU2f ? "U2F" : "FIDO2";
}

const char *zf_ui_protocol_target_label(ZfUiProtocol protocol) {
    return protocol == ZfUiProtocolU2f ? "App ID" : "RP ID";
}

const char *zf_ui_fido2_credential_type_tag(bool resident_key) {
    return resident_key ? "F2/RK" : "F2/AL";
}

const char *zf_ui_fido2_credential_type_label(bool resident_key) {
    return resident_key ? "Discoverable" : "Allow-list";
}

void zf_ui_format_approval_header(char *out, size_t out_size, ZfUiProtocol protocol,
                                  const char *operation) {
    snprintf(out, out_size, "%s %s", zf_ui_protocol_label(protocol),
             operation ? operation : "Operation");
}

void zf_ui_format_approval_body(char *out, size_t out_size, ZfUiProtocol protocol,
                                const char *target_id, const char *user_text) {
    snprintf(out, out_size, "Protocol: %s\n%s: %.60s\n%.40s", zf_ui_protocol_label(protocol),
             zf_ui_protocol_target_label(protocol),
             (target_id && target_id[0]) ? target_id : "(unknown)",
             (user_text && user_text[0]) ? user_text : "User: (not provided)");
}

void zf_ui_format_assertion_selection_label(const ZfCredentialIndexEntry *record, char *out,
                                            size_t out_size) {
    char credential_id[17];
    const char *base = NULL;

    if (!record) {
        snprintf(out, out_size, "Account");
        return;
    }

    base = record->user_display_name[0] ? record->user_display_name
                                        : (record->user_name[0] ? record->user_name : "Account");
    zf_ui_hex_encode_truncated(record->credential_id, record->credential_id_len, credential_id,
                               sizeof(credential_id));
    snprintf(out, out_size, "%s | %s", base, credential_id);
}

void zf_ui_format_fido2_credential_label(const ZfCredentialIndexEntry *record, char *out,
                                         size_t out_size) {
    const char *user_text = NULL;

    if (!record) {
        snprintf(out, out_size, "F2/--");
        return;
    }

    user_text = record->user_name[0] ? record->user_name
                                     : (record->resident_key ? "(discoverable)" : "(allow-list)");
    snprintf(out, out_size, "%s %s | %s", zf_ui_fido2_credential_type_tag(record->resident_key),
             record->rp_id, user_text);
}

void zf_ui_format_fido2_credential_detail(const ZfCredentialIndexEntry *record, char *out,
                                          size_t out_size) {
    char credential_id[17];
    const char *user_name = NULL;

    if (!record) {
        snprintf(out, out_size, "No credential selected");
        return;
    }

    user_name = record->user_name[0] ? record->user_name : "(not stored)";
    zf_ui_hex_encode_truncated(record->credential_id, record->credential_id_len, credential_id,
                               sizeof(credential_id));

    snprintf(out, out_size,
             "Protocol: FIDO2\nType: %s\nRP: %s\nUser: %s\nCount: %lu\nCreated: %lu\nID: %s",
             zf_ui_fido2_credential_type_label(record->resident_key), record->rp_id, user_name,
             (unsigned long)record->sign_count, (unsigned long)record->created_at, credential_id);
}
