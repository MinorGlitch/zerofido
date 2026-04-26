#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "zerofido_types.h"

typedef enum {
    ZfUiProtocolFido2 = 0,
    ZfUiProtocolU2f = 1,
} ZfUiProtocol;

const char *zf_ui_protocol_label(ZfUiProtocol protocol);
const char *zf_ui_protocol_target_label(ZfUiProtocol protocol);
const char *zf_ui_fido2_credential_type_tag(bool resident_key);
const char *zf_ui_fido2_credential_type_label(bool resident_key);
void zf_ui_hex_encode_truncated(const uint8_t *data, size_t size, char *out, size_t out_size);
void zf_ui_format_approval_header(char *out, size_t out_size, ZfUiProtocol protocol,
                                  const char *operation);
void zf_ui_format_approval_body(char *out, size_t out_size, ZfUiProtocol protocol,
                                const char *target_id, const char *user_text);
void zf_ui_format_assertion_selection_label(const ZfCredentialRecord *record, char *out,
                                            size_t out_size);
void zf_ui_format_fido2_credential_label(const ZfCredentialRecord *record, char *out,
                                         size_t out_size);
void zf_ui_format_fido2_credential_detail(const ZfCredentialRecord *record, char *out,
                                          size_t out_size);
