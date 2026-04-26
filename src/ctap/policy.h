#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"
#include <storage/storage.h>

typedef struct ZerofidoApp ZerofidoApp;

bool zf_ctap_request_uses_allow_list(const ZfGetAssertionRequest *request);
uint8_t zf_ctap_validate_pin_auth_protocol(bool has_pin_auth, bool has_pin_protocol,
                                           uint64_t pin_protocol);
bool zf_ctap_effective_uv_requested(bool has_pin_auth, bool has_uv, bool uv);
uint8_t zf_ctap_require_empty_payload(size_t request_len);
bool zf_ctap_local_maintenance_busy(ZerofidoApp *app);
bool zf_ctap_pin_is_set(ZerofidoApp *app);
bool zf_ctap_store_entry_matches_descriptor_list(const ZfCredentialIndexEntry *entry,
                                                 const void *context);
size_t zf_ctap_resolve_assertion_matches(Storage *storage, ZfCredentialStore *store,
                                         const ZfGetAssertionRequest *request, bool uv_verified,
                                         uint16_t *match_indices);
