#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_runtime_config.h"
#include "../zerofido_types.h"

uint8_t zf_ctap_build_get_info_response(const ZfResolvedCapabilities *capabilities,
                                        bool client_pin_set, uint8_t *out, size_t out_capacity,
                                        size_t *out_len);
uint8_t
zf_ctap_build_make_credential_response(const char *rp_id, const ZfCredentialRecord *record,
                                       const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN],
                                       bool user_verified, bool include_cred_protect, uint8_t *out,
                                       size_t out_capacity, size_t *out_len);
uint8_t zf_ctap_build_assertion_response(const ZfGetAssertionRequest *request,
                                         const ZfCredentialRecord *record, bool user_present,
                                         bool user_verified, uint32_t sign_count,
                                         bool include_user_details, bool include_count,
                                         size_t match_count, uint8_t *out, size_t out_capacity,
                                         size_t *out_len);
