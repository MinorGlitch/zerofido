#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_runtime_config.h"
#include "../zerofido_types.h"

typedef struct {
    uint8_t auth_data[288];
    uint8_t cose[128];
    uint8_t extension_data[32];
} ZfMakeCredentialResponseScratch;

typedef struct {
    uint8_t auth_data[37];
    uint8_t sign_hash[32];
    uint8_t signature[80];
} ZfAssertionResponseScratch;

uint8_t zf_ctap_build_get_info_response(const ZfResolvedCapabilities *capabilities,
                                        bool client_pin_set, uint8_t *out, size_t out_capacity,
                                        size_t *out_len);
uint8_t zf_ctap_build_make_credential_response_with_scratch(
    ZfMakeCredentialResponseScratch *scratch, const char *rp_id, const ZfCredentialRecord *record,
    const uint8_t client_data_hash[ZF_CLIENT_DATA_HASH_LEN], bool user_verified,
    bool include_cred_protect, uint8_t *out, size_t out_capacity, size_t *out_len);
uint8_t zf_ctap_build_assertion_response_with_scratch(
    ZfAssertionResponseScratch *scratch, const ZfGetAssertionRequest *request,
    const ZfCredentialRecord *record, bool user_present, bool user_verified, uint32_t sign_count,
    bool include_user_details, bool include_count, size_t match_count, bool user_selected,
    uint8_t *out, size_t out_capacity, size_t *out_len);
