#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zerofido_types.h"

const uint8_t *zf_attestation_get_aaguid(void);
const char *zf_attestation_get_aaguid_string(void);
const uint8_t *zf_attestation_get_leaf_cert_der(size_t *out_len);
const uint8_t *zf_attestation_get_leaf_private_key(void);
size_t zf_attestation_get_cert_chain(const uint8_t **certs, size_t *cert_lens, size_t max_certs);
bool zf_attestation_sign_input(const uint8_t *input, size_t input_len, uint8_t *out,
                               size_t out_capacity, size_t *out_len);
bool zf_attestation_validate_consistency(void);
void zf_attestation_reset_consistency_cache(void);
