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
