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

#include "../../zerofido_cbor.h"
#include "../../zerofido_types.h"

bool zf_ctap_text_equals(const uint8_t *ptr, size_t size, const char *text);

bool zf_ctap_mark_seen_key(uint16_t *seen_keys, uint64_t key);

bool zf_ctap_cbor_read_text_copy(ZfCborCursor *cursor, char *out, size_t out_size);

bool zf_ctap_cbor_read_text_discard(ZfCborCursor *cursor);

bool zf_ctap_cbor_read_bytes_copy(ZfCborCursor *cursor, uint8_t *out, size_t out_capacity,
                                  size_t *out_size);

bool zf_ctap_parse_options_map(ZfCborCursor *cursor, bool *up, bool *has_up, bool *uv, bool *has_uv,
                               bool *rk, bool *has_rk);

uint8_t zf_ctap_parse_extensions_map(ZfCborCursor *cursor, bool *has_cred_protect,
                                     uint8_t *cred_protect);

uint8_t zf_ctap_parse_pubkey_cred_params(ZfCborCursor *cursor, bool *es256_supported);

uint8_t zf_ctap_parse_descriptor_array(ZfCborCursor *cursor, ZfCredentialDescriptorList *list);
