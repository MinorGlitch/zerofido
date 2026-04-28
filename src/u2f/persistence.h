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

#ifdef __cplusplus
extern "C" {
#endif

#include <furi.h>
#include <storage/storage.h>

bool u2f_data_check(bool cert_only);

bool u2f_data_cert_check(void);

uint32_t u2f_data_cert_load(uint8_t *cert, size_t capacity);

bool u2f_data_cert_key_load(uint8_t *cert_key);
bool u2f_data_cert_key_matches(const uint8_t *cert_key);
bool u2f_data_bootstrap_attestation_assets(const uint8_t *cert, size_t cert_len,
                                           const uint8_t *cert_key, size_t cert_key_len);

bool u2f_data_key_exists(void);
bool u2f_data_key_load(uint8_t *device_key);

bool u2f_data_key_generate(uint8_t *device_key);

bool u2f_data_cnt_exists(void);
bool u2f_data_cnt_read(uint32_t *cnt);

bool u2f_data_cnt_reserve(uint32_t cnt, uint32_t *reserved_cnt);
bool u2f_data_cnt_write(uint32_t cnt);
bool u2f_data_wipe(Storage *storage);

#ifdef __cplusplus
}
#endif
