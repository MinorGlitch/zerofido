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

bool u2f_data_cnt_write(uint32_t cnt);
bool u2f_data_wipe(Storage *storage);

#ifdef __cplusplus
}
#endif
