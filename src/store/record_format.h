#pragma once

#include <stdbool.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

void zf_store_record_format_hex_encode(const uint8_t *data, size_t size, char *out);
bool zf_store_record_format_is_record_name(const char *name);
bool zf_store_record_format_load_index_with_buffer(Storage *storage, const char *file_name,
                                                   ZfCredentialIndexEntry *entry, uint8_t *buffer,
                                                   size_t buffer_size);
bool zf_store_record_format_load_record_with_buffer(Storage *storage, const char *file_name,
                                                    ZfCredentialRecord *record, uint8_t *buffer,
                                                    size_t buffer_size);
bool zf_store_record_format_reserve_counter(Storage *storage, const ZfCredentialRecord *record,
                                            uint32_t *out_high_water);
bool zf_store_record_format_write_record_with_buffer(Storage *storage,
                                                     const ZfCredentialRecord *record,
                                                     uint8_t *buffer, size_t buffer_size);
