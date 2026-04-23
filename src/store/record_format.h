#pragma once

#include <stdbool.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

void zf_store_record_format_hex_encode(const uint8_t *data, size_t size, char *out);
bool zf_store_record_format_is_record_name(const char *name);
bool zf_store_record_format_load_index(Storage *storage, const char *file_name,
                                       ZfCredentialIndexEntry *entry);
bool zf_store_record_format_load_record(Storage *storage, const char *file_name,
                                        ZfCredentialRecord *record);
bool zf_store_record_format_write_record(Storage *storage, const ZfCredentialRecord *record);
