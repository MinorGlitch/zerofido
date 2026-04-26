#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

bool zf_store_bootstrap_ensure_app_data_dir(Storage *storage);
bool zf_store_bootstrap_init_with_buffer(Storage *storage, ZfCredentialStore *store,
                                         uint8_t *buffer, size_t buffer_size);
bool zf_store_bootstrap_wipe_app_data(Storage *storage);
