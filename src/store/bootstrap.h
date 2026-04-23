#pragma once

#include <stdbool.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

bool zf_store_bootstrap_ensure_app_data_dir(Storage *storage);
bool zf_store_bootstrap_init(Storage *storage, ZfCredentialStore *store);
bool zf_store_bootstrap_wipe_app_data(Storage *storage);
