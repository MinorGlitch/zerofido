#pragma once

#include <stdbool.h>

#include <storage/storage.h>

#include "../zerofido_types.h"

void zf_store_recovery_cleanup_temp_files(Storage *storage);
bool zf_store_recovery_remove_record_paths(Storage *storage, const char *file_name);
