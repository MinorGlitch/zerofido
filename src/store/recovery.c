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

#include "recovery.h"

#include <string.h>

#include "../zerofido_storage.h"
#include "internal.h"

typedef struct {
    Storage *storage;
} ZfStoreRecoveryCleanupContext;

static bool zf_store_recovery_cleanup_visitor(const char *name, const FileInfo *info,
                                              void *context) {
    ZfStoreRecoveryCleanupContext *cleanup_context = context;

    if (!name || !info || !cleanup_context) {
        return false;
    }
    if (file_info_is_dir(info)) {
        return true;
    }

    if (zf_store_has_suffix(name, ".bak")) {
        char file_name[96];
        char backup_path[128];
        char record_path[128];
        size_t base_len = strlen(name) - 4;

        if (base_len == 0U || base_len >= sizeof(file_name)) {
            return true;
        }
        memcpy(file_name, name, base_len);
        file_name[base_len] = '\0';
        if (!zf_storage_build_child_path(ZF_APP_DATA_DIR, name, backup_path,
                                         sizeof(backup_path)) ||
            !zf_storage_build_child_path(ZF_APP_DATA_DIR, file_name, record_path,
                                         sizeof(record_path))) {
            return false;
        }
        if (storage_file_exists(cleanup_context->storage, record_path)) {
            return zf_storage_remove_optional(cleanup_context->storage, backup_path);
        }
        storage_common_rename(cleanup_context->storage, backup_path, record_path);
    }

    return true;
}

/*
 * Startup recovery is conservative: temp files are discarded, while backup
 * files are restored only if the primary record is missing.
 */
void zf_store_recovery_cleanup_temp_files(Storage *storage) {
    char name[96];
    char path[128];
    ZfStoreRecoveryCleanupContext context = {.storage = storage};

    zf_storage_remove_dir_entries_with_suffix(storage, ZF_APP_DATA_DIR, ".tmp", name,
                                              sizeof(name), path, sizeof(path));
    zf_storage_for_each_dir_entry(storage, ZF_APP_DATA_DIR, name, sizeof(name),
                                  zf_store_recovery_cleanup_visitor, &context);
}

bool zf_store_recovery_remove_record_paths(Storage *storage, const char *file_name) {
    char record_path[128];
    char counter_path[128];

    zf_store_build_record_path(file_name, record_path, sizeof(record_path));
    zf_store_build_counter_floor_path(file_name, counter_path, sizeof(counter_path));
    return zf_storage_remove_optional(storage, record_path) &&
           zf_storage_remove_optional(storage, counter_path);
}
