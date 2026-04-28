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

#include "bootstrap.h"

#include <string.h>

#include "../zerofido_store.h"
#include "../zerofido_crypto.h"
#include "internal.h"
#include "record_format.h"
#include "recovery.h"

static bool zf_store_remove_optional_path(Storage *storage, const char *path) {
    FS_Error result = storage_common_remove(storage, path);
    return result == FSE_OK || result == FSE_NOT_EXIST;
}

bool zf_store_bootstrap_ensure_app_data_dir(Storage *storage) {
    if (!storage_dir_exists(storage, ZF_APP_DATA_ROOT) &&
        !storage_simply_mkdir(storage, ZF_APP_DATA_ROOT)) {
        return false;
    }

    if (!storage_dir_exists(storage, ZF_APP_DATA_DIR) &&
        !storage_simply_mkdir(storage, ZF_APP_DATA_DIR)) {
        return false;
    }

    return true;
}

bool zf_store_bootstrap_init_with_buffer(Storage *storage, ZfCredentialStore *store,
                                         uint8_t *buffer, size_t buffer_size) {
    File *dir = NULL;
    FileInfo info;
    char name[96];
    bool dir_opened = false;
    bool ok = false;

    if (!storage || !store || !store->records || !buffer ||
        buffer_size < ZF_STORE_RECORD_MAX_SIZE) {
        return false;
    }

    memset(store->records, 0, sizeof(store->records[0]) * ZF_MAX_CREDENTIALS);
    store->count = 0;
    if (!zf_store_bootstrap_ensure_app_data_dir(storage)) {
        goto cleanup;
    }

    zf_store_recovery_cleanup_temp_files(storage);
    dir = storage_file_alloc(storage);
    if (!dir) {
        goto cleanup;
    }
    if (!storage_dir_open(dir, ZF_APP_DATA_DIR)) {
        goto cleanup;
    }
    dir_opened = true;

    while (storage_dir_read(dir, &info, name, sizeof(name))) {
        if (file_info_is_dir(&info)) {
            continue;
        }
        if (!zf_store_record_format_is_record_name(name)) {
            continue;
        }
        if (store->count >= ZF_MAX_CREDENTIALS) {
            break;
        }
        if (zf_store_record_format_load_index_with_buffer(
                storage, name, &store->records[store->count], buffer,
                ZF_STORE_RECORD_MAX_SIZE)) {
            store->count++;
        }
    }

    ok = true;

cleanup:
    if (dir_opened) {
        storage_dir_close(dir);
    }
    if (dir) {
        storage_file_free(dir);
    }
    zf_crypto_secure_zero(buffer, ZF_STORE_RECORD_MAX_SIZE);
    return ok;
}

bool zf_store_bootstrap_wipe_app_data(Storage *storage) {
    File *dir = NULL;
    FileInfo info;
    char name[96];

    if (!zf_store_bootstrap_ensure_app_data_dir(storage)) {
        return false;
    }

    dir = storage_file_alloc(storage);
    if (!dir) {
        return false;
    }
    if (!storage_dir_open(dir, ZF_APP_DATA_DIR)) {
        storage_file_free(dir);
        return false;
    }

    if (!zf_store_remove_optional_path(storage, ZF_APP_DATA_DIR "/client_pin.bin") ||
        !zf_store_remove_optional_path(storage, ZF_APP_DATA_DIR "/client_pin.tmp")) {
        storage_dir_close(dir);
        storage_file_free(dir);
        return false;
    }

    while (storage_dir_read(dir, &info, name, sizeof(name))) {
        char path[128];

        if (file_info_is_dir(&info)) {
            continue;
        }

        zf_store_build_record_path(name, path, sizeof(path));
        if (!zf_store_remove_optional_path(storage, path)) {
            storage_dir_close(dir);
            storage_file_free(dir);
            return false;
        }
    }

    storage_dir_close(dir);
    storage_file_free(dir);
    return true;
}
