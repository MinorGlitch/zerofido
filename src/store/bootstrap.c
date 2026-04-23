#include "bootstrap.h"

#include <stdlib.h>
#include <string.h>

#include "../zerofido_store.h"
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

bool zf_store_bootstrap_init(Storage *storage, ZfCredentialStore *store) {
    File *dir = NULL;
    FileInfo info;
    char name[96];
    if (!store->records) {
        store->records = malloc(sizeof(store->records[0]) * ZF_MAX_CREDENTIALS);
        if (!store->records) {
            return false;
        }
    }
    memset(store->records, 0, sizeof(store->records[0]) * ZF_MAX_CREDENTIALS);
    store->count = 0;
    if (!zf_store_bootstrap_ensure_app_data_dir(storage)) {
        return false;
    }

    zf_store_recovery_cleanup_temp_files(storage);
    dir = storage_file_alloc(storage);
    if (!dir) {
        return false;
    }
    if (!storage_dir_open(dir, ZF_APP_DATA_DIR)) {
        storage_file_free(dir);
        return false;
    }

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
        if (zf_store_record_format_load_index(storage, name, &store->records[store->count])) {
            store->count++;
        }
    }

    storage_dir_close(dir);
    storage_file_free(dir);
    return true;
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
