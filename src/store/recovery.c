#include "recovery.h"

#include <string.h>

#include "internal.h"
#include "record_format_internal.h"

void zf_store_recovery_cleanup_temp_files(Storage *storage) {
    File *dir = storage_file_alloc(storage);
    FileInfo info;
    char name[96];

    if (!dir) {
        return;
    }
    if (storage_dir_open(dir, ZF_APP_DATA_DIR)) {
        while (storage_dir_read(dir, &info, name, sizeof(name))) {
            if (file_info_is_dir(&info)) {
                continue;
            }

            if (zf_store_has_suffix(name, ".tmp")) {
                char path[128];
                zf_store_build_record_path(name, path, sizeof(path));
                storage_common_remove(storage, path);
            } else if (zf_store_has_suffix(name, ".bak")) {
                char file_name[96];
                char backup_path[128];
                char record_path[128];
                size_t base_len = strlen(name) - 4;

                if (base_len == 0 || base_len >= sizeof(file_name)) {
                    continue;
                }
                memcpy(file_name, name, base_len);
                file_name[base_len] = '\0';
                zf_store_build_record_path(name, backup_path, sizeof(backup_path));
                zf_store_build_record_path(file_name, record_path, sizeof(record_path));
                if (storage_file_exists(storage, record_path)) {
                    storage_common_remove(storage, backup_path);
                } else {
                    storage_common_rename(storage, backup_path, record_path);
                }
            }
        }
    }

    storage_dir_close(dir);
    storage_file_free(dir);
}

bool zf_store_recovery_remove_record_paths(Storage *storage, const char *file_name) {
    char record_path[128];
    char counter_path[128];
    FS_Error record_result;
    FS_Error counter_result;

    zf_store_build_record_path(file_name, record_path, sizeof(record_path));
    zf_store_build_counter_floor_path(file_name, counter_path, sizeof(counter_path));
    record_result = storage_common_remove(storage, record_path);
    counter_result = storage_common_remove(storage, counter_path);

    return (record_result == FSE_OK || record_result == FSE_NOT_EXIST) &&
           (counter_result == FSE_OK || counter_result == FSE_NOT_EXIST);
}

bool zf_store_recovery_replace_record(Storage *storage, const char *old_file_name,
                                      const ZfCredentialRecord *record) {
    uint8_t buffer[ZF_STORE_RECORD_MAX_SIZE];
    size_t encoded_size = 0;
    char old_path[128];
    char old_backup_path[128];
    char new_path[128];
    char new_temp_path[128];
    File *file = NULL;
    bool opened = false;
    bool wrote = false;

    if (strcmp(old_file_name, record->file_name) == 0) {
        return false;
    }
    if (!zf_store_record_format_encode(record, buffer, &encoded_size)) {
        return false;
    }

    file = storage_file_alloc(storage);
    if (!file) {
        return false;
    }

    zf_store_build_record_path(old_file_name, old_path, sizeof(old_path));
    zf_store_build_backup_path(old_file_name, old_backup_path, sizeof(old_backup_path));
    zf_store_build_record_path(record->file_name, new_path, sizeof(new_path));
    zf_store_build_temp_path(record->file_name, new_temp_path, sizeof(new_temp_path));

    storage_common_remove(storage, old_backup_path);
    storage_common_remove(storage, new_temp_path);

    opened = storage_file_open(file, new_temp_path, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    wrote = opened && (storage_file_write(file, buffer, encoded_size) == encoded_size);
    storage_file_close(file);
    if (!wrote) {
        storage_common_remove(storage, new_temp_path);
        storage_file_free(file);
        return false;
    }

    if (storage_common_rename(storage, old_path, old_backup_path) != FSE_OK) {
        storage_common_remove(storage, new_temp_path);
        storage_file_free(file);
        return false;
    }
    if (storage_common_rename(storage, new_temp_path, new_path) != FSE_OK) {
        storage_common_rename(storage, old_backup_path, old_path);
        storage_common_remove(storage, new_temp_path);
        storage_file_free(file);
        return false;
    }

    storage_common_remove(storage, new_temp_path);
    storage_common_remove(storage, old_backup_path);
    storage_file_free(file);
    return true;
}
