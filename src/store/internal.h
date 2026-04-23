#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../zerofido_types.h"

#define ZF_STORE_RECORD_MAX_SIZE 768

static inline bool zf_store_has_suffix(const char *value, const char *suffix) {
    size_t value_len = strlen(value);
    size_t suffix_len = strlen(suffix);

    return value_len >= suffix_len && strcmp(value + value_len - suffix_len, suffix) == 0;
}

static inline void zf_store_build_record_path(const char *file_name, char *path, size_t path_size) {
    snprintf(path, path_size, ZF_APP_DATA_DIR "/%s", file_name);
}

static inline void zf_store_build_temp_path(const char *file_name, char *path, size_t path_size) {
    snprintf(path, path_size, ZF_APP_DATA_DIR "/%s.tmp", file_name);
}

static inline void zf_store_build_backup_path(const char *file_name, char *path, size_t path_size) {
    snprintf(path, path_size, ZF_APP_DATA_DIR "/%s.bak", file_name);
}

static inline void zf_store_build_counter_floor_path(const char *file_name, char *path,
                                                     size_t path_size) {
    snprintf(path, path_size, ZF_APP_DATA_DIR "/%s.counter", file_name);
}

static inline void zf_store_build_counter_floor_temp_path(const char *file_name, char *path,
                                                          size_t path_size) {
    snprintf(path, path_size, ZF_APP_DATA_DIR "/%s.counter.tmp", file_name);
}
