#include "zerofido_store.h"

#include <furi_hal_random.h>
#include <furi_hal_rtc.h>
#include <stdlib.h>
#include <string.h>

#include "store/bootstrap.h"
#include "store/record_format.h"
#include "store/recovery.h"

static bool zf_store_index_is_newer(const ZfCredentialIndexEntry *candidate,
                                    const ZfCredentialIndexEntry *other) {
    if (candidate->created_at != other->created_at) {
        return candidate->created_at > other->created_at;
    }

    return memcmp(candidate->credential_id, other->credential_id, ZF_CREDENTIAL_ID_LEN) > 0;
}

static void zf_store_insert_sorted_index(uint16_t *out_indices, size_t *count, size_t max_out,
                                         const ZfCredentialStore *store, uint16_t index) {
    size_t insert_at = *count;

    if (*count >= max_out || !store || !store->records || index >= store->count) {
        return;
    }

    while (insert_at > 0 &&
           zf_store_index_is_newer(&store->records[index], &store->records[out_indices[insert_at - 1]])) {
        out_indices[insert_at] = out_indices[insert_at - 1];
        insert_at--;
    }
    out_indices[insert_at] = index;
    (*count)++;
}

static void zf_store_compact_after_delete(ZfCredentialStore *store, size_t index) {
    for (size_t j = index + 1; j < store->count; ++j) {
        store->records[j - 1] = store->records[j];
    }
    store->count--;
    memset(&store->records[store->count], 0, sizeof(store->records[store->count]));
}

void zf_store_index_entry_from_record(const ZfCredentialRecord *record,
                                      ZfCredentialIndexEntry *entry) {
    if (!record || !entry) {
        return;
    }

    memset(entry, 0, sizeof(*entry));
    entry->in_use = record->in_use;
    entry->resident_key = record->resident_key;
    memcpy(entry->file_name, record->file_name, sizeof(entry->file_name));
    memcpy(entry->credential_id, record->credential_id, sizeof(entry->credential_id));
    entry->credential_id_len = record->credential_id_len;
    memcpy(entry->rp_id, record->rp_id, sizeof(entry->rp_id));
    memcpy(entry->user_id, record->user_id, sizeof(entry->user_id));
    entry->user_id_len = record->user_id_len;
    memcpy(entry->user_name, record->user_name, sizeof(entry->user_name));
    memcpy(entry->user_display_name, record->user_display_name, sizeof(entry->user_display_name));
    entry->sign_count = record->sign_count;
    entry->created_at = record->created_at;
    entry->cred_protect =
        record->cred_protect == 0 ? ZF_CRED_PROTECT_UV_OPTIONAL : record->cred_protect;
}

bool zf_store_init(Storage *storage, ZfCredentialStore *store) {
    return zf_store_bootstrap_init(storage, store);
}

void zf_store_deinit(ZfCredentialStore *store) {
    if (!store) {
        return;
    }

    free(store->records);
    store->records = NULL;
    store->count = 0;
}

void zf_store_clear(ZfCredentialStore *store) {
    if (!store || !store->records) {
        if (store) {
            store->count = 0;
        }
        return;
    }

    memset(store->records, 0, sizeof(store->records[0]) * ZF_MAX_CREDENTIALS);
    store->count = 0;
}

bool zf_store_wipe_app_data(Storage *storage) {
    return zf_store_bootstrap_wipe_app_data(storage);
}

bool zf_store_prepare_credential(ZfCredentialRecord *record, const char *rp_id,
                                 const uint8_t *user_id, size_t user_id_len, const char *user_name,
                                 const char *user_display_name, bool resident_key) {
    if (user_id_len > ZF_MAX_USER_ID_LEN) {
        return false;
    }

    memset(record, 0, sizeof(*record));
    furi_hal_random_fill_buf(record->credential_id, ZF_CREDENTIAL_ID_LEN);
    record->storage_version = ZF_STORE_FORMAT_VERSION;
    record->credential_id_len = ZF_CREDENTIAL_ID_LEN;
    zf_store_record_format_hex_encode(record->credential_id, record->credential_id_len,
                                      record->file_name);

    strncpy(record->rp_id, rp_id, sizeof(record->rp_id) - 1);
    memcpy(record->user_id, user_id, user_id_len);
    record->user_id_len = user_id_len;
    if (user_name) {
        strncpy(record->user_name, user_name, sizeof(record->user_name) - 1);
    }
    if (user_display_name) {
        strncpy(record->user_display_name, user_display_name,
                sizeof(record->user_display_name) - 1);
    }

    record->created_at = furi_hal_rtc_get_timestamp();
    record->resident_key = resident_key;
    record->cred_protect = ZF_CRED_PROTECT_UV_OPTIONAL;
    record->in_use = true;
    return true;
}

bool zf_store_add_record(Storage *storage, ZfCredentialStore *store,
                         const ZfCredentialRecord *record) {
    if (!store || !store->records || store->count >= ZF_MAX_CREDENTIALS) {
        return false;
    }
    if (!zf_store_record_format_write_record(storage, record)) {
        return false;
    }

    zf_store_index_entry_from_record(record, &store->records[store->count]);
    store->count++;
    return true;
}

bool zf_store_update_record(Storage *storage, ZfCredentialStore *store,
                            const ZfCredentialRecord *record) {
    if (!store || !store->records) {
        return false;
    }

    for (size_t i = 0; i < store->count; ++i) {
        if (!store->records[i].in_use) {
            continue;
        }
        if (store->records[i].credential_id_len != record->credential_id_len ||
            memcmp(store->records[i].credential_id, record->credential_id, record->credential_id_len) != 0) {
            continue;
        }
        if (!zf_store_record_format_write_record(storage, record)) {
            return false;
        }

        zf_store_index_entry_from_record(record, &store->records[i]);
        return true;
    }

    return false;
}

bool zf_store_load_record(Storage *storage, const ZfCredentialIndexEntry *entry,
                          ZfCredentialRecord *out_record) {
    if (!entry || !entry->in_use || !out_record) {
        return false;
    }

    if (zf_store_record_format_load_record(storage, entry->file_name, out_record)) {
        return true;
    }

    memset(out_record, 0, sizeof(*out_record));
    out_record->in_use = entry->in_use;
    out_record->resident_key = entry->resident_key;
    memcpy(out_record->file_name, entry->file_name, sizeof(out_record->file_name));
    memcpy(out_record->credential_id, entry->credential_id, sizeof(out_record->credential_id));
    out_record->credential_id_len = entry->credential_id_len;
    memcpy(out_record->rp_id, entry->rp_id, sizeof(out_record->rp_id));
    memcpy(out_record->user_id, entry->user_id, sizeof(out_record->user_id));
    out_record->user_id_len = entry->user_id_len;
    memcpy(out_record->user_name, entry->user_name, sizeof(out_record->user_name));
    memcpy(out_record->user_display_name, entry->user_display_name,
           sizeof(out_record->user_display_name));
    out_record->sign_count = entry->sign_count;
    out_record->created_at = entry->created_at;
    out_record->cred_protect = entry->cred_protect;
    return true;
}

bool zf_store_load_record_by_index(Storage *storage, const ZfCredentialStore *store, size_t index,
                                   ZfCredentialRecord *out_record) {
    if (!store || !store->records || index >= store->count) {
        return false;
    }

    return zf_store_load_record(storage, &store->records[index], out_record);
}

bool zf_store_delete_resident_credentials_for_user(Storage *storage, ZfCredentialStore *store,
                                                   const char *rp_id, const uint8_t *user_id,
                                                   size_t user_id_len, size_t *deleted_count) {
    size_t removed = 0;
    ZfCredentialRecord record;

    if (!store || !store->records) {
        if (deleted_count) {
            *deleted_count = 0;
        }
        return true;
    }

    for (size_t i = 0; i < store->count;) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use || !entry->resident_key || strcmp(entry->rp_id, rp_id) != 0 ||
            !zf_store_load_record(storage, entry, &record) || record.user_id_len != user_id_len ||
            memcmp(record.user_id, user_id, user_id_len) != 0) {
            ++i;
            continue;
        }

        if (!zf_store_recovery_remove_record_paths(storage, entry->file_name)) {
            return false;
        }

        zf_store_compact_after_delete(store, i);
        ++removed;
    }

    if (deleted_count) {
        *deleted_count = removed;
    }
    return true;
}

ZfStoreDeleteResult zf_store_delete_record(Storage *storage, ZfCredentialStore *store,
                                           const uint8_t *credential_id, size_t credential_id_len) {
    if (!store || !store->records) {
        return ZfStoreDeleteNotFound;
    }

    for (size_t i = 0; i < store->count; ++i) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use || entry->credential_id_len != credential_id_len ||
            memcmp(entry->credential_id, credential_id, credential_id_len) != 0) {
            continue;
        }
        if (!zf_store_recovery_remove_record_paths(storage, entry->file_name)) {
            return ZfStoreDeleteRemoveFailed;
        }

        zf_store_compact_after_delete(store, i);
        return ZfStoreDeleteOk;
    }

    return ZfStoreDeleteNotFound;
}

bool zf_store_find_index_by_id(const ZfCredentialStore *store, const uint8_t *credential_id,
                               size_t credential_id_len, size_t *out_index) {
    if (!store || !store->records) {
        return false;
    }

    for (size_t i = 0; i < store->count; ++i) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use) {
            continue;
        }
        if (entry->credential_id_len == credential_id_len &&
            memcmp(entry->credential_id, credential_id, credential_id_len) == 0) {
            if (out_index) {
                *out_index = i;
            }
            return true;
        }
    }

    return false;
}

size_t zf_store_count_saved(const ZfCredentialStore *store) {
    size_t count = 0;

    if (!store || !store->records) {
        return 0;
    }

    for (size_t i = 0; i < store->count; ++i) {
        if (store->records[i].in_use) {
            ++count;
        }
    }

    return count;
}

size_t zf_store_count_resident(const ZfCredentialStore *store) {
    size_t count = 0;

    if (!store || !store->records) {
        return 0;
    }

    for (size_t i = 0; i < store->count; ++i) {
        if (store->records[i].in_use && store->records[i].resident_key) {
            ++count;
        }
    }

    return count;
}

size_t zf_store_find_by_rp(const ZfCredentialStore *store, const char *rp_id,
                           uint16_t *out_indices, size_t max_out) {
    size_t count = 0;

    if (!store || !store->records) {
        return 0;
    }

    for (size_t i = 0; i < store->count; ++i) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (entry->in_use && entry->resident_key && strcmp(entry->rp_id, rp_id) == 0) {
            zf_store_insert_sorted_index(out_indices, &count, max_out, store, (uint16_t)i);
        }
    }

    return count;
}

size_t zf_store_find_by_rp_and_allow_list(const ZfCredentialStore *store, const char *rp_id,
                                          const uint8_t allow_list[][ZF_CREDENTIAL_ID_LEN],
                                          const size_t *allow_list_lens, size_t allow_list_count,
                                          uint16_t *out_indices, size_t max_out) {
    size_t count = 0;

    if (!store || !store->records) {
        return 0;
    }

    for (size_t i = 0; i < store->count; ++i) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use || strcmp(entry->rp_id, rp_id) != 0) {
            continue;
        }

        for (size_t j = 0; j < allow_list_count; ++j) {
            if (allow_list_lens[j] > ZF_CREDENTIAL_ID_LEN) {
                continue;
            }
            if (entry->credential_id_len == allow_list_lens[j] &&
                memcmp(entry->credential_id, allow_list[j], allow_list_lens[j]) == 0) {
                zf_store_insert_sorted_index(out_indices, &count, max_out, store, (uint16_t)i);
                break;
            }
        }
    }

    return count;
}

bool zf_store_has_excluded_credential(const ZfCredentialStore *store, const char *rp_id,
                                      const uint8_t ids[][ZF_CREDENTIAL_ID_LEN],
                                      const size_t *id_lens, size_t id_count) {
    if (!store || !store->records) {
        return false;
    }

    for (size_t i = 0; i < store->count; ++i) {
        const ZfCredentialIndexEntry *entry = &store->records[i];

        if (!entry->in_use || strcmp(entry->rp_id, rp_id) != 0) {
            continue;
        }

        for (size_t j = 0; j < id_count; ++j) {
            if (id_lens[j] > ZF_CREDENTIAL_ID_LEN) {
                continue;
            }
            if (entry->credential_id_len == id_lens[j] &&
                memcmp(entry->credential_id, ids[j], id_lens[j]) == 0) {
                return true;
            }
        }
    }

    return false;
}
