#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <storage/storage.h>

#include "zerofido_types.h"

typedef enum {
    ZfStoreDeleteOk = 0,
    ZfStoreDeleteNotFound,
    ZfStoreDeleteRemoveFailed,
} ZfStoreDeleteResult;

bool zf_store_init(Storage *storage, ZfCredentialStore *store);
void zf_store_deinit(ZfCredentialStore *store);
void zf_store_clear(ZfCredentialStore *store);
void zf_store_index_entry_from_record(const ZfCredentialRecord *record,
                                      ZfCredentialIndexEntry *entry);
bool zf_store_wipe_app_data(Storage *storage);
bool zf_store_prepare_credential(ZfCredentialRecord *record, const char *rp_id,
                                 const uint8_t *user_id, size_t user_id_len, const char *user_name,
                                 const char *user_display_name, bool resident_key);
bool zf_store_add_record(Storage *storage, ZfCredentialStore *store,
                         const ZfCredentialRecord *record);
bool zf_store_update_record(Storage *storage, ZfCredentialStore *store,
                            const ZfCredentialRecord *record);
bool zf_store_load_record(Storage *storage, const ZfCredentialIndexEntry *entry,
                          ZfCredentialRecord *out_record);
bool zf_store_load_record_by_index(Storage *storage, const ZfCredentialStore *store, size_t index,
                                   ZfCredentialRecord *out_record);
bool zf_store_delete_resident_credentials_for_user(Storage *storage, ZfCredentialStore *store,
                                                   const char *rp_id, const uint8_t *user_id,
                                                   size_t user_id_len, size_t *deleted_count);
ZfStoreDeleteResult zf_store_delete_record(Storage *storage, ZfCredentialStore *store,
                                           const uint8_t *credential_id, size_t credential_id_len);
bool zf_store_find_index_by_id(const ZfCredentialStore *store, const uint8_t *credential_id,
                               size_t credential_id_len, size_t *out_index);
size_t zf_store_count_saved(const ZfCredentialStore *store);
size_t zf_store_count_resident(const ZfCredentialStore *store);
size_t zf_store_find_by_rp(const ZfCredentialStore *store, const char *rp_id,
                           uint16_t *out_indices, size_t max_out);
size_t zf_store_find_by_rp_and_allow_list(const ZfCredentialStore *store, const char *rp_id,
                                          const uint8_t allow_list[][ZF_CREDENTIAL_ID_LEN],
                                          const size_t *allow_list_lens, size_t allow_list_count,
                                          uint16_t *out_indices, size_t max_out);
bool zf_store_has_excluded_credential(const ZfCredentialStore *store, const char *rp_id,
                                      const uint8_t ids[][ZF_CREDENTIAL_ID_LEN],
                                      const size_t *id_lens, size_t id_count);
