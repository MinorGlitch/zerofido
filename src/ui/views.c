/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 or later.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "../zerofido_ui.h"

#include <furi/core/string.h>
#include <input/input.h>
#include <stdio.h>
#include <string.h>

#include "../transport/adapter.h"
#include "../zerofido_app_i.h"
#include "../zerofido_ctap.h"
#include "../zerofido_notify.h"
#include "../zerofido_store.h"
#include "../zerofido_ui_i.h"
#include "status.h"
#include "../app/lifecycle.h"

#if !defined(ZF_USB_ONLY) && !defined(ZF_NFC_ONLY)
#define ZF_HAS_TRANSPORT_SETTING 1
#else
#define ZF_HAS_TRANSPORT_SETTING 0
#endif

#define ZF_IDLE_TELEMETRY_INTERVAL_MS 30000U

static void zerofido_credentials_menu_callback(void *context, uint32_t index);
static void zerofido_settings_menu_callback(void *context, uint32_t index);
static void zerofido_pin_menu_callback(void *context, uint32_t index);
static uint32_t zerofido_ignore_previous_callback(void *context);
static uint32_t zerofido_credentials_previous_callback(void *context);
static uint32_t zerofido_settings_previous_callback(void *context);
static uint32_t zerofido_credential_detail_previous_callback(void *context);
static uint32_t zerofido_pin_menu_previous_callback(void *context);
static uint32_t zerofido_pin_input_previous_callback(void *context);
static uint32_t zerofido_pin_confirm_previous_callback(void *context);
static void zerofido_credential_detail_result_callback(DialogExResult result, void *context);
static void zerofido_pin_confirm_result_callback(DialogExResult result, void *context);
static void zerofido_pin_input_result_callback(void *context);
static bool zerofido_pin_input_validator_callback(const char *text, FuriString *error,
                                                  void *context);
static bool zerofido_delete_selected_credential(ZerofidoApp *app, const char **failure_status);
static bool zerofido_navigation_callback(void *context);
static bool zerofido_begin_local_maintenance(ZerofidoApp *app);
static void zerofido_end_local_maintenance(ZerofidoApp *app);
static bool zerofido_settings_available(ZerofidoApp *app);
static void zerofido_configure_credential_detail_dialog(ZerofidoApp *app, const char *text,
                                                        bool allow_delete);
static void zerofido_ui_prune_rare_views(ZerofidoApp *app);

enum {
    ZfSettingsItemTransport = 0,
    ZfSettingsItemAutoAcceptRequests = 1,
    ZfSettingsItemFido2Profile = 2,
    ZfSettingsItemAttestation = 3,
    ZfSettingsItemPin = 4,
    ZfSettingsItemStartupReset = 5,
};

enum {
    ZfPinMenuItemSet = 0,
    ZfPinMenuItemChange = 1,
    ZfPinMenuItemRemove = 2,
    ZfPinMenuItemResume = 3,
};

typedef struct {
    ZfCredentialRecord record;
    uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
} ZfCredentialDisplayScratch;

_Static_assert(sizeof(ZfCredentialDisplayScratch) <= ZF_UI_SCRATCH_SIZE,
               "credential display scratch exceeds UI arena");

static void *zerofido_ui_scratch_alloc(ZerofidoApp *app, size_t size) {
    return zf_app_ui_scratch_acquire(app, size);
}

static void zerofido_ui_scratch_free(ZerofidoApp *app, void *scratch, size_t size) {
    UNUSED(size);
    if (!scratch) {
        return;
    }

    zf_app_ui_scratch_release(app);
}

void zerofido_ui_switch_to_view(ZerofidoApp *app, ZfViewId view_id) {
    ViewDispatcher *dispatcher = NULL;
    bool registered = false;

    if (!app || view_id >= ZfViewCount) {
        return;
    }
    if (!zerofido_ui_ensure_view(app, view_id)) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    registered = (app->ui_registered_views & (1U << view_id)) != 0;
    if (registered) {
        app->active_view = view_id;
        dispatcher = app->view_dispatcher;
    }
    furi_mutex_release(app->ui_mutex);

    if (dispatcher) {
        view_dispatcher_switch_to_view(dispatcher, view_id);
    }
}

static bool zerofido_pin_status_message(uint8_t status, FuriString *error) {
    switch (status) {
    case ZF_CTAP_SUCCESS:
        return true;
    case ZF_CTAP_ERR_PIN_POLICY_VIOLATION:
        furi_string_set(error, "PIN must be\n4-63 chars");
        break;
    case ZF_CTAP_ERR_PIN_INVALID:
        furi_string_set(error, "Current PIN\nis incorrect");
        break;
    case ZF_CTAP_ERR_PIN_AUTH_BLOCKED:
        furi_string_set(error, "PIN attempts are\nblocked");
        break;
    case ZF_CTAP_ERR_PIN_NOT_SET:
        furi_string_set(error, "PIN is not set");
        break;
    default:
        furi_string_set(error, "PIN update failed");
        break;
    }
    return false;
}

static const char *zerofido_pin_status_text(uint8_t status) {
    switch (status) {
    case ZF_CTAP_ERR_PIN_POLICY_VIOLATION:
        return "PIN must be 4-63 chars";
    case ZF_CTAP_ERR_PIN_INVALID:
        return "Current PIN is incorrect";
    case ZF_CTAP_ERR_PIN_AUTH_BLOCKED:
        return "PIN attempts are blocked";
    case ZF_CTAP_ERR_PIN_NOT_SET:
        return "PIN is not set";
    default:
        return "PIN update failed";
    }
}

static uint8_t zerofido_pin_length_status(const char *text) {
    size_t pin_len = strlen(text);
    if (pin_len < 4 || pin_len > 63) {
        return ZF_CTAP_ERR_PIN_POLICY_VIOLATION;
    }
    return ZF_CTAP_SUCCESS;
}

static ZfPinBuffers *zerofido_pin_buffers_acquire(ZerofidoApp *app) {
    if (!app) {
        return NULL;
    }
    if (app->pin_buffers) {
        return app->pin_buffers;
    }

    app->pin_buffers = malloc(sizeof(*app->pin_buffers));
    if (!app->pin_buffers) {
        zf_telemetry_log_oom("pin buffers", sizeof(ZfPinBuffers));
        return NULL;
    }

    memset(app->pin_buffers, 0, sizeof(*app->pin_buffers));
    return app->pin_buffers;
}

static void zerofido_pin_reset_buffers(ZerofidoApp *app) {
    if (!app) {
        return;
    }
    if (app->pin_buffers) {
        zf_crypto_secure_zero(app->pin_buffers, sizeof(*app->pin_buffers));
        free(app->pin_buffers);
        app->pin_buffers = NULL;
    }
    app->pin_input_state = ZfPinInputNone;
    app->pin_confirm_action = ZfPinConfirmActionNone;
}

static bool zerofido_interaction_pending(ZerofidoApp *app) {
    bool pending = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    pending = app->approval.state == ZfApprovalPending;
    furi_mutex_release(app->ui_mutex);
    return pending;
}

static bool zerofido_assertion_selection_pending_locked(const ZerofidoApp *app) {
    return app->approval.state == ZfApprovalPending &&
           app->approval.kind == ZfInteractionKindAssertionSelection;
}

static bool zerofido_assertion_selection_pending(ZerofidoApp *app) {
    bool pending;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    pending = zerofido_assertion_selection_pending_locked(app);
    furi_mutex_release(app->ui_mutex);
    return pending;
}

static void zerofido_refresh_pin_menu(ZerofidoApp *app) {
    bool pin_is_set = false;
    bool pin_auth_blocked = false;

    if (!zerofido_ui_ensure_view(app, ZfViewPinMenu)) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    pin_is_set = zerofido_pin_is_set(&app->pin_state);
    pin_auth_blocked = zerofido_pin_is_auth_blocked(&app->pin_state);
    furi_mutex_release(app->ui_mutex);

    submenu_reset(app->pin_menu);
    submenu_set_header(app->pin_menu, "PIN");

    if (!pin_is_set) {
        submenu_add_item(app->pin_menu, "Set PIN", ZfPinMenuItemSet, zerofido_pin_menu_callback,
                         app);
        app->pin_menu_selected_index = ZfPinMenuItemSet;
        submenu_set_selected_item(app->pin_menu, app->pin_menu_selected_index);
        return;
    }

    if (pin_auth_blocked) {
        submenu_add_item(app->pin_menu, "Resume PIN attempts", ZfPinMenuItemResume,
                         zerofido_pin_menu_callback, app);
        app->pin_menu_selected_index = ZfPinMenuItemResume;
        submenu_set_selected_item(app->pin_menu, app->pin_menu_selected_index);
        return;
    }

    submenu_add_item(app->pin_menu, "Change PIN", ZfPinMenuItemChange, zerofido_pin_menu_callback,
                     app);
    submenu_add_item(app->pin_menu, "Remove PIN", ZfPinMenuItemRemove, zerofido_pin_menu_callback,
                     app);

    if (app->pin_menu_selected_index > ZfPinMenuItemRemove) {
        app->pin_menu_selected_index = ZfPinMenuItemChange;
    }
    submenu_set_selected_item(app->pin_menu, app->pin_menu_selected_index);
}

static void zerofido_open_pin_input(ZerofidoApp *app, ZfPinInputState state, const char *header,
                                    size_t min_length) {
    ZfPinBuffers *pin_buffers = zerofido_pin_buffers_acquire(app);

    if (!pin_buffers) {
        zerofido_notify_error(app);
        zerofido_ui_set_status(app, "PIN input unavailable");
        zerofido_ui_refresh_status_line(app);
        return;
    }
    if (!zerofido_ui_ensure_view(app, ZfViewPinInput)) {
        zerofido_pin_reset_buffers(app);
        return;
    }

    app->pin_input_state = state;
    zf_crypto_secure_zero(pin_buffers->input, sizeof(pin_buffers->input));

    text_input_reset(app->pin_input_view);
    text_input_set_header_text(app->pin_input_view, header);
    text_input_set_minimum_length(app->pin_input_view, min_length);
    text_input_set_validator(app->pin_input_view, zerofido_pin_input_validator_callback, app);
    text_input_set_result_callback(app->pin_input_view, zerofido_pin_input_result_callback, app,
                                   pin_buffers->input, sizeof(pin_buffers->input), false);
    zerofido_ui_switch_to_view(app, ZfViewPinInput);
}

static void zerofido_open_pin_confirm_dialog(ZerofidoApp *app, ZfPinConfirmAction action,
                                             ZfViewId return_view, const char *header,
                                             const char *text, const char *confirm_button) {
    if (!zerofido_ui_ensure_view(app, ZfViewPinConfirm)) {
        return;
    }

    app->pin_confirm_action = action;
    app->pin_confirm_return_view = return_view;
    dialog_ex_reset(app->pin_confirm_view);
    dialog_ex_set_header(app->pin_confirm_view, header, 64, 6, AlignCenter, AlignTop);
    dialog_ex_set_text(app->pin_confirm_view, text, 64, 22, AlignCenter, AlignTop);
    dialog_ex_set_left_button_text(app->pin_confirm_view, "Cancel");
    dialog_ex_set_center_button_text(app->pin_confirm_view, confirm_button);
    dialog_ex_set_result_callback(app->pin_confirm_view, zerofido_pin_confirm_result_callback);
    dialog_ex_set_context(app->pin_confirm_view, app);
    zerofido_ui_switch_to_view(app, ZfViewPinConfirm);
}

static void zerofido_open_pin_confirm(ZerofidoApp *app) {
    zerofido_open_pin_confirm_dialog(app, ZfPinConfirmActionRemove, ZfViewPinMenu, "Remove PIN?",
                                     "Entering the PIN will\nbe required again later", "Remove");
}

static void zerofido_open_pin_resume_confirm(ZerofidoApp *app) {
    zerofido_open_pin_confirm_dialog(app, ZfPinConfirmActionResume, ZfViewPinMenu, "Resume PIN?",
                                     "Allow PIN retries again\nwithout power cycling", "Resume");
}

static void zerofido_open_startup_reset_confirm(ZerofidoApp *app) {
    zerofido_open_pin_confirm_dialog(app, ZfPinConfirmActionResetAppData, ZfViewStatus,
                                     "Reset ZeroFIDO?", "Clear saved passkeys\nand PIN data",
                                     "Reset");
}

static void zerofido_finish_pin_update(ZerofidoApp *app) {
    zf_runtime_config_refresh_capabilities(app);
    zerofido_pin_reset_buffers(app);
    zerofido_refresh_pin_menu(app);
    zerofido_ui_set_status(app, NULL);
    zerofido_ui_refresh_status_line(app);
}

static bool zerofido_begin_local_maintenance(ZerofidoApp *app) {
    bool acquired = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->maintenance_busy) {
        app->maintenance_busy = true;
        acquired = true;
    }
    furi_mutex_release(app->ui_mutex);
    return acquired;
}

static void zerofido_end_local_maintenance(ZerofidoApp *app) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->maintenance_busy = false;
    furi_mutex_release(app->ui_mutex);
}

static void zerofido_refresh_settings_menu(ZerofidoApp *app) {
    char auto_accept_label[40];
    char fido2_profile_label[32];
    char attestation_label[28];
    ZfRuntimeConfig runtime_config;
    bool startup_reset_available = false;
    uint32_t min_index =
        ZF_HAS_TRANSPORT_SETTING ? ZfSettingsItemTransport : ZfSettingsItemAutoAcceptRequests;
    uint32_t max_index = ZfSettingsItemPin;

    if (!zerofido_ui_ensure_view(app, ZfViewSettings)) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    startup_reset_available = app->startup_reset_available;
    runtime_config = app->runtime_config;
    furi_mutex_release(app->ui_mutex);

    submenu_reset(app->settings_menu);
    submenu_set_header(app->settings_menu, "Settings");
#if ZF_HAS_TRANSPORT_SETTING
    char transport_label[24];
    snprintf(transport_label, sizeof(transport_label), "Transport: %s",
             runtime_config.transport_mode == ZfTransportModeNfc ? "NFC" : "USB HID");
    submenu_add_item(app->settings_menu, transport_label, ZfSettingsItemTransport,
                     zerofido_settings_menu_callback, app);
#endif
    snprintf(auto_accept_label, sizeof(auto_accept_label), "Auto-approve: %s",
             runtime_config.auto_accept_requests ? "On" : "Off");
    submenu_add_item(app->settings_menu, auto_accept_label, ZfSettingsItemAutoAcceptRequests,
                     zerofido_settings_menu_callback, app);
    snprintf(fido2_profile_label, sizeof(fido2_profile_label), "FIDO2: %s",
             zf_fido2_profile_name(runtime_config.fido2_profile));
    submenu_add_item(app->settings_menu, fido2_profile_label, ZfSettingsItemFido2Profile,
                     zerofido_settings_menu_callback, app);
    snprintf(attestation_label, sizeof(attestation_label), "Attest: %s",
             zf_attestation_mode_name(runtime_config.attestation_mode));
    submenu_add_item(app->settings_menu, attestation_label, ZfSettingsItemAttestation,
                     zerofido_settings_menu_callback, app);
    submenu_add_item(app->settings_menu, "PIN", ZfSettingsItemPin, zerofido_settings_menu_callback,
                     app);
    if (startup_reset_available) {
        submenu_add_item(app->settings_menu, "Reset app data", ZfSettingsItemStartupReset,
                         zerofido_settings_menu_callback, app);
        max_index = ZfSettingsItemStartupReset;
    }
    if (app->settings_selected_index < min_index || app->settings_selected_index > max_index) {
        app->settings_selected_index = min_index;
    }
    submenu_set_selected_item(app->settings_menu, app->settings_selected_index);
}

static void zerofido_format_assertion_selection_label(ZerofidoApp *app,
                                                      const ZfCredentialIndexEntry *entry,
                                                      char *label, size_t label_size) {
    ZfCredentialDisplayScratch *scratch = NULL;

    if (!entry || !entry->in_use) {
        snprintf(label, label_size, "Account");
        return;
    }

    zf_ui_format_assertion_selection_index_label(entry, label, label_size);
    if (!app) {
        return;
    }

    scratch = zerofido_ui_scratch_alloc(app, sizeof(*scratch));
    if (!scratch) {
        return;
    }
    if (zf_store_load_record_for_display_with_buffer(
            app->storage, entry, &scratch->record, scratch->store_io, sizeof(scratch->store_io))) {
        zf_ui_format_assertion_selection_record_label(&scratch->record, label, label_size);
    }
    zerofido_ui_scratch_free(app, scratch, sizeof(*scratch));
}

static bool zerofido_finish_assertion_selection_locked(ZerofidoApp *app, uint32_t menu_index) {
    uint16_t record_index;

    if (!zerofido_assertion_selection_pending_locked(app) || !app->store.records ||
        menu_index > UINT16_MAX || menu_index >= app->approval.details.selection.credential_count) {
        return false;
    }

    record_index = app->approval.details.selection.credential_indices[menu_index];
    if (record_index >= app->store.count || !app->store.records[record_index].in_use) {
        return false;
    }

    app->approval.details.selection.selected_menu_index = (uint16_t)menu_index;
    app->approval.details.selection.selected_record_index = record_index;
    app->approval.state = ZfApprovalApproved;
    app->approval.pending_hide_generation = app->approval.generation;
    furi_semaphore_release(app->approval.done);
    return true;
}

static bool zerofido_select_next_position(uint32_t *values, size_t count, bool found_selected,
                                          size_t selected_pos, int8_t direction,
                                          uint32_t *selected_value) {
    if (!values || !selected_value || count == 0U) {
        return false;
    }

    if (!found_selected) {
        selected_pos = 0;
    } else if (direction < 0) {
        selected_pos = selected_pos == 0U ? count - 1U : selected_pos - 1U;
    } else {
        selected_pos = selected_pos + 1U >= count ? 0U : selected_pos + 1U;
    }
    *selected_value = values[selected_pos];
    return true;
}

static bool zerofido_select_next_stored_credential_locked(ZerofidoApp *app, int8_t direction) {
    uint32_t values[ZF_MAX_CREDENTIALS];
    size_t count = 0;
    size_t selected_pos = 0;
    bool found_selected = false;
    uint32_t selected_value = 0;

    if (app->store.records) {
        for (size_t i = 0; i < app->store.count && count < COUNT_OF(values); ++i) {
            if (!app->store.records[i].in_use) {
                continue;
            }

            values[count] = (uint32_t)i;
            if ((uint32_t)i == app->credentials_selected_index) {
                selected_pos = count;
                found_selected = true;
            }
            ++count;
        }
    }

    if (!zerofido_select_next_position(values, count, found_selected, selected_pos, direction,
                                       &selected_value)) {
        return false;
    }
    app->credentials_selected_index = selected_value;
    return true;
}

static void zerofido_refresh_credentials_menu(ZerofidoApp *app) {
    char label[120];
    bool selected_found = false;
    size_t item_count = 0;
    size_t credential_count = 0;
    uint16_t first_menu_index = UINT16_MAX;
    uint32_t selected_menu_index = UINT32_MAX;

    if (!zerofido_ui_ensure_view(app, ZfViewCredentials)) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    submenu_reset(app->credentials_menu);
    submenu_set_header(app->credentials_menu,
                       app->approval.target_id[0] ? app->approval.target_id : "Select account");

    if (app->store.records) {
        credential_count = app->approval.details.selection.credential_count;
        for (size_t i = 0; i < app->approval.details.selection.credential_count; ++i) {
            uint32_t record_index = app->approval.details.selection.credential_indices[i];
            if (record_index >= app->store.count || !app->store.records[record_index].in_use) {
                continue;
            }

            if (first_menu_index == UINT16_MAX) {
                first_menu_index = (uint16_t)i;
            }
            if (app->approval.details.selection.selected_menu_index == i) {
                selected_found = true;
            }
            ++item_count;
        }

        if (item_count > 0U && !selected_found) {
            app->approval.details.selection.selected_menu_index = first_menu_index;
        }
    }

    if (app->store.records && item_count > 0U) {
        selected_menu_index = app->approval.details.selection.selected_menu_index;
        furi_mutex_release(app->ui_mutex);
        for (size_t i = 0; i < credential_count; ++i) {
            uint32_t record_index = UINT32_MAX;
            ZfCredentialIndexEntry entry = {0};
            bool entry_valid = false;

            furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
            record_index = app->approval.details.selection.credential_indices[i];
            if (app->store.records && record_index < app->store.count &&
                app->store.records[record_index].in_use) {
                entry = app->store.records[record_index];
                entry_valid = true;
            }
            furi_mutex_release(app->ui_mutex);
            if (!entry_valid) {
                continue;
            }

            zerofido_format_assertion_selection_label(app, &entry, label, sizeof(label));
            submenu_add_item(app->credentials_menu, label, (uint32_t)i,
                             zerofido_credentials_menu_callback, app);
        }
    } else {
        submenu_add_item(app->credentials_menu, "No accounts", UINT32_MAX, NULL, app);
        furi_mutex_release(app->ui_mutex);
    }
    submenu_set_selected_item(app->credentials_menu, selected_menu_index);
}

static void zerofido_fill_credential_detail_text(ZerofidoApp *app,
                                                 const ZfCredentialIndexEntry *entry, char *out,
                                                 size_t out_size) {
    ZfCredentialDisplayScratch *scratch = NULL;

    if (!entry || !entry->in_use) {
        goto unavailable;
    }

    if (!app) {
        goto unavailable;
    }
    scratch = zerofido_ui_scratch_alloc(app, sizeof(*scratch));
    if (!scratch) {
        goto unavailable;
    }

    if (!zf_store_load_record_for_display_with_buffer(
            app->storage, entry, &scratch->record, scratch->store_io, sizeof(scratch->store_io))) {
        zerofido_ui_scratch_free(app, scratch, sizeof(*scratch));
        goto unavailable;
    }

    scratch->record.sign_count = entry->sign_count;
    zf_ui_format_fido2_credential_detail(&scratch->record, out, out_size);
    zerofido_ui_scratch_free(app, scratch, sizeof(*scratch));
    return;

unavailable:
    strncpy(out, "Passkey unavailable", out_size - 1);
    out[out_size - 1] = '\0';
}

static void zerofido_refresh_credential_detail(ZerofidoApp *app) {
    char detail_text[256];
    ZfCredentialIndexEntry selected_entry = {0};
    bool allow_delete = false;

    if (!zerofido_ui_ensure_view(app, ZfViewCredentialDetail)) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->store.records || app->store.count == 0 ||
        app->credentials_selected_index >= app->store.count ||
        !app->store.records[app->credentials_selected_index].in_use) {
        furi_mutex_release(app->ui_mutex);
        zerofido_configure_credential_detail_dialog(app, "No passkey selected", false);
        return;
    }

    selected_entry = app->store.records[app->credentials_selected_index];
    allow_delete = app->approval.state != ZfApprovalPending;
    furi_mutex_release(app->ui_mutex);

    zerofido_fill_credential_detail_text(app, &selected_entry, detail_text, sizeof(detail_text));
    zerofido_configure_credential_detail_dialog(app, detail_text, allow_delete);
}

static void zerofido_configure_credential_detail_dialog(ZerofidoApp *app, const char *text,
                                                        bool allow_delete) {
    dialog_ex_reset(app->credential_detail_view);
    dialog_ex_set_header(app->credential_detail_view, "Passkey", 64, 6, AlignCenter, AlignTop);
    dialog_ex_set_text(app->credential_detail_view, text, 64, 20, AlignCenter, AlignTop);
    dialog_ex_set_left_button_text(app->credential_detail_view, "Back");
    if (allow_delete) {
        dialog_ex_set_center_button_text(app->credential_detail_view, "Delete");
    }
    dialog_ex_set_result_callback(app->credential_detail_view,
                                  zerofido_credential_detail_result_callback);
    dialog_ex_set_context(app->credential_detail_view, app);
}

static void zerofido_open_credential_detail(ZerofidoApp *app, uint32_t index) {
    bool can_open = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->store.records || index >= app->store.count || !app->store.records[index].in_use) {
        furi_mutex_release(app->ui_mutex);
        return;
    }

    app->credentials_selected_index = index;
    can_open = true;
    furi_mutex_release(app->ui_mutex);
    if (!can_open) {
        return;
    }
    zerofido_refresh_credential_detail(app);
    zerofido_ui_switch_to_view(app, ZfViewCredentialDetail);
}

static void zerofido_credentials_menu_callback(void *context, uint32_t index) {
    ZerofidoApp *app = context;
    bool finished = false;

    if (!app) {
        return;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    finished = zerofido_finish_assertion_selection_locked(app, index);
    furi_mutex_release(app->ui_mutex);
    if (finished) {
        zf_transport_notify_interaction_changed(app);
        zerofido_ui_dispatch_custom_event(app, ZfEventHideApproval);
    }
}

static void zerofido_settings_menu_callback(void *context, uint32_t index) {
    ZerofidoApp *app = context;
    ZfRuntimeConfig runtime_config;
    furi_assert(app);

    if (!zerofido_settings_available(app)) {
        zerofido_ui_refresh_status_line(app);
        zerofido_ui_switch_to_view(app, ZfViewStatus);
        return;
    }

    app->settings_selected_index = index;
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    runtime_config = app->runtime_config;
    furi_mutex_release(app->ui_mutex);

    switch (index) {
#if ZF_HAS_TRANSPORT_SETTING
    case ZfSettingsItemTransport: {
        ZfTransportMode mode = runtime_config.transport_mode == ZfTransportModeUsbHid
                                   ? ZfTransportModeNfc
                                   : ZfTransportModeUsbHid;
        if (zf_runtime_config_set_transport_mode(app, app->storage, mode) &&
            zf_app_lifecycle_restart_transport(app)) {
            zerofido_ui_set_status(app, mode == ZfTransportModeNfc ? "Transport: NFC"
                                                                   : "Transport: USB HID");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Transport switch failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status_line(app);
        break;
    }
#endif
    case ZfSettingsItemAutoAcceptRequests: {
        bool enabled = !runtime_config.auto_accept_requests;
        if (zf_runtime_config_set_auto_accept_requests(app, app->storage, enabled)) {
            zerofido_ui_set_status(app, enabled ? "Auto-accept enabled" : "Auto-accept disabled");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Settings save failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status_line(app);
        break;
    }
    case ZfSettingsItemFido2Profile: {
        ZfFido2Profile profile = runtime_config.fido2_profile == ZfFido2ProfileCtap2_1Experimental
                                     ? ZfFido2ProfileCtap2_0
                                     : ZfFido2ProfileCtap2_1Experimental;
        if (zf_runtime_config_set_fido2_profile(app, app->storage, profile)) {
            zerofido_ui_set_status(app, profile == ZfFido2ProfileCtap2_1Experimental
                                            ? "FIDO2 profile: 2.1 exp"
                                            : "FIDO2 profile: 2.0");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, profile == ZfFido2ProfileCtap2_1Experimental &&
                                                !zerofido_pin_is_set(&app->pin_state)
                                            ? "Set PIN before FIDO2 2.1"
                                            : "Settings save failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status_line(app);
        break;
    }
    case ZfSettingsItemAttestation: {
        ZfAttestationMode mode = runtime_config.attestation_mode == ZfAttestationModePacked
                                     ? ZfAttestationModeNone
                                     : ZfAttestationModePacked;
        if (zf_runtime_config_set_attestation_mode(app, app->storage, mode)) {
            zerofido_ui_set_status(app, mode == ZfAttestationModePacked ? "Attest: packed"
                                                                        : "Attest: none");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Settings save failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status_line(app);
        break;
    }
    case ZfSettingsItemPin:
        zerofido_refresh_pin_menu(app);
        zerofido_ui_switch_to_view(app, ZfViewPinMenu);
        break;
    case ZfSettingsItemStartupReset:
        zerofido_open_startup_reset_confirm(app);
        break;
    default:
        break;
    }
}

static bool zerofido_pin_input_validator_callback(const char *text, FuriString *error,
                                                  void *context) {
    ZerofidoApp *app = context;
    ZfPinBuffers *pin_buffers = app ? app->pin_buffers : NULL;
    furi_assert(app);

    switch (app->pin_input_state) {
    case ZfPinInputSetNew:
    case ZfPinInputChangeNew:
        return zerofido_pin_status_message(zerofido_pin_length_status(text), error);
    case ZfPinInputSetConfirm:
    case ZfPinInputChangeConfirm:
        if (!pin_buffers) {
            furi_string_set(error, "PIN input unavailable");
            return false;
        }
        if (strcmp(text, pin_buffers->new_pin) != 0) {
            furi_string_set(error, "PINs do not match");
            return false;
        }
        return true;
    case ZfPinInputChangeCurrent:
    case ZfPinInputRemoveCurrent:
        return zerofido_pin_status_message(zerofido_pin_length_status(text), error);
    case ZfPinInputNone:
    default:
        return true;
    }
}

static void zerofido_pin_input_result_callback(void *context) {
    ZerofidoApp *app = context;
    ZfPinBuffers *pin_buffers = app ? app->pin_buffers : NULL;
    uint8_t status = ZF_CTAP_SUCCESS;

    furi_assert(app);
    if (!pin_buffers) {
        zerofido_notify_error(app);
        zerofido_ui_set_status(app, "PIN input unavailable");
        zerofido_ui_switch_to_view(app, ZfViewPinMenu);
        return;
    }

    switch (app->pin_input_state) {
    case ZfPinInputSetNew:
        strncpy(pin_buffers->new_pin, pin_buffers->input, sizeof(pin_buffers->new_pin) - 1);
        pin_buffers->new_pin[sizeof(pin_buffers->new_pin) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputSetConfirm, "Confirm new PIN", 4);
        return;
    case ZfPinInputSetConfirm:
        if (!zerofido_begin_local_maintenance(app)) {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            zerofido_ui_switch_to_view(app, ZfViewPinMenu);
            return;
        }
        status = zerofido_pin_set_plaintext(app->storage, &app->pin_state, pin_buffers->new_pin);
        break;
    case ZfPinInputChangeCurrent:
        strncpy(pin_buffers->current, pin_buffers->input, sizeof(pin_buffers->current) - 1);
        pin_buffers->current[sizeof(pin_buffers->current) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputChangeNew, "Enter new PIN", 4);
        return;
    case ZfPinInputChangeNew:
        strncpy(pin_buffers->new_pin, pin_buffers->input, sizeof(pin_buffers->new_pin) - 1);
        pin_buffers->new_pin[sizeof(pin_buffers->new_pin) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputChangeConfirm, "Confirm new PIN", 4);
        return;
    case ZfPinInputChangeConfirm:
        if (!zerofido_begin_local_maintenance(app)) {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            zerofido_ui_switch_to_view(app, ZfViewPinMenu);
            return;
        }
        status = zerofido_pin_verify_plaintext(app->storage, &app->pin_state, pin_buffers->current);
        if (status == ZF_CTAP_SUCCESS) {
            status =
                zerofido_pin_replace_plaintext(app->storage, &app->pin_state, pin_buffers->new_pin);
        }
        break;
    case ZfPinInputRemoveCurrent:
        strncpy(pin_buffers->current, pin_buffers->input, sizeof(pin_buffers->current) - 1);
        pin_buffers->current[sizeof(pin_buffers->current) - 1] = '\0';
        zerofido_open_pin_confirm(app);
        return;
    case ZfPinInputNone:
    default:
        return;
    }

    zerofido_end_local_maintenance(app);

    if (status == ZF_CTAP_SUCCESS) {
        zerofido_notify_success(app);
        zerofido_finish_pin_update(app);
    } else {
        zerofido_notify_error(app);
        zerofido_ui_set_status(app, zerofido_pin_status_text(status));
        zerofido_ui_refresh_status_line(app);
    }

    zerofido_ui_switch_to_view(app, ZfViewPinMenu);
}

static void zerofido_pin_confirm_result_callback(DialogExResult result, void *context) {
    ZerofidoApp *app = context;
    ZfViewId return_view = app->pin_confirm_return_view;
    furi_assert(app);

    if (result == DialogExResultCenter) {
        bool action_ok = false;
        ZfPinConfirmAction action = app->pin_confirm_action;
        const char *failure_status = NULL;
        if (!zerofido_begin_local_maintenance(app)) {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            zerofido_ui_switch_to_view(app, return_view);
            return;
        } else {
            switch (action) {
            case ZfPinConfirmActionRemove: {
                ZfPinBuffers *pin_buffers = app->pin_buffers;
                if (!pin_buffers) {
                    failure_status = "PIN input unavailable";
                    break;
                }
                uint8_t status = zerofido_pin_verify_plaintext(app->storage, &app->pin_state,
                                                               pin_buffers->current);
                if (status == ZF_CTAP_SUCCESS) {
                    action_ok = zerofido_pin_clear(app->storage, &app->pin_state);
                    if (!action_ok) {
                        failure_status = "PIN removal failed";
                    }
                } else {
                    failure_status = zerofido_pin_status_text(status);
                }
                break;
            }
            case ZfPinConfirmActionResume:
                action_ok = zerofido_pin_resume_auth_attempts(app->storage, &app->pin_state);
                if (!action_ok) {
                    failure_status = "PIN resume failed";
                }
                break;
            case ZfPinConfirmActionResetAppData:
                action_ok = zf_store_wipe_app_data(app->storage);
                if (action_ok) {
                    zf_store_clear(&app->store);
                    zf_crypto_secure_zero(&app->pin_state, sizeof(app->pin_state));
                    memset(&app->assertion_queue, 0, sizeof(app->assertion_queue));
                    zf_runtime_config_refresh_capabilities(app);
                    app->startup_reset_available = false;
                } else {
                    failure_status = "Reset failed";
                }
                break;
            case ZfPinConfirmActionDeleteCredential:
                zerofido_end_local_maintenance(app);
                action_ok = zerofido_delete_selected_credential(app, &failure_status);
                if (!action_ok && failure_status == NULL) {
                    failure_status = "Could not delete passkey";
                }
                break;
            case ZfPinConfirmActionNone:
            default:
                break;
            }
            if (action != ZfPinConfirmActionDeleteCredential) {
                zerofido_end_local_maintenance(app);
            }
        }

        if (action_ok) {
            if (action == ZfPinConfirmActionRemove) {
                zf_runtime_config_refresh_capabilities(app);
            }
            zerofido_notify_success(app);
            if (action == ZfPinConfirmActionResetAppData) {
                zerofido_ui_set_status(app, "Data cleared. Exit and reopen");
                zerofido_ui_refresh_credentials_status(app);
            } else if (action == ZfPinConfirmActionDeleteCredential) {
                zerofido_refresh_credentials_menu(app);
                zerofido_ui_refresh_credentials_status(app);
                zerofido_ui_set_status(app, "Passkey deleted");
                return_view = ZfViewStatus;
            } else if (action == ZfPinConfirmActionResume) {
                zerofido_pin_reset_buffers(app);
                zerofido_refresh_pin_menu(app);
                zerofido_ui_set_status(app, "PIN attempts resumed");
                zerofido_ui_refresh_status_line(app);
            } else {
                zerofido_pin_reset_buffers(app);
                zerofido_refresh_pin_menu(app);
                zerofido_ui_set_status(app, NULL);
                zerofido_ui_refresh_status_line(app);
            }
        } else {
            zerofido_notify_error(app);
            if (failure_status) {
                zerofido_ui_set_status(app, failure_status);
                zerofido_ui_refresh_status_line(app);
            }
        }
    }

    zerofido_ui_switch_to_view(app, return_view);
}

static void zerofido_pin_menu_callback(void *context, uint32_t index) {
    ZerofidoApp *app = context;
    furi_assert(app);

    app->pin_menu_selected_index = index;
    if (zerofido_interaction_pending(app)) {
        return;
    }

    switch (index) {
    case ZfPinMenuItemSet:
        zerofido_pin_reset_buffers(app);
        zerofido_open_pin_input(app, ZfPinInputSetNew, "Enter new PIN", 4);
        break;
    case ZfPinMenuItemChange:
        zerofido_pin_reset_buffers(app);
        zerofido_open_pin_input(app, ZfPinInputChangeCurrent, "Enter current PIN", 4);
        break;
    case ZfPinMenuItemRemove:
        zerofido_pin_reset_buffers(app);
        zerofido_open_pin_input(app, ZfPinInputRemoveCurrent, "Enter current PIN", 4);
        break;
    case ZfPinMenuItemResume:
        zerofido_pin_reset_buffers(app);
        zerofido_open_pin_resume_confirm(app);
        break;
    default:
        break;
    }
}

static bool zerofido_delete_selected_credential(ZerofidoApp *app, const char **failure_status) {
    ZfStoreDeleteResult delete_result;
    uint8_t credential_id_bytes[ZF_CREDENTIAL_ID_LEN];
    size_t credential_id_len = 0;
    bool maintenance_acquired = false;

    if (failure_status) {
        *failure_status = NULL;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->store.records || app->store.count == 0 ||
        app->credentials_selected_index >= app->store.count) {
        furi_mutex_release(app->ui_mutex);
        if (failure_status) {
            *failure_status = "No passkey selected";
        }
        return false;
    }
    if (app->approval.state == ZfApprovalPending) {
        furi_mutex_release(app->ui_mutex);
        if (failure_status) {
            *failure_status = "Finish the active request first";
        }
        return false;
    }

    const ZfCredentialIndexEntry *record = &app->store.records[app->credentials_selected_index];
    credential_id_len = record->credential_id_len;
    memcpy(credential_id_bytes, record->credential_id, credential_id_len);
    if (app->maintenance_busy) {
        furi_mutex_release(app->ui_mutex);
        if (failure_status) {
            *failure_status = "Busy, try again";
        }
        return false;
    }
    app->maintenance_busy = true;
    maintenance_acquired = true;
    furi_mutex_release(app->ui_mutex);

    delete_result =
        zf_store_delete_record(app->storage, &app->store, credential_id_bytes, credential_id_len);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (maintenance_acquired) {
        app->maintenance_busy = false;
    }
    if (delete_result == ZfStoreDeleteOk) {
        memset(&app->assertion_queue, 0, sizeof(app->assertion_queue));
        if (app->credentials_selected_index >= app->store.count && app->store.count > 0) {
            app->credentials_selected_index = (uint32_t)(app->store.count - 1);
        }
        furi_mutex_release(app->ui_mutex);
        return true;
    }
    furi_mutex_release(app->ui_mutex);

    if (!failure_status) {
        return false;
    }

    switch (delete_result) {
    case ZfStoreDeleteNotFound:
        *failure_status = "Passkey not found";
        break;
    case ZfStoreDeleteRemoveFailed:
        *failure_status = "Could not delete passkey";
        break;
    case ZfStoreDeleteOk:
    default:
        *failure_status = "Delete failed";
        break;
    }
    return false;
}

static void zerofido_open_delete_credential_confirm(ZerofidoApp *app) {
    zerofido_open_pin_confirm_dialog(app, ZfPinConfirmActionDeleteCredential,
                                     ZfViewCredentialDetail, "Delete passkey?",
                                     "This cannot be undone", "Delete");
}

static void zerofido_credential_detail_result_callback(DialogExResult result, void *context) {
    ZerofidoApp *app = context;

    furi_assert(app);

    if (result == DialogExResultCenter) {
        if (zerofido_interaction_pending(app)) {
            zerofido_ui_set_status(app, "Finish the active request first");
            zerofido_refresh_credential_detail(app);
            return;
        }
        zerofido_open_delete_credential_confirm(app);
        return;
    }

    if (result == DialogExResultLeft) {
        zerofido_ui_refresh_status_line(app);
        zerofido_ui_switch_to_view(app, ZfViewStatus);
    }
}

static bool zerofido_home_select_relative(ZerofidoApp *app, int8_t direction) {
    bool selected = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    selected = zerofido_select_next_stored_credential_locked(app, direction);
    furi_mutex_release(app->ui_mutex);
    return selected;
}

static bool zerofido_home_selected_credential(ZerofidoApp *app, uint32_t *selected_index) {
    uint32_t first_index = UINT32_MAX;
    bool selected_valid = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->store.records) {
        for (size_t i = 0; i < app->store.count; ++i) {
            if (!app->store.records[i].in_use) {
                continue;
            }
            if (first_index == UINT32_MAX) {
                first_index = (uint32_t)i;
            }
            if ((uint32_t)i == app->credentials_selected_index) {
                selected_valid = true;
                break;
            }
        }
    }

    if (!selected_valid && first_index != UINT32_MAX) {
        app->credentials_selected_index = first_index;
        selected_valid = true;
    }
    if (selected_valid && selected_index) {
        *selected_index = app->credentials_selected_index;
    }
    furi_mutex_release(app->ui_mutex);
    return selected_valid;
}

// cppcheck-suppress constParameterCallback
static bool zerofido_status_input_callback(InputEvent *event, void *context) {
    ZerofidoApp *app = context;
    uint32_t selected_index = 0;

    if (event->type == InputTypeShort || event->type == InputTypeRepeat) {
        if (event->key == InputKeyUp || event->key == InputKeyDown) {
            if (zerofido_home_select_relative(app, event->key == InputKeyUp ? -1 : 1)) {
                zerofido_ui_refresh_credentials_status(app);
            }
            return true;
        }
    }

    if (event->type != InputTypeShort) {
        return false;
    }

    if (event->key == InputKeyLeft) {
        return zerofido_navigation_callback(app);
    }

    if (event->key == InputKeyRight) {
        if (!zerofido_settings_available(app)) {
            zerofido_ui_refresh_status_line(app);
            return true;
        }
        app->settings_selected_index =
            ZF_HAS_TRANSPORT_SETTING ? ZfSettingsItemTransport : ZfSettingsItemAutoAcceptRequests;
        zerofido_refresh_settings_menu(app);
        zerofido_ui_switch_to_view(app, ZfViewSettings);
        return true;
    }

    if (event->key == InputKeyOk) {
        if (zerofido_home_selected_credential(app, &selected_index)) {
            zerofido_open_credential_detail(app, selected_index);
        }
        return true;
    }

    return false;
}

static bool zerofido_settings_available(ZerofidoApp *app) {
    return !zf_app_lifecycle_startup_pending(app);
}

static uint32_t zerofido_ignore_previous_callback(void *context) {
    UNUSED(context);
    return VIEW_IGNORE;
}

static uint32_t zerofido_credentials_previous_callback(void *context) {
    UNUSED(context);
    return VIEW_IGNORE;
}

static uint32_t zerofido_settings_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewStatus;
}

static uint32_t zerofido_credential_detail_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewStatus;
}

static uint32_t zerofido_pin_menu_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewSettings;
}

static uint32_t zerofido_pin_input_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewPinMenu;
}

static uint32_t zerofido_pin_confirm_previous_callback(void *context) {
    ZerofidoApp *app = context;
    return app ? app->pin_confirm_return_view : ZfViewPinMenu;
}

#if ZF_RELEASE_DIAGNOSTICS
static void zerofido_ui_log_idle_telemetry(ZerofidoApp *app) {
    uint32_t now = furi_get_tick();
    bool idle = false;
    bool should_log = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    idle = app->active_view == ZfViewStatus && app->startup_complete &&
           app->approval.state != ZfApprovalPending && !app->maintenance_busy;
    if (!idle) {
        app->telemetry_next_idle_tick = 0U;
    } else if (app->telemetry_next_idle_tick == 0U) {
        app->telemetry_next_idle_tick = now + ZF_IDLE_TELEMETRY_INTERVAL_MS;
    } else if ((int32_t)(now - app->telemetry_next_idle_tick) >= 0) {
        app->telemetry_next_idle_tick = now + ZF_IDLE_TELEMETRY_INTERVAL_MS;
        should_log = true;
    }
    furi_mutex_release(app->ui_mutex);

    if (should_log) {
        zf_telemetry_log("idle heartbeat");
    }
}
#endif

static bool zerofido_custom_event_callback(void *context, uint32_t event) {
    ZerofidoApp *app = context;
    furi_assert(app);

    switch (event) {
    case ZfEventShowApproval:
        zerofido_ui_show_interaction(app);
        if (zerofido_assertion_selection_pending(app)) {
            zerofido_refresh_credentials_menu(app);
            zerofido_ui_switch_to_view(app, ZfViewCredentials);
        } else {
            zerofido_ui_switch_to_view(app, ZfViewApproval);
        }
        return true;
    case ZfEventHideApproval:
    case ZfEventApprovalTimeout:
        zerofido_ui_hide_interaction(app);
        return true;
    case ZfEventNotificationTimeout:
        zerofido_notify_reset(app);
        return true;
    case ZfEventConnected:
        zerofido_ui_apply_transport_connected(app, true);
        return true;
    case ZfEventDisconnected:
        zerofido_ui_apply_transport_connected(app, false);
        return true;
    case ZfEventActivity:
    default:
        zerofido_ui_refresh_status_line(app);
        return true;
    }
}

static bool zerofido_navigation_callback(void *context) {
    ZerofidoApp *app = context;
    ViewDispatcher *dispatcher = NULL;
    furi_assert(app);

    if (zerofido_ui_deny_pending_interaction(app)) {
        zerofido_ui_dispatch_custom_event(app, ZfEventHideApproval);
        return true;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->running = false;
    app->ui_events_enabled = false;
    dispatcher = app->view_dispatcher;
    furi_mutex_release(app->ui_mutex);
    zf_transport_stop(app);
    if (dispatcher) {
        view_dispatcher_stop(dispatcher);
    }
    return true;
}

static void zerofido_tick_callback(void *context) {
    ZerofidoApp *app = context;

    furi_assert(app);
    zf_app_lifecycle_startup_pending(app);
    if (zerofido_ui_expire_pending_interaction(app)) {
        zerofido_ui_dispatch_custom_event(app, ZfEventApprovalTimeout);
    }
    zerofido_ui_prune_rare_views(app);
#if ZF_RELEASE_DIAGNOSTICS
    zerofido_ui_log_idle_telemetry(app);
#endif
}

static bool zerofido_ui_register_view(ZerofidoApp *app, ZfViewId view_id, View *view) {
    if (!app || !app->view_dispatcher || !view || view_id >= ZfViewCount) {
        return false;
    }
    if ((app->ui_registered_views & (1U << view_id)) == 0U) {
        view_dispatcher_add_view(app->view_dispatcher, view_id, view);
        app->ui_registered_views |= (1U << view_id);
    }
    return true;
}

static void zerofido_ui_unregister_view(ZerofidoApp *app, ZfViewId view_id) {
    if (!app || !app->view_dispatcher || view_id >= ZfViewCount ||
        (app->ui_registered_views & (1U << view_id)) == 0U) {
        return;
    }

    view_dispatcher_remove_view(app->view_dispatcher, view_id);
    app->ui_registered_views &= ~(1U << view_id);
}

static bool zerofido_ui_can_prune_rare_views(ZerofidoApp *app) {
    bool can_prune = false;

    if (!app) {
        return false;
    }

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    can_prune = app->active_view == ZfViewStatus && app->approval.state != ZfApprovalPending;
    furi_mutex_release(app->ui_mutex);
    return can_prune;
}

static void zerofido_ui_free_rare_view(ZerofidoApp *app, ZfViewId view_id) {
    if (!app || view_id == ZfViewStatus || view_id >= ZfViewCount) {
        return;
    }

    zerofido_ui_unregister_view(app, view_id);
    switch (view_id) {
    case ZfViewApproval:
        if (app->approval_view) {
            dialog_ex_free(app->approval_view);
            app->approval_view = NULL;
        }
        break;
    case ZfViewCredentialDetail:
        if (app->credential_detail_view) {
            dialog_ex_free(app->credential_detail_view);
            app->credential_detail_view = NULL;
        }
        break;
    case ZfViewSettings:
        if (app->settings_menu) {
            submenu_free(app->settings_menu);
            app->settings_menu = NULL;
        }
        break;
    case ZfViewPinMenu:
        if (app->pin_menu) {
            submenu_free(app->pin_menu);
            app->pin_menu = NULL;
        }
        break;
    case ZfViewPinInput:
        if (app->pin_input_view) {
            text_input_free(app->pin_input_view);
            app->pin_input_view = NULL;
        }
        break;
    case ZfViewPinConfirm:
        if (app->pin_confirm_view) {
            dialog_ex_free(app->pin_confirm_view);
            app->pin_confirm_view = NULL;
        }
        break;
    case ZfViewCredentials:
        if (app->credentials_menu) {
            submenu_free(app->credentials_menu);
            app->credentials_menu = NULL;
        }
        break;
    case ZfViewStatus:
    case ZfViewCount:
    default:
        break;
    }
}

static void zerofido_ui_prune_rare_views(ZerofidoApp *app) {
    if (!zerofido_ui_can_prune_rare_views(app)) {
        return;
    }
    if (!app->approval_view && !app->credential_detail_view && !app->credentials_menu &&
        !app->pin_confirm_view && !app->pin_input_view && !app->pin_menu && !app->settings_menu &&
        !app->pin_buffers) {
        return;
    }

    zf_telemetry_log("ui prune before");
    zerofido_ui_free_rare_view(app, ZfViewApproval);
    zerofido_ui_free_rare_view(app, ZfViewCredentialDetail);
    zerofido_ui_free_rare_view(app, ZfViewCredentials);
    if (app->pin_confirm_view || app->pin_input_view || app->pin_menu) {
        zerofido_pin_reset_buffers(app);
    }
    zerofido_ui_free_rare_view(app, ZfViewPinConfirm);
    zerofido_ui_free_rare_view(app, ZfViewPinInput);
    zerofido_ui_free_rare_view(app, ZfViewPinMenu);
    zerofido_ui_free_rare_view(app, ZfViewSettings);
    zf_telemetry_log("ui prune after");
}

/*
 * Views are lazily allocated. Rare workflow views may be removed from the
 * dispatcher and freed after returning home, then recreated on next use.
 */
bool zerofido_ui_ensure_view(ZerofidoApp *app, ZfViewId view_id) {
    if (!app || view_id >= ZfViewCount || !app->view_dispatcher) {
        return false;
    }
    if ((app->ui_registered_views & (1U << view_id)) != 0U) {
        return true;
    }

    switch (view_id) {
    case ZfViewStatus:
        if (!app->status_view) {
            app->status_view = view_alloc();
            if (!app->status_view) {
                return false;
            }
            view_set_input_callback(app->status_view, zerofido_status_input_callback);
            view_set_previous_callback(app->status_view, zerofido_ignore_previous_callback);
            zerofido_ui_status_bind_view(app);
        }
        return zerofido_ui_register_view(app, ZfViewStatus, app->status_view);

    case ZfViewApproval:
        if (!app->approval_view) {
            app->approval_view = dialog_ex_alloc();
            if (!app->approval_view) {
                return false;
            }
        }
        return zerofido_ui_register_view(app, ZfViewApproval,
                                         dialog_ex_get_view(app->approval_view));

    case ZfViewCredentials:
        if (!app->credentials_menu) {
            app->credentials_menu = submenu_alloc();
            if (!app->credentials_menu) {
                return false;
            }
            view_set_previous_callback(submenu_get_view(app->credentials_menu),
                                       zerofido_credentials_previous_callback);
        }
        return zerofido_ui_register_view(app, ZfViewCredentials,
                                         submenu_get_view(app->credentials_menu));

    case ZfViewCredentialDetail:
        if (!app->credential_detail_view) {
            app->credential_detail_view = dialog_ex_alloc();
        }
        if (!app->credential_detail_view) {
            return false;
        }
        dialog_ex_set_result_callback(app->credential_detail_view,
                                      zerofido_credential_detail_result_callback);
        dialog_ex_set_context(app->credential_detail_view, app);
        view_set_previous_callback(dialog_ex_get_view(app->credential_detail_view),
                                   zerofido_credential_detail_previous_callback);
        return zerofido_ui_register_view(app, ZfViewCredentialDetail,
                                         dialog_ex_get_view(app->credential_detail_view));

    case ZfViewSettings:
        if (!app->settings_menu) {
            app->settings_menu = submenu_alloc();
            if (!app->settings_menu) {
                return false;
            }
            submenu_set_header(app->settings_menu, "Settings");
            view_set_previous_callback(submenu_get_view(app->settings_menu),
                                       zerofido_settings_previous_callback);
        }
        return zerofido_ui_register_view(app, ZfViewSettings, submenu_get_view(app->settings_menu));

    case ZfViewPinMenu:
        if (!app->pin_menu) {
            app->pin_menu = submenu_alloc();
            if (!app->pin_menu) {
                return false;
            }
            submenu_set_header(app->pin_menu, "PIN");
            view_set_previous_callback(submenu_get_view(app->pin_menu),
                                       zerofido_pin_menu_previous_callback);
        }
        return zerofido_ui_register_view(app, ZfViewPinMenu, submenu_get_view(app->pin_menu));

    case ZfViewPinInput:
        if (!app->pin_input_view) {
            app->pin_input_view = text_input_alloc();
            if (!app->pin_input_view) {
                return false;
            }
            view_set_previous_callback(text_input_get_view(app->pin_input_view),
                                       zerofido_pin_input_previous_callback);
        }
        return zerofido_ui_register_view(app, ZfViewPinInput,
                                         text_input_get_view(app->pin_input_view));

    case ZfViewPinConfirm:
        if (!app->pin_confirm_view) {
            app->pin_confirm_view = dialog_ex_alloc();
            if (!app->pin_confirm_view) {
                return false;
            }
            dialog_ex_set_result_callback(app->pin_confirm_view,
                                          zerofido_pin_confirm_result_callback);
            dialog_ex_set_context(app->pin_confirm_view, app);
            view_set_previous_callback(dialog_ex_get_view(app->pin_confirm_view),
                                       zerofido_pin_confirm_previous_callback);
        }
        return zerofido_ui_register_view(app, ZfViewPinConfirm,
                                         dialog_ex_get_view(app->pin_confirm_view));

    case ZfViewCount:
    default:
        return false;
    }
}

bool zerofido_ui_init(ZerofidoApp *app) {
    app->ui_thread_id = furi_thread_get_current_id();
    app->active_view = ZfViewStatus;
    app->view_dispatcher = view_dispatcher_alloc();

    if (!app->view_dispatcher) {
        zerofido_ui_deinit(app);
        return false;
    }

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher,
                                                  zerofido_navigation_callback);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, zerofido_custom_event_callback);
    view_dispatcher_set_tick_event_callback(app->view_dispatcher, zerofido_tick_callback, 100);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    if (!zerofido_ui_ensure_view(app, ZfViewStatus)) {
        zerofido_ui_deinit(app);
        return false;
    }

    return true;
}

void zerofido_ui_deinit(ZerofidoApp *app) {
    zf_app_ui_scratch_release(app);
    zerofido_pin_reset_buffers(app);

    if (app->view_dispatcher) {
        for (uint8_t view_id = 0; view_id < ZfViewCount; ++view_id) {
            if ((app->ui_registered_views & (1U << view_id)) != 0U) {
                view_dispatcher_remove_view(app->view_dispatcher, view_id);
            }
        }
        app->ui_registered_views = 0;
    }

    if (app->approval_view) {
        dialog_ex_free(app->approval_view);
        app->approval_view = NULL;
    }
    if (app->pin_confirm_view) {
        dialog_ex_free(app->pin_confirm_view);
        app->pin_confirm_view = NULL;
    }
    if (app->pin_input_view) {
        text_input_free(app->pin_input_view);
        app->pin_input_view = NULL;
    }
    if (app->credential_detail_view) {
        dialog_ex_free(app->credential_detail_view);
        app->credential_detail_view = NULL;
    }
    if (app->pin_menu) {
        submenu_free(app->pin_menu);
        app->pin_menu = NULL;
    }
    if (app->settings_menu) {
        submenu_free(app->settings_menu);
        app->settings_menu = NULL;
    }
    if (app->credentials_menu) {
        submenu_free(app->credentials_menu);
        app->credentials_menu = NULL;
    }
    if (app->status_view) {
        view_free(app->status_view);
        app->status_view = NULL;
    }
    if (app->view_dispatcher) {
        view_dispatcher_free(app->view_dispatcher);
        app->view_dispatcher = NULL;
    }
}

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, ZfCustomEvent event) {
    ViewDispatcher *dispatcher = NULL;
    bool dispatch_inline = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (app->ui_events_enabled) {
        dispatcher = app->view_dispatcher;
        dispatch_inline =
            app->ui_thread_id != NULL && app->ui_thread_id == furi_thread_get_current_id();
    }
    furi_mutex_release(app->ui_mutex);

    if (!dispatcher) {
        return;
    }

    if (dispatch_inline) {
        zerofido_custom_event_callback(app, event);
    } else {
        view_dispatcher_send_custom_event(dispatcher, event);
    }
}
