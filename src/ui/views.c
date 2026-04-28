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

#include "../zerofido_ui.h"

#include <furi/core/string.h>
#include <gui/elements.h>
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

static void zerofido_credentials_menu_callback(void *context, uint32_t index);
static void zerofido_settings_menu_callback(void *context, uint32_t index);
static void zerofido_pin_menu_callback(void *context, uint32_t index);
static uint32_t zerofido_ignore_previous_callback(void *context);
static uint32_t zerofido_credentials_browse_previous_callback(void *context);
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
static bool zerofido_navigation_callback(void *context);
static bool zerofido_begin_local_maintenance(ZerofidoApp *app);
static void zerofido_end_local_maintenance(ZerofidoApp *app);
static bool zerofido_settings_available(ZerofidoApp *app);

enum {
    ZfSettingsItemCredentials = 0,
    ZfSettingsItemTransport = 1,
    ZfSettingsItemFido2Enabled = 2,
    ZfSettingsItemAutoAcceptRequests = 3,
    ZfSettingsItemPin = 4,
    ZfSettingsItemStartupReset = 5,
};

enum {
    ZfPinMenuItemSet = 0,
    ZfPinMenuItemChange = 1,
    ZfPinMenuItemRemove = 2,
    ZfPinMenuItemResume = 3,
};

typedef enum {
    ZfCredentialsMenuModeBrowse = 0,
    ZfCredentialsMenuModeAssertionSelection = 1,
} ZfCredentialsMenuMode;

typedef struct {
    ZfPinConfirmAction action;
    ZfViewId return_view;
    const char *header;
    const char *text;
    const char *confirm_button;
} ZfPinConfirmDialogSpec;

static void zerofido_clear_view_draw_callback(Canvas *canvas, void *context) {
    UNUSED(context);
    canvas_clear(canvas);
}

void zerofido_ui_switch_to_view(ZerofidoApp *app, ZfViewId view_id) {
    ViewDispatcher *dispatcher = NULL;
    bool registered = false;

    if (!app || view_id >= ZfViewCount) {
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

static void zerofido_pin_reset_buffers(ZerofidoApp *app) {
    zf_crypto_secure_zero(app->pin_input_buffer, sizeof(app->pin_input_buffer));
    zf_crypto_secure_zero(app->pin_new_buffer, sizeof(app->pin_new_buffer));
    zf_crypto_secure_zero(app->pin_current_buffer, sizeof(app->pin_current_buffer));
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

static ZfCredentialsMenuMode zerofido_credentials_menu_mode_locked(const ZerofidoApp *app) {
    return (app->approval.state == ZfApprovalPending &&
            app->approval.kind == ZfInteractionKindAssertionSelection)
               ? ZfCredentialsMenuModeAssertionSelection
               : ZfCredentialsMenuModeBrowse;
}

static ZfCredentialsMenuMode zerofido_credentials_menu_mode(ZerofidoApp *app) {
    ZfCredentialsMenuMode mode;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    mode = zerofido_credentials_menu_mode_locked(app);
    furi_mutex_release(app->ui_mutex);
    return mode;
}

static void zerofido_refresh_pin_menu(ZerofidoApp *app) {
    bool pin_is_set = false;
    bool pin_auth_blocked = false;

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
    app->pin_input_state = state;
    zf_crypto_secure_zero(app->pin_input_buffer, sizeof(app->pin_input_buffer));

    text_input_reset(app->pin_input_view);
    text_input_set_header_text(app->pin_input_view, header);
    text_input_set_minimum_length(app->pin_input_view, min_length);
    text_input_set_validator(app->pin_input_view, zerofido_pin_input_validator_callback, app);
    text_input_set_result_callback(app->pin_input_view, zerofido_pin_input_result_callback, app,
                                   app->pin_input_buffer, sizeof(app->pin_input_buffer), false);
    zerofido_ui_switch_to_view(app, ZfViewPinInput);
}

static void zerofido_open_pin_confirm_dialog(ZerofidoApp *app, const ZfPinConfirmDialogSpec *spec) {
    app->pin_confirm_action = spec->action;
    app->pin_confirm_return_view = spec->return_view;
    dialog_ex_reset(app->pin_confirm_view);
    dialog_ex_set_header(app->pin_confirm_view, spec->header, 64, 6, AlignCenter, AlignTop);
    dialog_ex_set_text(app->pin_confirm_view, spec->text, 64, 22, AlignCenter, AlignTop);
    dialog_ex_set_left_button_text(app->pin_confirm_view, "Cancel");
    dialog_ex_set_center_button_text(app->pin_confirm_view, spec->confirm_button);
    dialog_ex_set_result_callback(app->pin_confirm_view, zerofido_pin_confirm_result_callback);
    dialog_ex_set_context(app->pin_confirm_view, app);
    zerofido_ui_switch_to_view(app, ZfViewPinConfirm);
}

static void zerofido_open_pin_confirm(ZerofidoApp *app) {
    static const ZfPinConfirmDialogSpec spec = {
        .action = ZfPinConfirmActionRemove,
        .return_view = ZfViewPinMenu,
        .header = "Remove PIN?",
        .text = "Entering the PIN will\nbe required again later",
        .confirm_button = "Remove",
    };
    zerofido_open_pin_confirm_dialog(app, &spec);
}

static void zerofido_open_pin_resume_confirm(ZerofidoApp *app) {
    static const ZfPinConfirmDialogSpec spec = {
        .action = ZfPinConfirmActionResume,
        .return_view = ZfViewPinMenu,
        .header = "Resume PIN?",
        .text = "Allow PIN retries again\nwithout power cycling",
        .confirm_button = "Resume",
    };
    zerofido_open_pin_confirm_dialog(app, &spec);
}

static void zerofido_open_startup_reset_confirm(ZerofidoApp *app) {
    static const ZfPinConfirmDialogSpec spec = {
        .action = ZfPinConfirmActionResetAppData,
        .return_view = ZfViewStatus,
        .header = "Reset ZeroFIDO?",
        .text = "Clear FIDO2 creds and\nPIN state on device",
        .confirm_button = "Reset",
    };
    zerofido_open_pin_confirm_dialog(app, &spec);
}

static void zerofido_finish_pin_update(ZerofidoApp *app) {
    zerofido_pin_reset_buffers(app);
    zerofido_refresh_pin_menu(app);
    zerofido_ui_set_status(app, NULL);
    zerofido_ui_refresh_status(app);
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
    char transport_label[24];
    char fido2_label[24];
    char auto_accept_label[40];
    ZfRuntimeConfig runtime_config;
    bool startup_reset_available = false;
    uint32_t max_index = ZfSettingsItemPin;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    startup_reset_available = app->startup_reset_available;
    runtime_config = app->runtime_config;
    furi_mutex_release(app->ui_mutex);

    submenu_reset(app->settings_menu);
    submenu_set_header(app->settings_menu, "Settings");
    submenu_add_item(app->settings_menu, "FIDO2 Credentials", ZfSettingsItemCredentials,
                     zerofido_settings_menu_callback, app);
    snprintf(transport_label, sizeof(transport_label), "Transport: %s",
             runtime_config.transport_mode == ZfTransportModeNfc ? "NFC" : "USB HID");
    submenu_add_item(app->settings_menu, transport_label, ZfSettingsItemTransport,
                     zerofido_settings_menu_callback, app);
    snprintf(fido2_label, sizeof(fido2_label), "FIDO2: %s",
             runtime_config.fido2_enabled ? "On" : "Off");
    submenu_add_item(app->settings_menu, fido2_label, ZfSettingsItemFido2Enabled,
                     zerofido_settings_menu_callback, app);
    snprintf(auto_accept_label, sizeof(auto_accept_label), "Auto-accept requests: %s",
             runtime_config.auto_accept_requests ? "On" : "Off");
    submenu_add_item(app->settings_menu, auto_accept_label, ZfSettingsItemAutoAcceptRequests,
                     zerofido_settings_menu_callback, app);
    submenu_add_item(app->settings_menu, "PIN", ZfSettingsItemPin, zerofido_settings_menu_callback,
                     app);
    if (startup_reset_available) {
        submenu_add_item(app->settings_menu, "Reset app data", ZfSettingsItemStartupReset,
                         zerofido_settings_menu_callback, app);
        max_index = ZfSettingsItemStartupReset;
    }
    if (app->settings_selected_index > max_index) {
        app->settings_selected_index = max_index;
    }
    submenu_set_selected_item(app->settings_menu, app->settings_selected_index);
}

static void zerofido_format_credential_fallback_label(const ZfCredentialIndexEntry *entry,
                                                      char *label, size_t label_size) {
    char credential_id[17];

    if (!entry) {
        snprintf(label, label_size, "F2/--");
        return;
    }

    zf_ui_hex_encode_truncated(entry->credential_id, entry->credential_id_len, credential_id,
                               sizeof(credential_id));
    snprintf(label, label_size, "%s | %s", zf_ui_fido2_credential_type_tag(entry->resident_key),
             credential_id);
}

static void zerofido_format_assertion_selection_fallback_label(const ZfCredentialIndexEntry *entry,
                                                               char *label, size_t label_size) {
    char credential_id[17];

    if (!entry) {
        snprintf(label, label_size, "Account");
        return;
    }

    zf_ui_hex_encode_truncated(entry->credential_id, entry->credential_id_len, credential_id,
                               sizeof(credential_id));
    snprintf(label, label_size, "Account | %s", credential_id);
}

static void zerofido_format_menu_label(ZerofidoApp *app, size_t index, char *label,
                                       size_t label_size) {
    if (!app->store.records || index >= app->store.count) {
        zerofido_format_credential_fallback_label(NULL, label, label_size);
        return;
    }

    zerofido_format_credential_fallback_label(&app->store.records[index], label, label_size);
}

static void zerofido_format_assertion_selection_label(ZerofidoApp *app, size_t index, char *label,
                                                      size_t label_size) {
    if (!app->store.records || index >= app->store.count) {
        zerofido_format_assertion_selection_fallback_label(NULL, label, label_size);
        return;
    }

    zerofido_format_assertion_selection_fallback_label(&app->store.records[index], label,
                                                       label_size);
}

static bool zerofido_finish_assertion_selection_locked(ZerofidoApp *app, uint32_t menu_index) {
    uint32_t record_index;

    if (zerofido_credentials_menu_mode_locked(app) != ZfCredentialsMenuModeAssertionSelection ||
        !app->store.records || menu_index >= app->approval.details.selection.credential_count) {
        return false;
    }

    record_index = app->approval.details.selection.credential_indices[menu_index];
    if (record_index >= app->store.count || !app->store.records[record_index].in_use) {
        return false;
    }

    app->approval.details.selection.selected_menu_index = menu_index;
    app->approval.details.selection.selected_record_index = record_index;
    app->approval.state = ZfApprovalApproved;
    app->approval.pending_hide_generation = app->approval.generation;
    furi_semaphore_release(app->approval.done);
    return true;
}

static void zerofido_refresh_credentials_menu(ZerofidoApp *app) {
    char label[120];
    uint32_t selected_index = 0;
    bool have_selected = false;
    size_t saved_count = 0;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    submenu_reset(app->credentials_menu);
    if (zerofido_credentials_menu_mode_locked(app) == ZfCredentialsMenuModeAssertionSelection) {
        view_set_previous_callback(submenu_get_view(app->credentials_menu),
                                   zerofido_ignore_previous_callback);
        submenu_set_header(app->credentials_menu,
                           app->approval.target_id[0] ? app->approval.target_id : "Select account");

        if (app->approval.details.selection.credential_count == 0) {
            submenu_add_item(app->credentials_menu, "No accounts", UINT32_MAX, NULL, app);
            furi_mutex_release(app->ui_mutex);
            return;
        }

        for (size_t i = 0; i < app->approval.details.selection.credential_count; ++i) {
            uint32_t record_index = app->approval.details.selection.credential_indices[i];
            if (record_index >= app->store.count || !app->store.records[record_index].in_use) {
                continue;
            }

            zerofido_format_assertion_selection_label(app, record_index, label, sizeof(label));
            submenu_add_item(app->credentials_menu, label, (uint32_t)i,
                             zerofido_credentials_menu_callback, app);
        }

        if (app->approval.details.selection.selected_menu_index <
            app->approval.details.selection.credential_count) {
            selected_index = app->approval.details.selection.selected_menu_index;
        }
        submenu_set_selected_item(app->credentials_menu, selected_index);
        furi_mutex_release(app->ui_mutex);
        return;
    }

    view_set_previous_callback(submenu_get_view(app->credentials_menu),
                               zerofido_credentials_browse_previous_callback);
    submenu_set_header(app->credentials_menu, "FIDO2 Credentials");

    saved_count = zf_store_count_saved(&app->store);
    if (saved_count == 0) {
        submenu_add_item(app->credentials_menu, "No FIDO2 credentials", UINT32_MAX, NULL, app);
        app->credentials_selected_index = 0;
        furi_mutex_release(app->ui_mutex);
        return;
    }
    if (!app->store.records) {
        submenu_add_item(app->credentials_menu, "Credential store unavailable", UINT32_MAX, NULL,
                         app);
        app->credentials_selected_index = 0;
        furi_mutex_release(app->ui_mutex);
        return;
    }

    for (size_t i = 0; i < app->store.count; ++i) {
        if (!app->store.records[i].in_use) {
            continue;
        }
        zerofido_format_menu_label(app, i, label, sizeof(label));
        submenu_add_item(app->credentials_menu, label, (uint32_t)i,
                         zerofido_credentials_menu_callback, app);
        if ((uint32_t)i == app->credentials_selected_index) {
            selected_index = (uint32_t)i;
            have_selected = true;
        }
    }

    if (!have_selected) {
        for (size_t i = 0; i < app->store.count; ++i) {
            if (app->store.records[i].in_use) {
                selected_index = (uint32_t)i;
                break;
            }
        }
    }

    submenu_set_selected_item(app->credentials_menu, selected_index);
    app->credentials_selected_index = selected_index;
    furi_mutex_release(app->ui_mutex);
}

static void zerofido_fill_credential_detail_text(ZerofidoApp *app,
                                                 const ZfCredentialIndexEntry *entry, char *out,
                                                 size_t out_size) {
    typedef struct {
        ZfCredentialRecord record;
        uint8_t store_io[ZF_STORE_RECORD_IO_SIZE];
    } ZfCredentialDetailScratch;

    _Static_assert(sizeof(ZfCredentialDetailScratch) <= ZF_UI_SCRATCH_SIZE,
                   "credential detail scratch exceeds UI arena");

    ZfCredentialDetailScratch *scratch = NULL;

    if (!entry || !entry->in_use) {
        strncpy(out, "Credential unavailable", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }

    if (!app) {
        strncpy(out, "Credential unavailable", out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    scratch = (ZfCredentialDetailScratch *)app->ui_scratch.bytes;
    memset(scratch, 0, sizeof(*scratch));

    if (!zf_store_load_record_with_buffer(app->storage, entry, &scratch->record, scratch->store_io,
                                          sizeof(scratch->store_io))) {
        strncpy(out, "Credential unavailable", out_size - 1);
        out[out_size - 1] = '\0';
        zf_crypto_secure_zero(scratch, sizeof(*scratch));
        return;
    }

    scratch->record.sign_count = entry->sign_count;
    zf_ui_format_fido2_credential_detail(&scratch->record, out, out_size);
    zf_crypto_secure_zero(scratch, sizeof(*scratch));
}

static void zerofido_refresh_credential_detail(ZerofidoApp *app) {
    char detail_text[256];
    ZfCredentialIndexEntry selected_entry = {0};
    bool allow_delete = false;

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if (!app->store.records || app->store.count == 0 ||
        app->credentials_selected_index >= app->store.count ||
        !app->store.records[app->credentials_selected_index].in_use) {
        furi_mutex_release(app->ui_mutex);
        dialog_ex_reset(app->credential_detail_view);
        dialog_ex_set_header(app->credential_detail_view, "FIDO2 Credential", 64, 6, AlignCenter,
                             AlignTop);
        dialog_ex_set_text(app->credential_detail_view, "No credential selected", 64, 20,
                           AlignCenter, AlignTop);
        dialog_ex_set_left_button_text(app->credential_detail_view, "Back");
        dialog_ex_set_result_callback(app->credential_detail_view,
                                      zerofido_credential_detail_result_callback);
        dialog_ex_set_context(app->credential_detail_view, app);
        return;
    }

    selected_entry = app->store.records[app->credentials_selected_index];
    allow_delete = app->approval.state != ZfApprovalPending;
    furi_mutex_release(app->ui_mutex);

    zerofido_fill_credential_detail_text(app, &selected_entry, detail_text, sizeof(detail_text));
    dialog_ex_reset(app->credential_detail_view);
    dialog_ex_set_header(app->credential_detail_view, "FIDO2 Credential", 64, 6, AlignCenter,
                         AlignTop);
    dialog_ex_set_text(app->credential_detail_view, detail_text, 64, 20, AlignCenter, AlignTop);
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
    bool selection_mode = false;
    furi_assert(app);

    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    selection_mode =
        zerofido_credentials_menu_mode_locked(app) == ZfCredentialsMenuModeAssertionSelection;
    finished = zerofido_finish_assertion_selection_locked(app, index);
    furi_mutex_release(app->ui_mutex);

    if (finished) {
        zf_transport_notify_interaction_changed(app);
        zerofido_ui_dispatch_custom_event(app, ZfEventHideApproval);
        return;
    }
    if (selection_mode) {
        return;
    }

    zerofido_open_credential_detail(app, index);
}

static void zerofido_settings_menu_callback(void *context, uint32_t index) {
    ZerofidoApp *app = context;
    ZfRuntimeConfig runtime_config;
    furi_assert(app);

    if (!zerofido_settings_available(app)) {
        zerofido_ui_set_status(app, "Starting...");
        zerofido_ui_switch_to_view(app, ZfViewStatus);
        return;
    }

    app->settings_selected_index = index;
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    runtime_config = app->runtime_config;
    furi_mutex_release(app->ui_mutex);

    switch (index) {
    case ZfSettingsItemCredentials:
        zerofido_refresh_credentials_menu(app);
        zerofido_ui_switch_to_view(app, ZfViewCredentials);
        break;
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
        zerofido_ui_refresh_status(app);
        break;
    }
    case ZfSettingsItemFido2Enabled: {
        bool enabled = !runtime_config.fido2_enabled;
        if (zf_runtime_config_set_fido2_enabled(app, app->storage, enabled)) {
            zerofido_ui_set_status(app, enabled ? "FIDO2 enabled" : "FIDO2 disabled");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Settings save failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status(app);
        break;
    }
    case ZfSettingsItemAutoAcceptRequests: {
        bool enabled = !runtime_config.auto_accept_requests;
        if (zf_runtime_config_set_auto_accept_requests(app, app->storage, enabled)) {
            zerofido_ui_set_status(app, enabled ? "Auto-accept enabled" : "Auto-accept disabled");
        } else {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Settings save failed");
        }
        zerofido_refresh_settings_menu(app);
        zerofido_ui_refresh_status(app);
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
    furi_assert(app);

    switch (app->pin_input_state) {
    case ZfPinInputSetNew:
    case ZfPinInputChangeNew:
        return zerofido_pin_status_message(zerofido_pin_length_status(text), error);
    case ZfPinInputSetConfirm:
    case ZfPinInputChangeConfirm:
        if (strcmp(text, app->pin_new_buffer) != 0) {
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
    uint8_t status = ZF_CTAP_SUCCESS;
    bool maintenance_acquired = false;

    furi_assert(app);

    switch (app->pin_input_state) {
    case ZfPinInputSetNew:
        strncpy(app->pin_new_buffer, app->pin_input_buffer, sizeof(app->pin_new_buffer) - 1);
        app->pin_new_buffer[sizeof(app->pin_new_buffer) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputSetConfirm, "Confirm new PIN", 4);
        return;
    case ZfPinInputSetConfirm:
        if (!zerofido_begin_local_maintenance(app)) {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            zerofido_ui_switch_to_view(app, ZfViewPinMenu);
            return;
        }
        maintenance_acquired = true;
        status = zerofido_pin_set_plaintext(app->storage, &app->pin_state, app->pin_new_buffer);
        break;
    case ZfPinInputChangeCurrent:
        strncpy(app->pin_current_buffer, app->pin_input_buffer,
                sizeof(app->pin_current_buffer) - 1);
        app->pin_current_buffer[sizeof(app->pin_current_buffer) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputChangeNew, "Enter new PIN", 4);
        return;
    case ZfPinInputChangeNew:
        strncpy(app->pin_new_buffer, app->pin_input_buffer, sizeof(app->pin_new_buffer) - 1);
        app->pin_new_buffer[sizeof(app->pin_new_buffer) - 1] = '\0';
        zerofido_open_pin_input(app, ZfPinInputChangeConfirm, "Confirm new PIN", 4);
        return;
    case ZfPinInputChangeConfirm:
        if (!zerofido_begin_local_maintenance(app)) {
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            zerofido_ui_switch_to_view(app, ZfViewPinMenu);
            return;
        }
        maintenance_acquired = true;
        status =
            zerofido_pin_verify_plaintext(app->storage, &app->pin_state, app->pin_current_buffer);
        if (status == ZF_CTAP_SUCCESS) {
            status =
                zerofido_pin_replace_plaintext(app->storage, &app->pin_state, app->pin_new_buffer);
        }
        break;
    case ZfPinInputRemoveCurrent:
        strncpy(app->pin_current_buffer, app->pin_input_buffer,
                sizeof(app->pin_current_buffer) - 1);
        app->pin_current_buffer[sizeof(app->pin_current_buffer) - 1] = '\0';
        zerofido_open_pin_confirm(app);
        return;
    case ZfPinInputNone:
    default:
        return;
    }

    if (maintenance_acquired) {
        zerofido_end_local_maintenance(app);
    }

    if (status == ZF_CTAP_SUCCESS) {
        zerofido_notify_success(app);
        zerofido_finish_pin_update(app);
    } else {
        zerofido_notify_error(app);
        zerofido_ui_set_status(app, zerofido_pin_status_text(status));
        zerofido_ui_refresh_status(app);
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
                uint8_t status = zerofido_pin_verify_plaintext(app->storage, &app->pin_state,
                                                               app->pin_current_buffer);
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
                    app->startup_reset_available = false;
                } else {
                    failure_status = "Reset failed";
                }
                break;
            case ZfPinConfirmActionNone:
            default:
                break;
            }
            zerofido_end_local_maintenance(app);
        }

        if (action_ok) {
            zerofido_notify_success(app);
            if (action == ZfPinConfirmActionResetAppData) {
                zerofido_ui_set_status(app, "Data cleared. Exit and reopen");
            } else if (action == ZfPinConfirmActionResume) {
                zerofido_pin_reset_buffers(app);
                zerofido_refresh_pin_menu(app);
                zerofido_ui_set_status(app, "PIN attempts resumed");
                zerofido_ui_refresh_status(app);
            } else {
                zerofido_pin_reset_buffers(app);
                zerofido_refresh_pin_menu(app);
                zerofido_ui_set_status(app, NULL);
                zerofido_ui_refresh_status(app);
            }
        } else {
            zerofido_notify_error(app);
            if (failure_status) {
                zerofido_ui_set_status(app, failure_status);
                zerofido_ui_refresh_status(app);
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

static void zerofido_credential_detail_result_callback(DialogExResult result, void *context) {
    ZerofidoApp *app = context;

    furi_assert(app);

    if (result == DialogExResultCenter) {
        ZfStoreDeleteResult delete_result;
        char credential_id[ZF_CREDENTIAL_ID_LEN * 2 + 1];
        uint8_t credential_id_bytes[ZF_CREDENTIAL_ID_LEN];
        size_t credential_id_len = 0;
        bool maintenance_acquired = false;

        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        if (!app->store.records || app->store.count == 0 ||
            app->credentials_selected_index >= app->store.count) {
            furi_mutex_release(app->ui_mutex);
            zerofido_ui_set_status(app, "Delete blocked: no selected credential");
            return;
        }
        if (app->approval.state == ZfApprovalPending) {
            furi_mutex_release(app->ui_mutex);
            zerofido_ui_set_status(app, "Finish the active request before deleting");
            zerofido_refresh_credential_detail(app);
            return;
        }

        const ZfCredentialIndexEntry *record = &app->store.records[app->credentials_selected_index];
        credential_id_len = record->credential_id_len;
        memcpy(credential_id_bytes, record->credential_id, credential_id_len);
        zf_ui_hex_encode_truncated(record->credential_id, credential_id_len, credential_id,
                                   sizeof(credential_id));
        if (app->maintenance_busy) {
            furi_mutex_release(app->ui_mutex);
            zerofido_notify_error(app);
            zerofido_ui_set_status(app, "Busy, try again");
            return;
        }
        app->maintenance_busy = true;
        maintenance_acquired = true;
        furi_mutex_release(app->ui_mutex);

        delete_result = zf_store_delete_record(app->storage, &app->store, credential_id_bytes,
                                               credential_id_len);

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
            zerofido_refresh_credentials_menu(app);
            zerofido_ui_refresh_status(app);
            zerofido_ui_set_status(app, "Credential deleted");
            zerofido_ui_switch_to_view(app, ZfViewCredentials);
            return;
        }

        switch (delete_result) {
        case ZfStoreDeleteNotFound:
            zerofido_ui_set_status(app, "Delete failed: record not found");
            break;
        case ZfStoreDeleteRemoveFailed:
            zerofido_ui_set_status(app, "Delete failed: file remove error");
            break;
        case ZfStoreDeleteOk:
        default:
            zerofido_ui_set_status(app, "Delete failed: unexpected state");
            break;
        }
        furi_mutex_release(app->ui_mutex);
        zerofido_refresh_credential_detail(app);
        zerofido_ui_switch_to_view(app, ZfViewCredentialDetail);
        return;
    }

    if (result == DialogExResultLeft) {
        zerofido_refresh_credentials_menu(app);
        zerofido_ui_switch_to_view(app, ZfViewCredentials);
    }
}

// cppcheck-suppress constParameterCallback
static bool zerofido_status_input_callback(InputEvent *event, void *context) {
    ZerofidoApp *app = context;

    if (event->type != InputTypeShort) {
        return false;
    }

    if (event->key == InputKeyLeft) {
        return zerofido_navigation_callback(app);
    }

    if (event->key == InputKeyRight) {
        if (!zerofido_settings_available(app)) {
            zerofido_ui_set_status(app, "Starting...");
            return true;
        }
        app->settings_selected_index = ZfSettingsItemCredentials;
        zerofido_refresh_settings_menu(app);
        zerofido_ui_switch_to_view(app, ZfViewSettings);
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

static uint32_t zerofido_credentials_browse_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewSettings;
}

static uint32_t zerofido_settings_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewStatus;
}

static uint32_t zerofido_credential_detail_previous_callback(void *context) {
    UNUSED(context);
    return ZfViewCredentials;
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
    UNUSED(context);
    return ZfViewPinMenu;
}

static bool zerofido_custom_event_callback(void *context, uint32_t event) {
    ZerofidoApp *app = context;
    furi_assert(app);

    switch (event) {
    case ZfEventShowApproval:
        zerofido_ui_show_interaction(app);
        if (zerofido_credentials_menu_mode(app) == ZfCredentialsMenuModeAssertionSelection) {
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
        zerofido_ui_refresh_status(app);
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
    if (zerofido_ui_expire_pending_interaction(app)) {
        zerofido_ui_dispatch_custom_event(app, ZfEventApprovalTimeout);
    }
}

bool zerofido_ui_init(ZerofidoApp *app) {
    app->ui_thread_id = furi_thread_get_current_id();
    app->active_view = ZfViewStatus;
    app->view_dispatcher = view_dispatcher_alloc();
    app->status_view = view_alloc();
    app->credentials_menu = submenu_alloc();
    app->settings_menu = submenu_alloc();
    app->pin_menu = submenu_alloc();
    app->pin_input_view = text_input_alloc();
    app->pin_confirm_view = dialog_ex_alloc();
    app->credential_detail_view = dialog_ex_alloc();
    app->approval_view = dialog_ex_alloc();
    app->credential_detail_stack = view_stack_alloc();
    app->credential_detail_background_view = view_alloc();

    if (!app->view_dispatcher || !app->status_view || !app->credential_detail_stack ||
        !app->credential_detail_background_view || !app->credentials_menu || !app->settings_menu ||
        !app->pin_menu || !app->pin_input_view || !app->pin_confirm_view ||
        !app->credential_detail_view || !app->approval_view) {
        zerofido_ui_deinit(app);
        return false;
    }

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher,
                                                  zerofido_navigation_callback);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, zerofido_custom_event_callback);
    view_dispatcher_set_tick_event_callback(app->view_dispatcher, zerofido_tick_callback, 100);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    submenu_set_header(app->credentials_menu, "FIDO2 Credentials");
    view_set_previous_callback(submenu_get_view(app->credentials_menu),
                               zerofido_credentials_browse_previous_callback);
    submenu_set_header(app->settings_menu, "Settings");
    view_set_previous_callback(submenu_get_view(app->settings_menu),
                               zerofido_settings_previous_callback);
    submenu_set_header(app->pin_menu, "PIN");
    view_set_previous_callback(submenu_get_view(app->pin_menu), zerofido_pin_menu_previous_callback);
    view_set_previous_callback(text_input_get_view(app->pin_input_view),
                               zerofido_pin_input_previous_callback);
    dialog_ex_set_result_callback(app->pin_confirm_view, zerofido_pin_confirm_result_callback);
    dialog_ex_set_context(app->pin_confirm_view, app);
    view_set_previous_callback(dialog_ex_get_view(app->pin_confirm_view),
                               zerofido_pin_confirm_previous_callback);
    dialog_ex_set_result_callback(app->credential_detail_view,
                                  zerofido_credential_detail_result_callback);
    dialog_ex_set_context(app->credential_detail_view, app);
    view_set_previous_callback(view_stack_get_view(app->credential_detail_stack),
                               zerofido_credential_detail_previous_callback);

    view_set_input_callback(app->status_view, zerofido_status_input_callback);
    view_set_previous_callback(app->status_view, zerofido_ignore_previous_callback);
    zerofido_ui_status_bind_view(app);
    view_set_draw_callback(app->credential_detail_background_view,
                           zerofido_clear_view_draw_callback);
    view_stack_add_view(app->credential_detail_stack, app->credential_detail_background_view);
    view_stack_add_view(app->credential_detail_stack,
                        dialog_ex_get_view(app->credential_detail_view));

    view_dispatcher_add_view(app->view_dispatcher, ZfViewStatus, app->status_view);
    app->ui_registered_views |= (1U << ZfViewStatus);

    view_dispatcher_add_view(app->view_dispatcher, ZfViewApproval,
                             dialog_ex_get_view(app->approval_view));
    app->ui_registered_views |= (1U << ZfViewApproval);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewSettings,
                             submenu_get_view(app->settings_menu));
    app->ui_registered_views |= (1U << ZfViewSettings);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewCredentials,
                             submenu_get_view(app->credentials_menu));
    app->ui_registered_views |= (1U << ZfViewCredentials);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewPinMenu, submenu_get_view(app->pin_menu));
    app->ui_registered_views |= (1U << ZfViewPinMenu);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewPinInput,
                             text_input_get_view(app->pin_input_view));
    app->ui_registered_views |= (1U << ZfViewPinInput);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewPinConfirm,
                             dialog_ex_get_view(app->pin_confirm_view));
    app->ui_registered_views |= (1U << ZfViewPinConfirm);
    view_dispatcher_add_view(app->view_dispatcher, ZfViewCredentialDetail,
                             view_stack_get_view(app->credential_detail_stack));
    app->ui_registered_views |= (1U << ZfViewCredentialDetail);

    zerofido_refresh_credentials_menu(app);
    zerofido_refresh_settings_menu(app);
    zerofido_refresh_pin_menu(app);
    return true;
}

void zerofido_ui_deinit(ZerofidoApp *app) {
    if (app->view_dispatcher) {
        if (app->ui_registered_views & (1U << ZfViewCredentialDetail)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewCredentialDetail);
            app->ui_registered_views &= ~(1U << ZfViewCredentialDetail);
        }
        if (app->ui_registered_views & (1U << ZfViewPinConfirm)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewPinConfirm);
            app->ui_registered_views &= ~(1U << ZfViewPinConfirm);
        }
        if (app->ui_registered_views & (1U << ZfViewPinInput)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewPinInput);
            app->ui_registered_views &= ~(1U << ZfViewPinInput);
        }
        if (app->ui_registered_views & (1U << ZfViewPinMenu)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewPinMenu);
            app->ui_registered_views &= ~(1U << ZfViewPinMenu);
        }
        if (app->ui_registered_views & (1U << ZfViewSettings)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewSettings);
            app->ui_registered_views &= ~(1U << ZfViewSettings);
        }
        if (app->ui_registered_views & (1U << ZfViewCredentials)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewCredentials);
            app->ui_registered_views &= ~(1U << ZfViewCredentials);
        }
        if (app->ui_registered_views & (1U << ZfViewApproval)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewApproval);
            app->ui_registered_views &= ~(1U << ZfViewApproval);
        }
        if (app->ui_registered_views & (1U << ZfViewStatus)) {
            view_dispatcher_remove_view(app->view_dispatcher, ZfViewStatus);
            app->ui_registered_views &= ~(1U << ZfViewStatus);
        }
    }

    if (app->credential_detail_stack) {
        view_stack_free(app->credential_detail_stack);
        app->credential_detail_stack = NULL;
    }
    if (app->credential_detail_background_view) {
        view_free(app->credential_detail_background_view);
        app->credential_detail_background_view = NULL;
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
