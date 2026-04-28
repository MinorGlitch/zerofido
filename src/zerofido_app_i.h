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

#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/view_dispatcher.h>
#include <gui/view_stack.h>
#include <notification/notification.h>
#include <storage/storage.h>
#include <string.h>

#include "u2f/session.h"
#include "transport/adapter.h"
#include "transport/nfc_worker.h"
#include "transport/usb_hid_session.h"
#include "zerofido_pin.h"
#include "zerofido_runtime_config.h"
#include "zerofido_types.h"
#include "zerofido_ui_format.h"

typedef enum {
    ZfViewStatus = 0,
    ZfViewApproval = 1,
    ZfViewCredentials = 2,
    ZfViewCredentialDetail = 3,
    ZfViewSettings = 4,
    ZfViewPinMenu = 5,
    ZfViewPinInput = 6,
    ZfViewPinConfirm = 7,
    ZfViewCount,
} ZfViewId;

typedef enum {
    ZfEventShowApproval = 1,
    ZfEventHideApproval,
    ZfEventConnected,
    ZfEventDisconnected,
    ZfEventActivity,
    ZfEventApprovalTimeout,
    ZfEventNotificationTimeout,
} ZfCustomEvent;

typedef enum {
    ZfApprovalIdle,
    ZfApprovalPending,
    ZfApprovalApproved,
    ZfApprovalDenied,
    ZfApprovalCanceled,
    ZfApprovalTimedOut,
} ZfApprovalState;

typedef enum {
    ZfInteractionKindApproval = 0,
    ZfInteractionKindAssertionSelection = 1,
} ZfInteractionKind;

typedef enum {
    ZfPinInputNone,
    ZfPinInputSetNew,
    ZfPinInputSetConfirm,
    ZfPinInputChangeCurrent,
    ZfPinInputChangeNew,
    ZfPinInputChangeConfirm,
    ZfPinInputRemoveCurrent,
} ZfPinInputState;

typedef enum {
    ZfPinConfirmActionNone,
    ZfPinConfirmActionRemove,
    ZfPinConfirmActionResume,
    ZfPinConfirmActionResetAppData,
} ZfPinConfirmAction;

typedef struct {
    ZfUiProtocol protocol;
    char operation[24];
    char user_text[ZF_MAX_USER_NAME_LEN + ZF_MAX_DISPLAY_NAME_LEN + 8];
} ZfApprovalPrompt;

typedef struct {
    uint32_t credential_indices[ZF_MAX_CREDENTIALS];
    size_t credential_count;
    uint32_t selected_menu_index;
    uint32_t selected_record_index;
} ZfAssertionSelectionPrompt;

typedef struct {
    ZfApprovalState state;
    ZfInteractionKind kind;
    char target_id[ZF_MAX_RP_ID_LEN];
    uint32_t generation;
    uint32_t pending_hide_generation;
    uint32_t deadline;
    FuriSemaphore *done;
    union {
        ZfApprovalPrompt approval;
        ZfAssertionSelectionPrompt selection;
    } details;
} ZfApprovalRequest;

typedef struct ZerofidoApp {
    Gui *gui;
    ViewDispatcher *view_dispatcher;
    View *status_view;
    Submenu *credentials_menu;
    Submenu *settings_menu;
    Submenu *pin_menu;
    TextInput *pin_input_view;
    DialogEx *pin_confirm_view;
    DialogEx *credential_detail_view;
    DialogEx *approval_view;
    ViewStack *credential_detail_stack;
    View *credential_detail_background_view;
    Storage *storage;
    NotificationApp *notifications;
    FuriTimer *notify_timer;
    FuriThread *startup_thread;
    FuriThread *worker_thread;
    FuriMutex *ui_mutex;
    const ZfTransportAdapterOps *transport_adapter;
    FuriHalUsbInterface *previous_usb;
    void *transport_state;
    union {
        ZfTransportState usb_hid;
        ZfNfcTransportState nfc;
    } transport_state_storage_union;
    U2fData *u2f;
    ZfClientPinState pin_state;
    ZfRuntimeConfig runtime_config;
    ZfResolvedCapabilities capabilities;
    bool capabilities_resolved;
    bool running;
    bool ui_events_enabled;
    bool transport_connected;
    bool maintenance_busy;
    bool transport_auto_accept_transaction;
    bool startup_complete;
    bool startup_ok;
    uint32_t ui_registered_views;
    ZfViewId active_view;
    FuriThreadId ui_thread_id;
    char last_ctap_command_tag[16];
    char last_ctap_step[24];
    char status_text[64];
    uint8_t transport_arena[ZF_TRANSPORT_ARENA_SIZE];
    ZfCommandScratchArena command_scratch;
    ZfUiScratchArena ui_scratch;
    char pin_input_buffer[64];
    char pin_new_buffer[64];
    char pin_current_buffer[64];
    uint32_t credentials_selected_index;
    uint32_t settings_selected_index;
    uint32_t pin_menu_selected_index;
    ZfPinInputState pin_input_state;
    ZfPinConfirmAction pin_confirm_action;
    ZfViewId pin_confirm_return_view;
    bool startup_reset_available;
    ZfApprovalRequest approval;
    ZfCredentialIndexEntry store_records[ZF_MAX_CREDENTIALS];
    ZfCredentialStore store;
    ZfAssertionQueue assertion_queue;
} ZerofidoApp;


static inline void *zf_app_command_scratch_acquire(ZerofidoApp *app, size_t size) {
    if (!app || size > sizeof(app->command_scratch.bytes)) {
        return NULL;
    }

    memset(app->command_scratch.bytes, 0, size);
    return app->command_scratch.bytes;
}

static inline void zf_app_command_scratch_release(ZerofidoApp *app) {
    if (!app) {
        return;
    }

    volatile uint8_t *bytes = app->command_scratch.bytes;
    for (size_t i = 0; i < sizeof(app->command_scratch.bytes); ++i) {
        bytes[i] = 0;
    }
}
#define transport_state_storage transport_state_storage_union.usb_hid
#define transport_nfc_state_storage transport_state_storage_union.nfc
