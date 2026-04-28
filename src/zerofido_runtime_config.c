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

#include "zerofido_runtime_config.h"

#include <string.h>

#include "zerofido_app_i.h"
#include "zerofido_types.h"

#define ZF_RUNTIME_CONFIG_FILE_PATH ZF_APP_DATA_DIR "/runtime_config.bin"
#define ZF_RUNTIME_CONFIG_FILE_TEMP_PATH ZF_APP_DATA_DIR "/runtime_config.tmp"
#define ZF_RUNTIME_CONFIG_FILE_MAGIC 0x5A465243UL
#define ZF_RUNTIME_CONFIG_FILE_VERSION 2U
#define ZF_RUNTIME_CONFIG_FLAG_AUTO_ACCEPT_REQUESTS 0x01U
#define ZF_RUNTIME_CONFIG_FLAG_FIDO2_ENABLED 0x02U

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t flags;
    uint8_t transport_mode;
    uint8_t reserved;
} ZfRuntimeConfigFileRecord;

static bool zf_transport_mode_is_valid(uint8_t mode) {
#ifdef ZF_NFC_ONLY
    return mode == ZfTransportModeNfc;
#else
    return mode == ZfTransportModeUsbHid || mode == ZfTransportModeNfc;
#endif
}

static ZfTransportMode zf_runtime_config_default_transport_mode(void) {
#ifdef ZF_NFC_ONLY
    return ZfTransportModeNfc;
#else
    return ZfTransportModeUsbHid;
#endif
}

static bool zf_runtime_config_ensure_app_data_dir(Storage *storage) {
    if (!storage) {
        return false;
    }

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

void zf_runtime_config_load_defaults(ZfRuntimeConfig *config) {
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->transport_mode = zf_runtime_config_default_transport_mode();
    config->fido2_enabled = true;
    config->fido2_profile = ZfFido2ProfileCurrent;
    config->u2f_enabled = true;
    config->u2f_profile = ZfU2fProfileCurrent;
    config->auto_accept_requests = false;
}

void zf_runtime_config_load(Storage *storage, ZfRuntimeConfig *config) {
    ZfRuntimeConfigFileRecord record = {0};
    File *file = NULL;
    size_t size = 0;

    zf_runtime_config_load_defaults(config);
    if (!storage || !config) {
        return;
    }

    file = storage_file_alloc(storage);
    if (!file) {
        return;
    }

    if (!storage_file_open(file, ZF_RUNTIME_CONFIG_FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return;
    }

    size = storage_file_size(file);
    if (size != sizeof(record) ||
        storage_file_read(file, &record, sizeof(record)) != sizeof(record)) {
        storage_file_close(file);
        storage_file_free(file);
        return;
    }

    storage_file_close(file);
    storage_file_free(file);

    if (record.magic != ZF_RUNTIME_CONFIG_FILE_MAGIC || record.reserved != 0) {
        return;
    }

    if ((record.flags & ~(ZF_RUNTIME_CONFIG_FLAG_AUTO_ACCEPT_REQUESTS |
                          ZF_RUNTIME_CONFIG_FLAG_FIDO2_ENABLED)) != 0) {
        return;
    }

    if (record.version == 1U) {
        config->transport_mode = zf_runtime_config_default_transport_mode();
    } else if (record.version == ZF_RUNTIME_CONFIG_FILE_VERSION) {
        if (!zf_transport_mode_is_valid(record.transport_mode)) {
            return;
        }
        config->transport_mode = (ZfTransportMode)record.transport_mode;
    } else {
        return;
    }

    config->auto_accept_requests =
        (record.flags & ZF_RUNTIME_CONFIG_FLAG_AUTO_ACCEPT_REQUESTS) != 0;
    config->fido2_enabled = (record.flags & ZF_RUNTIME_CONFIG_FLAG_FIDO2_ENABLED) != 0;
}

bool zf_runtime_config_persist(Storage *storage, const ZfRuntimeConfig *config) {
    ZfRuntimeConfigFileRecord record = {
        .magic = ZF_RUNTIME_CONFIG_FILE_MAGIC,
        .version = ZF_RUNTIME_CONFIG_FILE_VERSION,
        .flags = config
                     ? ((config->auto_accept_requests ? ZF_RUNTIME_CONFIG_FLAG_AUTO_ACCEPT_REQUESTS
                                                      : 0U) |
                        (config->fido2_enabled ? ZF_RUNTIME_CONFIG_FLAG_FIDO2_ENABLED : 0U))
                     : 0U,
        .transport_mode = config ? (uint8_t)config->transport_mode
                                 : (uint8_t)zf_runtime_config_default_transport_mode(),
        .reserved = 0,
    };
    File *file = NULL;
    bool ok = false;

    if (!storage || !config || !zf_runtime_config_ensure_app_data_dir(storage)) {
        return false;
    }

    storage_common_remove(storage, ZF_RUNTIME_CONFIG_FILE_TEMP_PATH);
    file = storage_file_alloc(storage);
    if (!file) {
        return false;
    }

    if (!storage_file_open(file, ZF_RUNTIME_CONFIG_FILE_TEMP_PATH, FSAM_WRITE,
                           FSOM_CREATE_ALWAYS)) {
        storage_file_free(file);
        return false;
    }

    ok = storage_file_write(file, &record, sizeof(record)) == sizeof(record);
    storage_file_close(file);
    storage_file_free(file);
    if (!ok) {
        storage_common_remove(storage, ZF_RUNTIME_CONFIG_FILE_TEMP_PATH);
        return false;
    }

    ok = storage_common_rename(storage, ZF_RUNTIME_CONFIG_FILE_TEMP_PATH,
                               ZF_RUNTIME_CONFIG_FILE_PATH) == FSE_OK;
    storage_common_remove(storage, ZF_RUNTIME_CONFIG_FILE_TEMP_PATH);
    return ok;
}

void zf_runtime_config_apply(ZerofidoApp *app, const ZfRuntimeConfig *config) {
    if (!app || !config) {
        return;
    }

    app->runtime_config = *config;
    zf_runtime_config_resolve_capabilities(&app->runtime_config, &app->capabilities);
    app->capabilities_resolved = true;
}

bool zf_runtime_config_set_auto_accept_requests(ZerofidoApp *app, Storage *storage, bool enabled) {
    ZfRuntimeConfig next_config;

    if (!app) {
        return false;
    }

    next_config = app->runtime_config;
    next_config.auto_accept_requests = enabled;
    if (!zf_runtime_config_persist(storage, &next_config)) {
        return false;
    }

    zf_runtime_config_apply(app, &next_config);
    return true;
}

bool zf_runtime_config_set_fido2_enabled(ZerofidoApp *app, Storage *storage, bool enabled) {
    ZfRuntimeConfig next_config;

    if (!app) {
        return false;
    }

    next_config = app->runtime_config;
    next_config.fido2_enabled = enabled;
    if (!zf_runtime_config_persist(storage, &next_config)) {
        return false;
    }

    zf_runtime_config_apply(app, &next_config);
    return true;
}

bool zf_runtime_config_set_transport_mode(ZerofidoApp *app, Storage *storage,
                                          ZfTransportMode mode) {
    ZfRuntimeConfig next_config;

    if (!app || !zf_transport_mode_is_valid((uint8_t)mode)) {
        return false;
    }

    next_config = app->runtime_config;
    next_config.transport_mode = mode;
    if (!zf_runtime_config_persist(storage, &next_config)) {
        return false;
    }

    zf_runtime_config_apply(app, &next_config);
    return true;
}

void zf_runtime_config_resolve_capabilities(const ZfRuntimeConfig *config,
                                            ZfResolvedCapabilities *capabilities) {
    bool usb_hid_enabled = false;
    bool nfc_enabled = false;

    if (!config || !capabilities) {
        return;
    }

    usb_hid_enabled = config->transport_mode == ZfTransportModeUsbHid;
    nfc_enabled = config->transport_mode == ZfTransportModeNfc;

    memset(capabilities, 0, sizeof(*capabilities));
    capabilities->usb_hid_enabled = usb_hid_enabled;
    capabilities->nfc_enabled = nfc_enabled;
    capabilities->fido2_enabled = config->fido2_enabled;
    capabilities->u2f_enabled = config->u2f_enabled;
    capabilities->client_pin_enabled = config->fido2_enabled;
    capabilities->selection_enabled = config->fido2_enabled;
    capabilities->transport_keepalive_enabled = usb_hid_enabled && config->fido2_enabled;
    capabilities->transport_cancel_enabled = usb_hid_enabled && config->fido2_enabled;
    capabilities->transport_wink_enabled = usb_hid_enabled && config->u2f_enabled;
    capabilities->advertise_fido_2_1 = config->fido2_enabled;
    capabilities->advertise_fido_2_0 = config->fido2_enabled;
    capabilities->advertise_u2f_v2 = config->u2f_enabled;
    capabilities->advertise_usb_transport = usb_hid_enabled;
    capabilities->advertise_nfc_transport = nfc_enabled;
    capabilities->auto_accept_requests = config->auto_accept_requests;
}

void zf_runtime_get_effective_capabilities(const ZerofidoApp *app,
                                           ZfResolvedCapabilities *capabilities) {
    ZfRuntimeConfig defaults;

    if (!capabilities) {
        return;
    }

    if (app && app->capabilities_resolved) {
        *capabilities = app->capabilities;
        return;
    }

    zf_runtime_config_load_defaults(&defaults);
    zf_runtime_config_resolve_capabilities(&defaults, capabilities);
}

bool zf_runtime_ctap_command_enabled(const ZerofidoApp *app, uint8_t cmd) {
    ZfResolvedCapabilities capabilities;

    zf_runtime_get_effective_capabilities(app, &capabilities);
    switch (cmd) {
    case ZfCtapeCmdGetInfo:
    case ZfCtapeCmdMakeCredential:
    case ZfCtapeCmdGetAssertion:
    case ZfCtapeCmdReset:
    case ZfCtapeCmdGetNextAssertion:
        return capabilities.fido2_enabled;
    case ZfCtapeCmdClientPin:
        return capabilities.client_pin_enabled;
    case ZfCtapeCmdSelection:
        return capabilities.selection_enabled;
    default:
        return false;
    }
}

const char *zf_transport_mode_name(ZfTransportMode mode) {
    switch (mode) {
    case ZfTransportModeNfc:
        return "NFC";
    case ZfTransportModeUsbHid:
    default:
        return "USB HID";
    }
}
