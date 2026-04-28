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

#include <stdbool.h>
#include <storage/storage.h>
#include <stdint.h>

typedef struct ZerofidoApp ZerofidoApp;

typedef enum {
    ZfTransportModeUsbHid = 0,
    ZfTransportModeNfc = 1,
} ZfTransportMode;

typedef enum {
    ZfFido2ProfileCurrent = 0,
} ZfFido2Profile;

typedef enum {
    ZfU2fProfileCurrent = 0,
} ZfU2fProfile;

typedef struct {
    ZfTransportMode transport_mode;
    bool fido2_enabled;
    ZfFido2Profile fido2_profile;
    bool u2f_enabled;
    ZfU2fProfile u2f_profile;
    bool auto_accept_requests;
} ZfRuntimeConfig;

typedef struct {
    bool usb_hid_enabled;
    bool nfc_enabled;
    bool fido2_enabled;
    bool u2f_enabled;
    bool client_pin_enabled;
    bool selection_enabled;
    bool transport_keepalive_enabled;
    bool transport_cancel_enabled;
    bool transport_wink_enabled;
    bool advertise_fido_2_1;
    bool advertise_fido_2_0;
    bool advertise_u2f_v2;
    bool advertise_usb_transport;
    bool advertise_nfc_transport;
    bool auto_accept_requests;
} ZfResolvedCapabilities;

void zf_runtime_config_load_defaults(ZfRuntimeConfig *config);
void zf_runtime_config_load(Storage *storage, ZfRuntimeConfig *config);
bool zf_runtime_config_persist(Storage *storage, const ZfRuntimeConfig *config);
void zf_runtime_config_apply(ZerofidoApp *app, const ZfRuntimeConfig *config);
bool zf_runtime_config_set_auto_accept_requests(ZerofidoApp *app, Storage *storage, bool enabled);
bool zf_runtime_config_set_fido2_enabled(ZerofidoApp *app, Storage *storage, bool enabled);
bool zf_runtime_config_set_transport_mode(ZerofidoApp *app, Storage *storage, ZfTransportMode mode);
void zf_runtime_config_resolve_capabilities(const ZfRuntimeConfig *config,
                                            ZfResolvedCapabilities *capabilities);
void zf_runtime_get_effective_capabilities(const ZerofidoApp *app,
                                           ZfResolvedCapabilities *capabilities);
bool zf_runtime_ctap_command_enabled(const ZerofidoApp *app, uint8_t cmd);
const char *zf_transport_mode_name(ZfTransportMode mode);
