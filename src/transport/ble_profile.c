/*
 * ZeroFIDO (BLE transport fork)
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

#include "ble_profile.h"

#include <furi.h>
#include <furi_hal_version.h>
#include <furi_ble/event_dispatcher.h>
#include <furi_ble/gatt.h>
#include <services/dev_info_service.h>
#include <stdlib.h>
#include <string.h>

/*
 * The SDK exposes these constants through ST headers that are not guaranteed to
 * be on a FAP's include path, so provide the (stable, ST-defined) values as a
 * fallback. Guards make this a no-op if the headers do supply them.
 */
#ifndef UUID_TYPE_16
#define UUID_TYPE_16 0x01
#endif
#ifndef UUID_TYPE_128
#define UUID_TYPE_128 0x02
#endif
#ifndef PRIMARY_SERVICE
#define PRIMARY_SERVICE 0x01
#endif
#ifndef CHAR_PROP_READ
#define CHAR_PROP_READ 0x02
#endif
#ifndef CHAR_PROP_WRITE
#define CHAR_PROP_WRITE 0x08
#endif
#ifndef CHAR_PROP_NOTIFY
#define CHAR_PROP_NOTIFY 0x10
#endif
#ifndef ATTR_PERMISSION_AUTHEN_READ
#define ATTR_PERMISSION_AUTHEN_READ 0x01
#endif
#ifndef ATTR_PERMISSION_AUTHEN_WRITE
#define ATTR_PERMISSION_AUTHEN_WRITE 0x08
#endif
#ifndef GATT_DONT_NOTIFY_EVENTS
#define GATT_DONT_NOTIFY_EVENTS 0x00
#endif
#ifndef GATT_NOTIFY_ATTRIBUTE_WRITE
#define GATT_NOTIFY_ATTRIBUTE_WRITE 0x01
#endif
#ifndef CHAR_VALUE_LEN_CONSTANT
#define CHAR_VALUE_LEN_CONSTANT 0x00
#endif
#ifndef CHAR_VALUE_LEN_VARIABLE
#define CHAR_VALUE_LEN_VARIABLE 0x01
#endif

/* Vendor-specific HCI event carrying ACI_GATT_ATTRIBUTE_MODIFIED. */
#define ZF_HCI_VENDOR_EVT 0xFFU
#define ZF_ACI_GATT_ATTRIBUTE_MODIFIED 0x0C01U

#define ZF_FIDO_SERVICE_UUID16 0xFFFDU

/*
 * FIDO 128-bit characteristic UUIDs, F1D0FFFx-DEAA-ECEE-B42F-C9BA7ED623BB,
 * byte-reversed because the BLE stack takes them little-endian.
 */
#define ZF_FIDO_CHAR_UUID(last)                                                                    \
    {0xBB, 0x23, 0xD6, 0x7E, 0xBA, 0xC9, 0x2F, 0xB4, 0xEE, 0xEC, 0xAA, 0xDE, 0xF1, (last), 0xFF,    \
     0xD0, 0xF1}

typedef enum {
    ZfBleCharControlPoint = 0,
    ZfBleCharStatus,
    ZfBleCharControlPointLength,
    ZfBleCharServiceRevisionBitfield,
    ZfBleCharCount,
} ZfBleCharId;

/* Notification payload handed to the data callback through the update `source`. */
typedef struct {
    const uint8_t *data;
    uint16_t len;
} ZfBleStatusUpdate;

typedef struct {
    FuriHalBleProfileBase base;
    BleServiceDevInfo *dev_info_svc;
    uint16_t svc_handle;
    BleGattCharacteristicInstance chars[ZfBleCharCount];
    GapSvcEventHandler *event_handler;
    ZfBleWriteCallback on_write;
    void *write_context;
} ZfBleProfile;

_Static_assert(offsetof(ZfBleProfile, base) == 0, "Wrong layout");

/* fidoControlPointLength is a big-endian uint16. */
static const uint8_t zf_ble_control_point_length[2] = {
    (uint8_t)(ZF_BLE_PROFILE_FRAGMENT_SIZE >> 8),
    (uint8_t)(ZF_BLE_PROFILE_FRAGMENT_SIZE & 0xFFU),
};

/* Revision bits: bit 6 = U2F 1.2, bit 5 = FIDO2. */
static const uint8_t zf_ble_service_revision_bitfield[1] = {0x60};

/* Data callback for the variable-length status characteristic. */
static bool zf_ble_status_data(const void *context, const uint8_t **data, uint16_t *data_len) {
    const ZfBleStatusUpdate *update = context;

    if (!data || !data_len) {
        return false;
    }
    if (!update) {
        /* Characteristic creation: report the maximum value length, no data. */
        *data = NULL;
        *data_len = ZF_BLE_PROFILE_WRITE_MAX;
        return false;
    }
    *data = update->data;
    *data_len = update->len;
    return false; /* we keep ownership of the buffer */
}

static const BleGattCharacteristicParams zf_ble_chars[ZfBleCharCount] = {
    [ZfBleCharControlPoint] =
        {.name = "fidoControlPoint",
         .data_prop_type = FlipperGattCharacteristicDataFixed,
         .data.fixed.length = ZF_BLE_PROFILE_WRITE_MAX,
         .uuid.Char_UUID_128 = ZF_FIDO_CHAR_UUID(0xF1),
         .uuid_type = UUID_TYPE_128,
         .char_properties = CHAR_PROP_WRITE,
         .security_permissions = ATTR_PERMISSION_AUTHEN_WRITE,
         .gatt_evt_mask = GATT_NOTIFY_ATTRIBUTE_WRITE,
         .is_variable = CHAR_VALUE_LEN_VARIABLE},
    [ZfBleCharStatus] =
        {.name = "fidoStatus",
         .data_prop_type = FlipperGattCharacteristicDataCallback,
         .data.callback.fn = zf_ble_status_data,
         .data.callback.context = NULL,
         .uuid.Char_UUID_128 = ZF_FIDO_CHAR_UUID(0xF2),
         .uuid_type = UUID_TYPE_128,
         .char_properties = CHAR_PROP_NOTIFY,
         .security_permissions = ATTR_PERMISSION_AUTHEN_READ,
         .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS,
         .is_variable = CHAR_VALUE_LEN_VARIABLE},
    [ZfBleCharControlPointLength] =
        {.name = "fidoControlPointLength",
         .data_prop_type = FlipperGattCharacteristicDataFixed,
         .data.fixed.length = sizeof(zf_ble_control_point_length),
         .uuid.Char_UUID_128 = ZF_FIDO_CHAR_UUID(0xF3),
         .uuid_type = UUID_TYPE_128,
         .char_properties = CHAR_PROP_READ,
         .security_permissions = ATTR_PERMISSION_AUTHEN_READ,
         .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS,
         .is_variable = CHAR_VALUE_LEN_CONSTANT},
    [ZfBleCharServiceRevisionBitfield] =
        {.name = "fidoServiceRevisionBitfield",
         .data_prop_type = FlipperGattCharacteristicDataFixed,
         .data.fixed.length = sizeof(zf_ble_service_revision_bitfield),
         .uuid.Char_UUID_128 = ZF_FIDO_CHAR_UUID(0xF4),
         .uuid_type = UUID_TYPE_128,
         .char_properties = CHAR_PROP_READ | CHAR_PROP_WRITE,
         .security_permissions = ATTR_PERMISSION_AUTHEN_READ | ATTR_PERMISSION_AUTHEN_WRITE,
         .gatt_evt_mask = GATT_DONT_NOTIFY_EVENTS,
         .is_variable = CHAR_VALUE_LEN_CONSTANT},
};

static uint16_t zf_ble_read_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

/*
 * Event layout (hci_uart_pckt): [0] packet type, [1] event code, [2] parameter
 * length, [3..4] ACI event code (LE), [5..] ACI payload. For
 * ACI_GATT_ATTRIBUTE_MODIFIED the payload is connection handle, attribute
 * handle, offset and data length (all uint16 LE) followed by the data.
 */
static BleEventAckStatus zf_ble_event_handler(void *event, void *context) {
    ZfBleProfile *profile = context;
    const uint8_t *pkt = event;
    uint8_t param_len;
    uint16_t attr_handle;
    uint16_t data_len;

    if (!pkt || !profile) {
        return BleEventNotAck;
    }
    if (pkt[1] != ZF_HCI_VENDOR_EVT) {
        return BleEventNotAck;
    }
    param_len = pkt[2];
    if (param_len < 10U || zf_ble_read_u16(&pkt[3]) != ZF_ACI_GATT_ATTRIBUTE_MODIFIED) {
        return BleEventNotAck;
    }

    attr_handle = zf_ble_read_u16(&pkt[5 + 2]);
    data_len = zf_ble_read_u16(&pkt[5 + 6]);
    if ((size_t)data_len + 8U + 2U > param_len) {
        return BleEventNotAck;
    }

    /* The value attribute sits right after the characteristic declaration. */
    if (attr_handle == profile->chars[ZfBleCharControlPoint].handle + 1U) {
        if (profile->on_write && data_len > 0U && data_len <= ZF_BLE_PROFILE_WRITE_MAX) {
            profile->on_write(&pkt[5 + 8], data_len, profile->write_context);
        }
        return BleEventAckFlowEnable;
    }
    if (attr_handle == profile->chars[ZfBleCharServiceRevisionBitfield].handle + 1U) {
        /* The client selects a revision; both are served by the same handlers. */
        return BleEventAckFlowEnable;
    }
    return BleEventNotAck;
}

static FuriHalBleProfileBase *zf_ble_profile_start(FuriHalBleProfileParams profile_params) {
    const ZfBleProfileParams *params = profile_params;
    ZfBleProfile *profile = malloc(sizeof(ZfBleProfile));
    Service_UUID_t service_uuid;

    memset(profile, 0, sizeof(*profile));
    profile->base.config = zf_ble_profile;
    if (params) {
        profile->on_write = params->on_write;
        profile->write_context = params->context;
    }

    profile->dev_info_svc = ble_svc_dev_info_start();

    profile->event_handler = ble_event_dispatcher_register_svc_handler(zf_ble_event_handler, profile);

    memset(&service_uuid, 0, sizeof(service_uuid));
    service_uuid.Service_UUID_16 = ZF_FIDO_SERVICE_UUID16;
    if (!ble_gatt_service_add(UUID_TYPE_16, &service_uuid, PRIMARY_SERVICE, 12, &profile->svc_handle)) {
        ble_event_dispatcher_unregister_svc_handler(profile->event_handler);
        ble_svc_dev_info_stop(profile->dev_info_svc);
        free(profile);
        return NULL;
    }

    for (uint8_t i = 0; i < ZfBleCharCount; i++) {
        ble_gatt_characteristic_init(profile->svc_handle, &zf_ble_chars[i], &profile->chars[i]);
    }

    ble_gatt_characteristic_update(profile->svc_handle,
                                   &profile->chars[ZfBleCharControlPointLength],
                                   zf_ble_control_point_length);
    ble_gatt_characteristic_update(profile->svc_handle,
                                   &profile->chars[ZfBleCharServiceRevisionBitfield],
                                   zf_ble_service_revision_bitfield);

    return &profile->base;
}

static void zf_ble_profile_stop(FuriHalBleProfileBase *base) {
    ZfBleProfile *profile = (ZfBleProfile *)base;

    furi_check(base);
    furi_check(base->config == zf_ble_profile);

    ble_event_dispatcher_unregister_svc_handler(profile->event_handler);
    for (uint8_t i = 0; i < ZfBleCharCount; i++) {
        ble_gatt_characteristic_delete(profile->svc_handle, &profile->chars[i]);
    }
    ble_gatt_service_delete(profile->svc_handle);
    ble_svc_dev_info_stop(profile->dev_info_svc);
    free(profile);
}

/* Same connection interval window the firmware's serial profile uses. */
#define ZF_BLE_CONN_INTERVAL_MIN 0x06
#define ZF_BLE_CONN_INTERVAL_MAX 0x24

static void zf_ble_profile_get_gap_config(GapConfig *config, FuriHalBleProfileParams params) {
    UNUSED(params);
    furi_check(config);

    memset(config, 0, sizeof(*config));
    config->adv_service.UUID_Type = UUID_TYPE_16;
    config->adv_service.Service_UUID_16 = ZF_FIDO_SERVICE_UUID16;
    config->appearance_char = 0x0000;
    /* FIDO requires an authenticated, bonded link; show a passkey on the Flipper. */
    config->bonding_mode = true;
    config->pairing_method = GapPairingPinCodeShow;
    config->conn_param.conn_int_min = ZF_BLE_CONN_INTERVAL_MIN;
    config->conn_param.conn_int_max = ZF_BLE_CONN_INTERVAL_MAX;
    config->conn_param.slave_latency = 0;
    config->conn_param.supervisor_timeout = 0;

    memcpy(config->mac_address, furi_hal_version_get_ble_mac(), sizeof(config->mac_address));
    strlcpy(config->adv_name, furi_hal_version_get_ble_local_device_name_ptr(),
            sizeof(config->adv_name));
}

static const FuriHalBleProfileTemplate zf_ble_profile_template = {
    .start = zf_ble_profile_start,
    .stop = zf_ble_profile_stop,
    .get_gap_config = zf_ble_profile_get_gap_config,
};

const FuriHalBleProfileTemplate *const zf_ble_profile = &zf_ble_profile_template;

void zf_ble_profile_notify(FuriHalBleProfileBase *base, const uint8_t *data, uint16_t len) {
    ZfBleProfile *profile = (ZfBleProfile *)base;
    ZfBleStatusUpdate update = {.data = data, .len = len};

    if (!base || base->config != zf_ble_profile || !data || len == 0U ||
        len > ZF_BLE_PROFILE_WRITE_MAX) {
        return;
    }

    ble_gatt_characteristic_update(profile->svc_handle, &profile->chars[ZfBleCharStatus], &update);
}
