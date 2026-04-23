#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct ZerofidoApp ZerofidoApp;

typedef struct {
    int32_t (*worker)(void *context);
    void (*stop)(ZerofidoApp *app);
    void (*send_keepalive)(uint32_t cid, uint8_t status);
    bool (*wait_for_interaction)(ZerofidoApp *app, uint32_t current_cid, bool *approved);
    void (*notify_interaction_changed)(ZerofidoApp *app);
    uint8_t (*poll_cbor_control)(ZerofidoApp *app, uint32_t current_cid);
} ZfTransportAdapterOps;

extern const ZfTransportAdapterOps zf_transport_usb_hid_adapter;

void zf_transport_stop(ZerofidoApp *app);
void zf_transport_send_keepalive(const ZerofidoApp *app, uint32_t cid, uint8_t status);
bool zf_transport_wait_for_interaction(ZerofidoApp *app, uint32_t current_cid, bool *approved);
void zf_transport_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, uint32_t current_cid);
