#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct ZerofidoApp ZerofidoApp;

int32_t zf_transport_usb_hid_worker(void *context);
void zf_transport_usb_hid_stop(ZerofidoApp *app);
void zf_transport_usb_hid_send_keepalive(uint32_t cid, uint8_t status);
bool zf_transport_usb_hid_wait_for_interaction(ZerofidoApp *app, uint32_t current_cid,
                                               bool *approved);
void zf_transport_usb_hid_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_usb_hid_poll_cbor_control(ZerofidoApp *app, uint32_t current_cid);
