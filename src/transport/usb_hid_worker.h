#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dispatch.h"

typedef struct ZerofidoApp ZerofidoApp;

int32_t zf_transport_usb_hid_worker(void *context);
void zf_transport_usb_hid_stop(ZerofidoApp *app);
void zf_transport_usb_hid_send_dispatch_result(ZerofidoApp *app,
                                               const ZfProtocolDispatchRequest *request,
                                               const ZfProtocolDispatchResult *result);
bool zf_transport_usb_hid_wait_for_interaction(ZerofidoApp *app,
                                               ZfTransportSessionId current_session_id,
                                               bool *approved);
void zf_transport_usb_hid_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_usb_hid_poll_cbor_control(ZerofidoApp *app,
                                               ZfTransportSessionId current_session_id);
