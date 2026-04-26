#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "dispatch.h"

typedef struct ZerofidoApp ZerofidoApp;

typedef struct {
    int32_t (*worker)(void *context);
    size_t worker_stack_size;
    void (*stop)(ZerofidoApp *app);
    void (*send_dispatch_result)(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                 const ZfProtocolDispatchResult *result);
    bool (*wait_for_interaction)(ZerofidoApp *app, ZfTransportSessionId current_session_id,
                                 bool *approved);
    void (*notify_interaction_changed)(ZerofidoApp *app);
    uint8_t (*poll_cbor_control)(ZerofidoApp *app, ZfTransportSessionId current_session_id);
} ZfTransportAdapterOps;

#ifndef ZF_NFC_ONLY
extern const ZfTransportAdapterOps zf_transport_usb_hid_adapter;
#endif
extern const ZfTransportAdapterOps zf_transport_nfc_adapter;

void zf_transport_stop(ZerofidoApp *app);
void zf_transport_send_dispatch_result(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                       const ZfProtocolDispatchResult *result);
bool zf_transport_wait_for_interaction(ZerofidoApp *app, ZfTransportSessionId current_session_id,
                                       bool *approved);
void zf_transport_notify_interaction_changed(ZerofidoApp *app);
uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, ZfTransportSessionId current_session_id);
