#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "usb_hid_session.h"

typedef struct ZerofidoApp ZerofidoApp;

typedef struct {
    uint32_t cid;
    uint8_t transport_command;
    const uint8_t *payload;
    size_t payload_len;
} ZfProtocolDispatchRequest;

typedef struct {
    uint8_t transport_response_command;
    uint8_t *response;
    size_t response_capacity;
    size_t response_len;
    bool send_transport_error;
    uint8_t transport_error;
} ZfProtocolDispatchResult;

void zf_transport_dispatch_complete_message(ZerofidoApp *app, ZfTransportState *transport,
                                            uint32_t cid, uint8_t transport_command,
                                            const uint8_t *payload, size_t payload_len);
