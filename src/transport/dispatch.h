#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;
typedef struct ZfTransportState ZfTransportState;

typedef enum {
    ZfTransportProtocolKindPing = 0,
    ZfTransportProtocolKindU2f = 1,
    ZfTransportProtocolKindCtap2 = 2,
    ZfTransportProtocolKindWink = 3,
} ZfTransportProtocolKind;

typedef struct {
    ZfTransportSessionId session_id;
    ZfTransportProtocolKind protocol;
    const uint8_t *payload;
    size_t payload_len;
} ZfProtocolDispatchRequest;

typedef struct {
    uint8_t *response;
    size_t response_capacity;
    size_t response_len;
    bool send_transport_error;
    uint8_t transport_error;
} ZfProtocolDispatchResult;

void zf_transport_dispatch_complete_message(ZerofidoApp *app, ZfTransportState *transport,
                                            ZfTransportSessionId session_id,
                                            ZfTransportProtocolKind protocol,
                                            const uint8_t *payload, size_t payload_len);
