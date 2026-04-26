#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nfc_worker.h"

bool zf_transport_nfc_handle_apdu(ZerofidoApp *app, ZfNfcTransportState *state,
                                  const uint8_t *apdu_bytes, size_t apdu_len);
