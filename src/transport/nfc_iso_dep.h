#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nfc_worker.h"

#define ZF_NFC_PCB_BLOCK 0x02U
#define ZF_NFC_PCB_CID 0x08U
#define ZF_NFC_PCB_CHAIN 0x10U
#define ZF_NFC_PCB_R_BLOCK 0xA0U
#define ZF_NFC_PCB_S_BLOCK 0xC0U

bool zf_transport_nfc_send_frame(ZfNfcTransportState *state, const uint8_t *data, size_t data_len);
bool zf_transport_nfc_send_raw_bits(ZfNfcTransportState *state, const uint8_t *data,
                                    size_t bit_len);
bool zf_transport_nfc_send_short_frame(ZfNfcTransportState *state, uint8_t data);
bool zf_transport_nfc_send_iso_response(ZfNfcTransportState *state, const uint8_t *data,
                                        size_t data_len, bool chaining);
bool zf_transport_nfc_send_r_ack(ZfNfcTransportState *state, uint8_t pcb);
void zf_transport_nfc_clear_last_iso_response(ZfNfcTransportState *state);
bool zf_transport_nfc_replay_last_iso_response(ZfNfcTransportState *state);
bool zf_transport_nfc_send_status_word(ZfNfcTransportState *state, uint16_t status_word);
bool zf_transport_nfc_send_forced_iso_status_word(ZfNfcTransportState *state, uint16_t status_word);
bool zf_transport_nfc_send_apdu_payload(ZfNfcTransportState *state, const uint8_t *data,
                                        size_t data_len, uint16_t status_word);
void zf_transport_nfc_prepare_listener(ZfNfcTransportState *state);
