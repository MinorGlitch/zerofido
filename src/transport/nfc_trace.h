#pragma once

#include <furi.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define ZF_NFC_TRACE_TAG "ZeroFIDO:NFC"
#define ZF_NFC_TRACE_CHUNK 24U

#if defined(ZF_RELEASE_DIAGNOSTICS) && ZF_RELEASE_DIAGNOSTICS
static inline void zf_transport_nfc_trace_bytes(const char *label, const uint8_t *data,
                                                size_t data_len) {
    const char *name = label ? label : "bytes";

    if (!data && data_len > 0U) {
        FURI_LOG_I(ZF_NFC_TRACE_TAG, "%s len=%u null", name, (unsigned)data_len);
        return;
    }

    if (data_len == 0U) {
        FURI_LOG_I(ZF_NFC_TRACE_TAG, "%s len=0", name);
        return;
    }

    for (size_t offset = 0; offset < data_len; offset += ZF_NFC_TRACE_CHUNK) {
        char hex[(ZF_NFC_TRACE_CHUNK * 3U) + 1U] = {0};
        size_t hex_offset = 0U;
        size_t chunk_len = data_len - offset;

        if (chunk_len > ZF_NFC_TRACE_CHUNK) {
            chunk_len = ZF_NFC_TRACE_CHUNK;
        }

        for (size_t i = 0; i < chunk_len; ++i) {
            int written = snprintf(&hex[hex_offset], sizeof(hex) - hex_offset, "%s%02X",
                                   i == 0U ? "" : " ", data[offset + i]);
            if (written <= 0 || (size_t)written >= (sizeof(hex) - hex_offset)) {
                break;
            }
            hex_offset += (size_t)written;
        }

        FURI_LOG_I(ZF_NFC_TRACE_TAG, "%s len=%u off=%u %s", name, (unsigned)data_len,
                   (unsigned)offset, hex);
    }
}

static inline void zf_transport_nfc_trace_event(const char *event) {
    FURI_LOG_I(ZF_NFC_TRACE_TAG, "event %s", event ? event : "?");
}

static inline void zf_transport_nfc_trace_apdu_header(const char *direction, uint8_t cla,
                                                      uint8_t ins, uint8_t p1, uint8_t p2,
                                                      size_t data_len, bool extended, bool chained,
                                                      bool has_le, size_t le) {
    FURI_LOG_I(ZF_NFC_TRACE_TAG, "apdu-%s %02X %02X %02X %02X data=%u ext=%u chain=%u le=%s%u",
               direction ? direction : "?", cla, ins, p1, p2, (unsigned)data_len,
               extended ? 1U : 0U, chained ? 1U : 0U, has_le ? "" : "none/",
               has_le ? (unsigned)le : 0U);
}

static inline void zf_transport_nfc_trace_apdu_status(uint16_t status_word) {
    FURI_LOG_I(ZF_NFC_TRACE_TAG, "apdu-tx sw=%04X data=0", status_word);
}

static inline void zf_transport_nfc_trace_apdu_tx(const uint8_t *data, size_t data_len,
                                                  uint16_t status_word) {
    FURI_LOG_I(ZF_NFC_TRACE_TAG, "apdu-tx sw=%04X data=%u", status_word, (unsigned)data_len);
    zf_transport_nfc_trace_bytes("apdu-tx-data", data, data_len);
}
#else
static inline void zf_transport_nfc_trace_bytes(const char *label, const uint8_t *data,
                                                size_t data_len) {
    (void)label;
    (void)data;
    (void)data_len;
}

static inline void zf_transport_nfc_trace_event(const char *event) {
    (void)event;
}

static inline void zf_transport_nfc_trace_apdu_header(const char *direction, uint8_t cla,
                                                      uint8_t ins, uint8_t p1, uint8_t p2,
                                                      size_t data_len, bool extended, bool chained,
                                                      bool has_le, size_t le) {
    (void)direction;
    (void)cla;
    (void)ins;
    (void)p1;
    (void)p2;
    (void)data_len;
    (void)extended;
    (void)chained;
    (void)has_le;
    (void)le;
}

static inline void zf_transport_nfc_trace_apdu_status(uint16_t status_word) {
    (void)status_word;
}

static inline void zf_transport_nfc_trace_apdu_tx(const uint8_t *data, size_t data_len,
                                                  uint16_t status_word) {
    (void)data;
    (void)data_len;
    (void)status_word;
}
#endif
