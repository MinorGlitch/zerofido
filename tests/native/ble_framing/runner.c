/*
 * Host-native regression tests for the FIDO-over-BLE framing layer.
 * Build: cc -std=c11 -Wall -Wextra -Werror -I src/transport \
 *           tests/native/ble_framing/runner.c src/transport/ble_framing.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ble_framing.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        g_checks++;                                                                    \
        if (!(cond)) {                                                                 \
            g_failures++;                                                              \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                              \
    } while (0)

/* Sends msg through the fragmenter at fragment_size and reassembles it. */
static void roundtrip(uint8_t cmd, size_t len, size_t fragment_size) {
    uint8_t *payload = malloc(len ? len : 1);
    uint8_t *rxbuf = malloc(0x10000);
    uint8_t frag[ZF_BLE_MAX_FRAGMENT_SIZE];
    ZfBleTx tx;
    ZfBleRx rx;
    ZfBleRxStatus status = ZfBleRxIncomplete;
    size_t fragments = 0;
    size_t n;

    for (size_t i = 0; i < len; i++) {
        payload[i] = (uint8_t)(i * 7 + 3);
    }

    CHECK(zf_ble_tx_init(&tx, cmd, payload, len, fragment_size));
    zf_ble_rx_init(&rx, rxbuf, 0x10000);

    while ((n = zf_ble_tx_next(&tx, frag, sizeof(frag))) > 0) {
        CHECK(n <= fragment_size);
        status = zf_ble_rx_feed(&rx, frag, n);
        fragments++;
        if (zf_ble_tx_done(&tx)) {
            break;
        }
        CHECK(status == ZfBleRxIncomplete);
    }

    CHECK(zf_ble_tx_done(&tx));
    CHECK(status == ZfBleRxComplete);
    CHECK(rx.cmd == cmd);
    CHECK(rx.len == len);
    CHECK(len == 0 || memcmp(rx.buf, payload, len) == 0);

    /* Expected fragment count: one init plus enough continuations. */
    {
        size_t first = fragment_size - ZF_BLE_INIT_HEADER_SIZE;
        size_t per = fragment_size - ZF_BLE_CONT_HEADER_SIZE;
        size_t expect = 1;
        if (len > first) {
            expect += (len - first + per - 1) / per;
        }
        CHECK(fragments == expect);
    }

    free(payload);
    free(rxbuf);
}

static void test_roundtrip_sizes(void) {
    const size_t sizes[] = {0, 1, 16, 17, 18, 19, 20, 100, 255, 256, 1024, 4000, 0xFFFF};
    const size_t frags[] = {20, 23, 64, 185, 244, 512};

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        for (size_t j = 0; j < sizeof(frags) / sizeof(frags[0]); j++) {
            roundtrip(ZF_BLE_CMD_MSG, sizes[i], frags[j]);
        }
    }
    roundtrip(ZF_BLE_CMD_PING, 40, 20);
}

static void test_sequence_wraps_at_128(void) {
    /* 20-byte fragments carry 19 bytes each, so this needs > 128 continuations. */
    roundtrip(ZF_BLE_CMD_MSG, 3000, 20);
}

static void test_single_fragment_message(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t frag[] = {ZF_BLE_CMD_MSG, 0x00, 0x03, 0x04, 0xAA, 0xBB};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, sizeof(frag)) == ZfBleRxComplete);
    CHECK(rx.len == 3);
    CHECK(buf[0] == 0x04 && buf[1] == 0xAA && buf[2] == 0xBB);
    CHECK(!rx.active);
}

static void test_invalid_command(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t frag[] = {0x90, 0x00, 0x00};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, sizeof(frag)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_CMD);
}

static void test_short_init_header(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t frag[] = {ZF_BLE_CMD_MSG, 0x00};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, sizeof(frag)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_LEN);
}

static void test_length_exceeds_buffer(void) {
    uint8_t buf[16];
    ZfBleRx rx;
    const uint8_t frag[] = {ZF_BLE_CMD_MSG, 0x00, 0x20, 0x01};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, sizeof(frag)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_LEN);
}

static void test_init_data_longer_than_hlen(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t frag[] = {ZF_BLE_CMD_MSG, 0x00, 0x01, 0xAA, 0xBB};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, sizeof(frag)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_LEN);
}

static void test_bad_sequence(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t init[] = {ZF_BLE_CMD_MSG, 0x00, 0x05, 0x01, 0x02};
    const uint8_t bad[] = {0x01, 0x03, 0x04, 0x05};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, init, sizeof(init)) == ZfBleRxIncomplete);
    CHECK(zf_ble_rx_feed(&rx, bad, sizeof(bad)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_SEQ);
    CHECK(!rx.active);
}

static void test_continuation_without_init(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t cont[] = {0x00, 0x01};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, cont, sizeof(cont)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_SEQ);
}

static void test_continuation_overflow(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t init[] = {ZF_BLE_CMD_MSG, 0x00, 0x04, 0x01, 0x02};
    const uint8_t cont[] = {0x00, 0x03, 0x04, 0x05};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, init, sizeof(init)) == ZfBleRxIncomplete);
    CHECK(zf_ble_rx_feed(&rx, cont, sizeof(cont)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_LEN);
}

static void test_cancel(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t init[] = {ZF_BLE_CMD_MSG, 0x00, 0x05, 0x01, 0x02};
    const uint8_t cancel[] = {ZF_BLE_CMD_CANCEL, 0x00, 0x00};
    const uint8_t whole[] = {ZF_BLE_CMD_MSG, 0x00, 0x01, 0x04};

    zf_ble_rx_init(&rx, buf, sizeof(buf));

    /* CANCEL with nothing in flight. */
    CHECK(zf_ble_rx_feed(&rx, cancel, sizeof(cancel)) == ZfBleRxCancel);

    /* CANCEL mid-message drops the partial message and the next one works. */
    CHECK(zf_ble_rx_feed(&rx, init, sizeof(init)) == ZfBleRxIncomplete);
    CHECK(zf_ble_rx_feed(&rx, cancel, sizeof(cancel)) == ZfBleRxCancel);
    CHECK(!rx.active);
    CHECK(zf_ble_rx_feed(&rx, whole, sizeof(whole)) == ZfBleRxComplete);
    CHECK(rx.len == 1 && buf[0] == 0x04);
}

static void test_new_init_mid_message(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t init[] = {ZF_BLE_CMD_MSG, 0x00, 0x05, 0x01, 0x02};
    const uint8_t again[] = {ZF_BLE_CMD_MSG, 0x00, 0x01, 0x04};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, init, sizeof(init)) == ZfBleRxIncomplete);
    CHECK(zf_ble_rx_feed(&rx, again, sizeof(again)) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_SEQ);
}

static void test_empty_write(void) {
    uint8_t buf[64];
    ZfBleRx rx;
    const uint8_t frag[] = {0x00};

    zf_ble_rx_init(&rx, buf, sizeof(buf));
    CHECK(zf_ble_rx_feed(&rx, frag, 0) == ZfBleRxError);
    CHECK(rx.error_code == ZF_BLE_ERR_INVALID_LEN);
}

static void test_tx_rejects_bad_params(void) {
    ZfBleTx tx;
    uint8_t data[4] = {0};

    CHECK(!zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, data, 4, ZF_BLE_MIN_FRAGMENT_SIZE - 1));
    CHECK(!zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, data, 4, ZF_BLE_MAX_FRAGMENT_SIZE + 1));
    CHECK(!zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, data, 0x10000, 64));
    CHECK(!zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, NULL, 4, 64));
    CHECK(zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, NULL, 0, 64));
}

static void test_tx_small_output_buffer(void) {
    ZfBleTx tx;
    uint8_t data[40] = {0};
    uint8_t out[8];

    CHECK(zf_ble_tx_init(&tx, ZF_BLE_CMD_MSG, data, sizeof(data), 20));
    CHECK(zf_ble_tx_next(&tx, out, sizeof(out)) == 0);
    CHECK(!zf_ble_tx_done(&tx));
}

static void test_classify(void) {
    const uint8_t u2f[] = {0x00, 0x01, 0x03, 0x00};
    const uint8_t get_info[] = {0x04};
    const uint8_t make_cred[] = {0x01, 0xA5};

    CHECK(zf_ble_classify_msg(u2f, sizeof(u2f)) == ZfBleMessageKindU2f);
    CHECK(zf_ble_classify_msg(get_info, sizeof(get_info)) == ZfBleMessageKindCtap2);
    CHECK(zf_ble_classify_msg(make_cred, sizeof(make_cred)) == ZfBleMessageKindCtap2);
    CHECK(zf_ble_classify_msg(NULL, 0) == ZfBleMessageKindInvalid);
    CHECK(zf_ble_classify_msg(get_info, 0) == ZfBleMessageKindInvalid);
}

static void test_error_and_keepalive_builders(void) {
    uint8_t out[4];
    uint8_t small[3];

    CHECK(zf_ble_build_error(ZF_BLE_ERR_INVALID_SEQ, out, sizeof(out)) == 4);
    CHECK(out[0] == ZF_BLE_CMD_ERROR && out[1] == 0x00 && out[2] == 0x01 &&
          out[3] == ZF_BLE_ERR_INVALID_SEQ);

    CHECK(zf_ble_build_keepalive(ZF_BLE_KEEPALIVE_USER_PRESENCE_NEEDED, out, sizeof(out)) == 4);
    CHECK(out[0] == ZF_BLE_CMD_KEEPALIVE && out[3] == ZF_BLE_KEEPALIVE_USER_PRESENCE_NEEDED);

    CHECK(zf_ble_build_error(ZF_BLE_ERR_OTHER, small, sizeof(small)) == 0);
}

int main(void) {
    test_roundtrip_sizes();
    test_sequence_wraps_at_128();
    test_single_fragment_message();
    test_invalid_command();
    test_short_init_header();
    test_length_exceeds_buffer();
    test_init_data_longer_than_hlen();
    test_bad_sequence();
    test_continuation_without_init();
    test_continuation_overflow();
    test_cancel();
    test_new_init_mid_message();
    test_empty_write();
    test_tx_rejects_bad_params();
    test_tx_small_output_buffer();
    test_classify();
    test_error_and_keepalive_builders();

    if (g_failures) {
        fprintf(stderr, "%d of %d checks failed\n", g_failures, g_checks);
        return 1;
    }
    printf("ble_framing: %d checks passed\n", g_checks);
    return 0;
}
