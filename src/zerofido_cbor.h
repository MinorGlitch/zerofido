#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *buf;
    size_t capacity;
    size_t offset;
} ZfCborEncoder;

typedef struct {
    const uint8_t *ptr;
    const uint8_t *end;
} ZfCborCursor;

bool zf_cbor_encoder_init(ZfCborEncoder *enc, uint8_t *buf, size_t capacity);
size_t zf_cbor_encoder_size(const ZfCborEncoder *enc);
bool zf_cbor_encode_uint(ZfCborEncoder *enc, uint64_t value);
bool zf_cbor_encode_int(ZfCborEncoder *enc, int64_t value);
bool zf_cbor_encode_bool(ZfCborEncoder *enc, bool value);
bool zf_cbor_encode_bytes(ZfCborEncoder *enc, const uint8_t *data, size_t size);
bool zf_cbor_encode_text(ZfCborEncoder *enc, const char *text);
bool zf_cbor_encode_text_n(ZfCborEncoder *enc, const char *text, size_t size);
bool zf_cbor_encode_map(ZfCborEncoder *enc, size_t pairs);
bool zf_cbor_encode_array(ZfCborEncoder *enc, size_t items);

void zf_cbor_cursor_init(ZfCborCursor *cursor, const uint8_t *data, size_t size);
bool zf_cbor_read_uint(ZfCborCursor *cursor, uint64_t *value);
bool zf_cbor_read_int(ZfCborCursor *cursor, int64_t *value);
bool zf_cbor_read_bool(ZfCborCursor *cursor, bool *value);
bool zf_cbor_read_bytes_ptr(ZfCborCursor *cursor, const uint8_t **data, size_t *size);
bool zf_cbor_read_text_ptr(ZfCborCursor *cursor, const uint8_t **data, size_t *size);
bool zf_cbor_read_map_start(ZfCborCursor *cursor, size_t *pairs);
bool zf_cbor_read_array_start(ZfCborCursor *cursor, size_t *items);
bool zf_cbor_skip(ZfCborCursor *cursor);
