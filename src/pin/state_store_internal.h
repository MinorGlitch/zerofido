#pragma once

#include <stdint.h>

#include "../zerofido_types.h"

#define ZF_PIN_FILE_PATH ZF_APP_DATA_DIR "/client_pin.bin"
#define ZF_PIN_FILE_TEMP_PATH ZF_APP_DATA_DIR "/client_pin.tmp"
#define ZF_PIN_FILE_MAGIC 0x50494E31UL
#define ZF_PIN_FILE_VERSION 1U
#define ZF_PIN_FILE_FLAG_AUTH_BLOCKED 0x01U
#define ZF_PIN_RETRY_SEAL_MAGIC 0x504E5231UL
#define ZF_PIN_RETRY_SEAL_SIZE 32U

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t pin_retries;
    uint8_t pin_consecutive_mismatches;
    uint8_t flags;
    uint8_t iv[ZF_WRAP_IV_LEN];
    uint8_t encrypted_pin_hash[ZF_PIN_HASH_LEN];
} ZfPinFileRecordBase;

typedef struct {
    uint32_t magic;
    uint8_t pin_retries;
    uint8_t pin_consecutive_mismatches;
    uint8_t flags;
    uint8_t reserved;
    uint8_t digest[24];
} ZfPinRetrySeal;

typedef struct {
    ZfPinFileRecordBase base;
    uint8_t retry_seal_iv[ZF_WRAP_IV_LEN];
    uint8_t encrypted_retry_seal[ZF_PIN_RETRY_SEAL_SIZE];
} ZfPinFileRecord;
