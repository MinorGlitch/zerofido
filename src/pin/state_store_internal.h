#pragma once

#include <stdint.h>

#include "../zerofido_types.h"

#define ZF_PIN_FILE_PATH ZF_APP_DATA_DIR "/client_pin.bin"
#define ZF_PIN_FILE_TEMP_PATH ZF_APP_DATA_DIR "/client_pin.tmp"
#define ZF_PIN_FILE_MAGIC 0x50494E31UL
#define ZF_PIN_FILE_VERSION_LEGACY 1U
#define ZF_PIN_FILE_VERSION_RETRIES_ONLY 2U
#define ZF_PIN_FILE_VERSION_UNSEALED 3U
#define ZF_PIN_FILE_VERSION 4U
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
} ZfPinFileRecordV3;

typedef struct {
    uint32_t magic;
    uint8_t pin_retries;
    uint8_t pin_consecutive_mismatches;
    uint8_t flags;
    uint8_t reserved;
    uint8_t digest[24];
} ZfPinRetrySeal;

typedef struct {
    ZfPinFileRecordV3 base;
    uint8_t retry_seal_iv[ZF_WRAP_IV_LEN];
    uint8_t encrypted_retry_seal[ZF_PIN_RETRY_SEAL_SIZE];
} ZfPinFileRecord;
