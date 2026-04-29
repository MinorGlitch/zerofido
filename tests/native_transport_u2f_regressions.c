#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "furi.h"
#include "furi_hal.h"
#include "furi_hal_random.h"
#include "furi_hal_usb_hid_u2f.h"
#include "flipper_format/flipper_format.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "nfc/helpers/iso14443_crc.h"
#include "nfc/nfc.h"
#include "nfc/nfc_listener.h"
#include "nfc/protocols/iso14443_3a/iso14443_3a_listener.h"
#include "nfc/protocols/iso14443_4a/iso14443_4a.h"
#include "nfc/protocols/iso14443_4a/iso14443_4a_listener.h"
#include "storage/storage.h"
#include "toolbox/bit_buffer.h"
#include "zerofido_crypto.h"
#include "zerofido_ui_format.h"
#include "lib/toolbox/simple_array.h"

/*
 * Host-native transport/U2F regression harness. It stubs USB, NFC, storage, UI,
 * and crypto boundaries so the production transport and U2F modules can be
 * tested as compiled C on the workstation.
 */

#define FURI_PACKED __attribute__((packed))
#define FURI_LOG_E(tag, fmt, ...) ((void)0)
#define FURI_LOG_W(tag, fmt, ...) ((void)0)
#define FURI_LOG_D(tag, fmt, ...) ((void)0)
#define furi_assert(expr) ((void)(expr))

static void test_furi_log_i(const char *tag, const char *fmt, ...);
#define FURI_LOG_I test_furi_log_i

typedef int FuriStatus;
typedef struct ZerofidoApp ZerofidoApp;
static bool test_transport_auto_accept_enabled(const ZerofidoApp *app);

struct Storage {
    int unused;
};

struct File {
    char path[160];
    FS_AccessMode access_mode;
    size_t offset;
    bool open;
};

struct FileInfo {
    int unused;
};

struct FlipperFormat {
    int unused;
};

struct FuriString {
    char value[64];
};

struct FuriHalUsbInterface {
    int unused;
};

struct FuriThread {
    FuriThreadCallback callback;
    void *context;
    size_t stack_size;
    FuriThreadPriority priority;
    bool started;
    bool joined;
    bool freed;
};

struct FuriSemaphore {
    int unused;
};

struct FuriTimer {
    FuriTimerCallback callback;
    void *context;
    FuriTimerType type;
    uint32_t last_timeout;
    size_t start_count;
    size_t stop_count;
    bool running;
};

struct FuriMutex {
    size_t depth;
};

struct BitBuffer {
    uint8_t *data;
    size_t size_bits;
    size_t size_bytes;
    size_t capacity;
};

struct SimpleArray {
    const SimpleArrayConfig *config;
    uint8_t *data;
    uint32_t count;
};

struct Nfc {
    uint32_t fdt_listen_fc;
    NfcMode mode;
    NfcTech tech;
    bool started;
    bool stopped;
    uint8_t uid[10];
    uint8_t uid_len;
    uint8_t atqa[2];
    uint8_t sak;
};

struct NfcListener {
    Nfc *nfc;
    NfcGenericCallback callback;
    void *context;
    NfcProtocol protocol;
    const NfcDeviceData *data;
    bool started;
    bool stopped;
};

struct Iso14443_4aListener {
    int unused;
};

#define FuriStatusOk 0
#define FuriFlagError 0x80000000U
#define FuriFlagErrorTimeout 0xFFFFFFFEU
#define FuriFlagWaitAny 0U
#define FuriWaitForever 0U

static uint32_t g_fake_tick = 0;
static uint32_t g_random_values[16];
static size_t g_random_count = 0;
static size_t g_random_index = 0;
static uint32_t g_thread_flag_results[8];
static size_t g_thread_flag_result_count = 0;
static size_t g_thread_flag_result_index = 0;
static uint32_t g_last_thread_flags_set = 0;
static size_t g_thread_flags_set_count = 0;
static FuriThread g_nfc_worker_thread;
static uint32_t g_last_thread_wait_timeout = 0;
static size_t g_thread_flag_wait_call_count = 0;
static FuriMutex *g_thread_start_observed_mutex = NULL;
static size_t g_thread_start_observed_depth = 0;
static size_t g_thread_join_count = 0;
static size_t g_thread_free_count = 0;
static FuriMutex *g_thread_join_observed_mutex = NULL;
static size_t g_thread_join_observed_depth = 0;
static FuriStatus g_semaphore_results[8];
static size_t g_semaphore_result_count = 0;
static size_t g_semaphore_result_index = 0;
static size_t g_cancel_pending_interaction_count = 0;
static bool g_cancel_pending_interaction_result = false;
static size_t g_approval_request_count = 0;
static bool g_auto_accept_requests = false;
static size_t g_transport_connected_set_count = 0;
static size_t g_transport_connected_true_count = 0;
static bool g_last_transport_connected = false;
static size_t g_notify_prompt_count = 0;
static uint8_t g_last_hid_response[64];
static size_t g_last_hid_response_len = 0;
static size_t g_hid_response_count = 0;
static uint8_t g_last_nfc_tx[320];
static size_t g_last_nfc_tx_bits = 0;
static size_t g_last_nfc_tx_len = 0;
static size_t g_nfc_tx_count = 0;
static bool g_nfc_alloc_result = true;
static bool g_nfc_listener_alloc_result = true;
static size_t g_mutex_max_depth = 0;
static char g_last_status_text[64];
static char g_last_log_text[192];
static char g_log_text[4096];
static size_t g_log_i_count = 0;
static bool g_bit_buffer_scrub_on_reset = false;
static bool g_ctap2_saw_transport_auto_accept = false;
static bool g_ctap2_request_response_overlap = false;
static size_t g_ctap2_large_response_len = 0U;
static bool g_get_info_builder_called = false;
static bool g_get_info_builder_saw_nfc_transport = false;
static bool g_get_info_builder_saw_usb_transport = false;
static bool g_u2f_cert_assets_present = true;
static bool g_u2f_cert_check_result = true;
static bool g_u2f_cert_key_load_result = true;
static bool g_u2f_cert_key_matches_result = true;
static size_t g_u2f_attestation_ensure_call_count = 0;
static bool g_u2f_attestation_ensure_result = true;
static bool g_u2f_key_exists_result = true;
static bool g_u2f_key_load_result = true;
static size_t g_u2f_key_generate_count = 0;
static bool g_u2f_cnt_exists_result = true;
static bool g_u2f_cnt_read_result = true;
static size_t g_u2f_cnt_write_count = 0;
static uint32_t g_u2f_last_written_counter = 0;
static size_t g_u2f_cnt_reserve_count = 0;
static uint32_t g_u2f_last_reserved_counter = 0;
static uint8_t g_hid_request_packets[8][64];
static size_t g_hid_request_packet_lens[8];
static size_t g_hid_request_count = 0;
static size_t g_hid_request_index = 0;
static bool g_hid_connected = false;
static bool g_usb_set_config_result = true;
static size_t g_usb_set_config_count = 0;
static const FuriHalUsbInterface *g_last_usb_set_config = NULL;
static FuriHalUsbInterface g_previous_usb_config = {1};
static uint8_t g_sha256_trace[4096];
static size_t g_sha256_trace_len = 0;
#define TEST_STORAGE_MAX_FILE_SIZE 128
typedef struct {
    bool in_use;
    char path[128];
    uint8_t data[TEST_STORAGE_MAX_FILE_SIZE];
    size_t size;
    bool exists;
} TestStorageFile;
static bool g_storage_root_exists = true;
static bool g_storage_app_data_exists = true;
static const char *g_storage_fail_write_match = NULL;
static TestStorageFile g_storage_files[4];
static FuriTimer g_timer_pool[8];
static size_t g_timer_pool_count = 0;

const SimpleArrayConfig simple_array_config_uint8_t = {
    .init = NULL,
    .reset = NULL,
    .copy = NULL,
    .type_size = sizeof(uint8_t),
};

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_furi_log_i(const char *tag, const char *fmt, ...) {
    char line[192];
    size_t used = 0U;
    va_list args;

    UNUSED(tag);
    va_start(args, fmt);
    vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    snprintf(g_last_log_text, sizeof(g_last_log_text), "%s", line);
    used = strlen(g_log_text);
    if (used < sizeof(g_log_text) - 1U) {
        snprintf(&g_log_text[used], sizeof(g_log_text) - used, "%s%s", used ? "\n" : "", line);
    }
    g_log_i_count++;
}

static bool test_log_contains(const char *needle) {
    return needle && strstr(g_log_text, needle) != NULL;
}

static void test_reset(void) {
    g_fake_tick = 0;
    memset(g_random_values, 0, sizeof(g_random_values));
    g_random_count = 0;
    g_random_index = 0;
    memset(g_thread_flag_results, 0, sizeof(g_thread_flag_results));
    g_thread_flag_result_count = 0;
    g_thread_flag_result_index = 0;
    g_last_thread_flags_set = 0;
    g_thread_flags_set_count = 0;
    memset(&g_nfc_worker_thread, 0, sizeof(g_nfc_worker_thread));
    g_last_thread_wait_timeout = 0;
    g_thread_flag_wait_call_count = 0;
    g_thread_start_observed_mutex = NULL;
    g_thread_start_observed_depth = 0;
    g_thread_join_count = 0;
    g_thread_free_count = 0;
    g_thread_join_observed_mutex = NULL;
    g_thread_join_observed_depth = 0;
    memset(g_semaphore_results, 0, sizeof(g_semaphore_results));
    g_semaphore_result_count = 0;
    g_semaphore_result_index = 0;
    g_cancel_pending_interaction_count = 0;
    g_cancel_pending_interaction_result = false;
    g_approval_request_count = 0;
    g_auto_accept_requests = false;
    g_transport_connected_set_count = 0;
    g_transport_connected_true_count = 0;
    g_last_transport_connected = false;
    g_notify_prompt_count = 0;
    memset(g_last_hid_response, 0, sizeof(g_last_hid_response));
    g_last_hid_response_len = 0;
    g_hid_response_count = 0;
    memset(g_last_nfc_tx, 0, sizeof(g_last_nfc_tx));
    g_last_nfc_tx_bits = 0;
    g_last_nfc_tx_len = 0;
    g_nfc_tx_count = 0;
    g_nfc_alloc_result = true;
    g_nfc_listener_alloc_result = true;
    g_mutex_max_depth = 0;
    memset(g_last_status_text, 0, sizeof(g_last_status_text));
    memset(g_last_log_text, 0, sizeof(g_last_log_text));
    memset(g_log_text, 0, sizeof(g_log_text));
    g_log_i_count = 0;
    g_bit_buffer_scrub_on_reset = false;
    g_ctap2_saw_transport_auto_accept = false;
    g_ctap2_request_response_overlap = false;
    g_ctap2_large_response_len = 0U;
    g_get_info_builder_called = false;
    g_get_info_builder_saw_nfc_transport = false;
    g_get_info_builder_saw_usb_transport = false;
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    g_u2f_attestation_ensure_call_count = 0;
    g_u2f_attestation_ensure_result = true;
    g_u2f_key_exists_result = true;
    g_u2f_key_load_result = true;
    g_u2f_key_generate_count = 0;
    g_u2f_cnt_exists_result = true;
    g_u2f_cnt_read_result = true;
    g_u2f_cnt_write_count = 0;
    g_u2f_last_written_counter = 0;
    g_u2f_cnt_reserve_count = 0;
    g_u2f_last_reserved_counter = 0;
    memset(g_hid_request_packets, 0, sizeof(g_hid_request_packets));
    memset(g_hid_request_packet_lens, 0, sizeof(g_hid_request_packet_lens));
    g_hid_request_count = 0;
    g_hid_request_index = 0;
    g_hid_connected = false;
    g_usb_set_config_result = true;
    g_usb_set_config_count = 0;
    g_last_usb_set_config = NULL;
    g_previous_usb_config.unused = 1;
    memset(g_sha256_trace, 0, sizeof(g_sha256_trace));
    g_sha256_trace_len = 0;
    g_storage_root_exists = true;
    g_storage_app_data_exists = true;
    g_storage_fail_write_match = NULL;
    memset(g_storage_files, 0, sizeof(g_storage_files));
    memset(g_timer_pool, 0, sizeof(g_timer_pool));
    g_timer_pool_count = 0;
}

uint32_t furi_get_tick(void) {
    return g_fake_tick;
}

uint32_t furi_hal_random_get(void) {
    if (g_random_index < g_random_count) {
        return g_random_values[g_random_index++];
    }

    return 0xA5A50000U + (uint32_t)g_random_index++;
}

void furi_hal_random_fill_buf(void *buffer, size_t size) {
    memset(buffer, 0xA5, size);
}

bool furi_hal_crypto_enclave_load_key(uint8_t slot, const uint8_t *iv) {
    UNUSED(slot);
    UNUSED(iv);
    return true;
}

bool furi_hal_crypto_enclave_ensure_key(uint8_t slot) {
    UNUSED(slot);
    return true;
}

void furi_hal_crypto_enclave_unload_key(uint8_t slot) {
    UNUSED(slot);
}

bool furi_hal_crypto_load_key(const uint8_t *key, const uint8_t *iv) {
    UNUSED(key);
    UNUSED(iv);
    return true;
}

bool furi_hal_crypto_unload_key(void) {
    return true;
}

bool furi_hal_crypto_encrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

bool furi_hal_crypto_decrypt(const uint8_t *input, uint8_t *output, size_t size) {
    memcpy(output, input, size);
    return true;
}

FuriThreadId furi_thread_get_current_id(void) {
    return (FuriThreadId)0x1;
}

uint32_t furi_thread_get_stack_space(FuriThreadId thread_id) {
    UNUSED(thread_id);
    return 4096U;
}

FuriThreadId furi_thread_get_id(FuriThread *thread) {
    UNUSED(thread);
    return (FuriThreadId)0x2;
}

uint32_t furi_thread_flags_set(FuriThreadId thread_id, uint32_t flags) {
    UNUSED(thread_id);
    g_last_thread_flags_set = flags;
    g_thread_flags_set_count++;
    return 0;
}

uint32_t furi_thread_flags_get(void) {
    return 0;
}

uint32_t furi_thread_flags_clear(uint32_t flags) {
    UNUSED(flags);
    return 0;
}

uint32_t furi_thread_flags_wait(uint32_t flags, uint32_t options, uint32_t timeout) {
    UNUSED(flags);
    UNUSED(options);
    g_last_thread_wait_timeout = timeout;
    g_thread_flag_wait_call_count++;
    if (g_thread_flag_result_index < g_thread_flag_result_count) {
        return g_thread_flag_results[g_thread_flag_result_index++];
    }
    return FuriFlagErrorTimeout;
}

FuriThread *furi_thread_alloc_ex(const char *name, size_t stack_size, FuriThreadCallback callback,
                                 void *context) {
    FuriThread *thread = malloc(sizeof(*thread));
    UNUSED(name);
    if (!thread) {
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));
    thread->callback = callback;
    thread->context = context;
    thread->stack_size = stack_size;
    return thread;
}

void furi_thread_set_appid(FuriThread *thread, const char *appid) {
    UNUSED(thread);
    UNUSED(appid);
}

void furi_thread_set_priority(FuriThread *thread, FuriThreadPriority priority) {
    if (thread) {
        thread->priority = priority;
    }
}

void furi_thread_start(FuriThread *thread) {
    if (thread) {
        if (g_thread_start_observed_mutex) {
            g_thread_start_observed_depth = g_thread_start_observed_mutex->depth;
        }
        thread->started = true;
    }
}

void furi_thread_join(FuriThread *thread) {
    if (thread) {
        g_thread_join_count++;
        if (g_thread_join_observed_mutex) {
            g_thread_join_observed_depth = g_thread_join_observed_mutex->depth;
        }
        thread->joined = true;
    }
}

void furi_thread_free(FuriThread *thread) {
    if (thread) {
        g_thread_free_count++;
        thread->freed = true;
        free(thread);
    }
}

FuriStatus furi_semaphore_acquire(FuriSemaphore *sem, uint32_t timeout) {
    UNUSED(sem);
    UNUSED(timeout);
    if (g_semaphore_result_index < g_semaphore_result_count) {
        return g_semaphore_results[g_semaphore_result_index++];
    }
    return 1;
}

FuriStatus furi_semaphore_release(FuriSemaphore *sem) {
    UNUSED(sem);
    return FuriStatusOk;
}

FuriStatus furi_mutex_acquire(FuriMutex *mutex, uint32_t timeout) {
    UNUSED(timeout);
    if (mutex) {
        mutex->depth++;
        if (mutex->depth > g_mutex_max_depth) {
            g_mutex_max_depth = mutex->depth;
        }
    }
    return FuriStatusOk;
}

void furi_mutex_release(FuriMutex *mutex) {
    if (mutex && mutex->depth > 0U) {
        mutex->depth--;
    }
}

FuriTimer *furi_timer_alloc(FuriTimerCallback callback, FuriTimerType type, void *context) {
    FuriTimer *timer = NULL;

    expect(g_timer_pool_count < (sizeof(g_timer_pool) / sizeof(g_timer_pool[0])),
           "timer pool should have free slots");
    timer = &g_timer_pool[g_timer_pool_count++];
    memset(timer, 0, sizeof(*timer));
    timer->callback = callback;
    timer->context = context;
    timer->type = type;
    return timer;
}

void furi_timer_free(FuriTimer *timer) {
    if (timer) {
        timer->running = false;
    }
}

void furi_timer_start(FuriTimer *timer, uint32_t timeout) {
    expect(timer != NULL, "timer start should receive a timer");
    timer->last_timeout = timeout;
    timer->start_count++;
    timer->running = true;
}

void furi_timer_stop(FuriTimer *timer) {
    expect(timer != NULL, "timer stop should receive a timer");
    timer->stop_count++;
    timer->running = false;
}

BitBuffer *bit_buffer_alloc(size_t capacity) {
    BitBuffer *buffer = malloc(sizeof(*buffer));

    expect(buffer != NULL, "bit buffer allocation should succeed");
    buffer->data = malloc(capacity);
    expect(buffer->data != NULL, "bit buffer storage allocation should succeed");
    buffer->size_bits = 0;
    buffer->size_bytes = 0;
    buffer->capacity = capacity;
    return buffer;
}

void bit_buffer_free(BitBuffer *buffer) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
    }
}

void bit_buffer_reset(BitBuffer *buffer) {
    expect(buffer != NULL, "bit buffer reset should receive a buffer");
    if (g_bit_buffer_scrub_on_reset) {
        memset(buffer->data, 0xEE, buffer->capacity);
    }
    buffer->size_bits = 0;
    buffer->size_bytes = 0;
}

void bit_buffer_append_bytes(BitBuffer *buffer, const uint8_t *data, size_t size) {
    expect(buffer != NULL, "bit buffer append should receive a buffer");
    expect((buffer->size_bits % 8U) == 0U, "bit buffer byte append should be byte-aligned");
    expect(buffer->size_bytes + size <= buffer->capacity, "bit buffer append should fit capacity");
    if (size > 0) {
        memcpy(&buffer->data[buffer->size_bytes], data, size);
        buffer->size_bytes += size;
        buffer->size_bits = buffer->size_bytes * 8U;
    }
}

size_t bit_buffer_get_size(const BitBuffer *buffer) {
    expect(buffer != NULL, "bit buffer bit size should receive a buffer");
    return buffer->size_bits;
}

size_t bit_buffer_get_size_bytes(const BitBuffer *buffer) {
    expect(buffer != NULL, "bit buffer size should receive a buffer");
    return buffer->size_bytes;
}

uint8_t *bit_buffer_get_data(const BitBuffer *buffer) {
    expect(buffer != NULL, "bit buffer data should receive a buffer");
    return buffer->data;
}

void bit_buffer_set_byte(BitBuffer *buffer, size_t index, uint8_t byte) {
    expect(buffer != NULL, "bit buffer set byte should receive a buffer");
    expect(index < buffer->capacity, "bit buffer set byte should fit capacity");
    buffer->data[index] = byte;
}

void bit_buffer_set_size(BitBuffer *buffer, size_t size_bits) {
    size_t size_bytes = (size_bits + 7U) / 8U;

    expect(buffer != NULL, "bit buffer set size should receive a buffer");
    expect(size_bytes <= buffer->capacity, "bit buffer set size should fit capacity");
    buffer->size_bits = size_bits;
    buffer->size_bytes = size_bytes;
}

void iso14443_crc_append(Iso14443CrcType type, BitBuffer *buffer) {
    UNUSED(type);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x00, 0x00}, 2);
}

bool iso14443_crc_check(Iso14443CrcType type, const BitBuffer *buffer) {
    UNUSED(type);
    return buffer && buffer->size_bytes >= 2;
}

void iso14443_crc_trim(BitBuffer *buffer) {
    expect(buffer != NULL, "crc trim should receive a buffer");
    expect(buffer->size_bytes >= 2, "crc trim should only run on frames with crc bytes");
    buffer->size_bytes -= 2;
    buffer->size_bits = buffer->size_bytes * 8U;
}

Nfc *nfc_alloc(void) {
    if (!g_nfc_alloc_result) {
        return NULL;
    }

    Nfc *nfc = malloc(sizeof(*nfc));

    expect(nfc != NULL, "nfc allocation should succeed");
    memset(nfc, 0, sizeof(*nfc));
    return nfc;
}

void nfc_free(Nfc *nfc) {
    free(nfc);
}

void nfc_start(Nfc *nfc, NfcEventCallback callback, void *context) {
    expect(nfc != NULL, "nfc_start should receive a device");
    UNUSED(callback);
    UNUSED(context);
    nfc->started = true;
}

void nfc_stop(Nfc *nfc) {
    if (nfc) {
        nfc->stopped = true;
    }
}

NfcListener *nfc_listener_alloc(Nfc *nfc, NfcProtocol protocol, const NfcDeviceData *data) {
    if (!g_nfc_listener_alloc_result) {
        return NULL;
    }

    NfcListener *listener = malloc(sizeof(*listener));

    expect(listener != NULL, "nfc listener allocation should succeed");
    memset(listener, 0, sizeof(*listener));
    listener->nfc = nfc;
    listener->protocol = protocol;
    listener->data = data;
    return listener;
}

void nfc_listener_free(NfcListener *instance) {
    free(instance);
}

void nfc_listener_start(NfcListener *instance, NfcGenericCallback callback, void *context) {
    expect(instance != NULL, "nfc_listener_start should receive a listener");
    instance->callback = callback;
    instance->context = context;
    instance->started = true;
}

void nfc_listener_stop(NfcListener *instance) {
    if (instance) {
        instance->stopped = true;
    }
}

void nfc_set_fdt_listen_fc(Nfc *nfc, uint32_t fdt_listen_fc) {
    expect(nfc != NULL, "nfc_set_fdt_listen_fc should receive a device");
    nfc->fdt_listen_fc = fdt_listen_fc;
}

void nfc_config(Nfc *nfc, NfcMode mode, NfcTech tech) {
    expect(nfc != NULL, "nfc_config should receive a device");
    nfc->mode = mode;
    nfc->tech = tech;
}

NfcError nfc_listener_tx(Nfc *nfc, const BitBuffer *buffer) {
    UNUSED(nfc);
    expect(buffer != NULL, "nfc_listener_tx should receive a frame buffer");
    expect(buffer->size_bytes <= sizeof(g_last_nfc_tx), "nfc tx frame should fit capture");
    memcpy(g_last_nfc_tx, buffer->data, buffer->size_bytes);
    g_last_nfc_tx_bits = buffer->size_bits;
    g_last_nfc_tx_len = buffer->size_bytes;
    g_nfc_tx_count++;
    return NfcErrorNone;
}

void nfc_iso14443a_listener_set_col_res_data(Nfc *nfc, const uint8_t *uid, uint8_t uid_len,
                                             const uint8_t *atqa, uint8_t sak) {
    expect(nfc != NULL, "nfc collision-response setup should receive a device");
    expect(uid_len <= sizeof(nfc->uid), "nfc uid should fit the test stub");
    memcpy(nfc->uid, uid, uid_len);
    nfc->uid_len = uid_len;
    memcpy(nfc->atqa, atqa, sizeof(nfc->atqa));
    nfc->sak = sak;
}

void iso14443_3a_set_atqa(Iso14443_3aData *data, const uint8_t atqa[2]) {
    expect(data != NULL, "iso14443_3a_set_atqa should receive data");
    memcpy(data->atqa, atqa, 2);
}

void iso14443_3a_set_sak(Iso14443_3aData *data, uint8_t sak) {
    expect(data != NULL, "iso14443_3a_set_sak should receive data");
    data->sak = sak;
}

Iso14443_4aData *iso14443_4a_alloc(void) {
    Iso14443_4aData *data = malloc(sizeof(*data));

    expect(data != NULL, "iso14443_4a allocation should succeed");
    memset(data, 0, sizeof(*data));
    data->iso14443_3a_data = malloc(sizeof(*data->iso14443_3a_data));
    expect(data->iso14443_3a_data != NULL, "iso14443_4a base allocation should succeed");
    memset(data->iso14443_3a_data, 0, sizeof(*data->iso14443_3a_data));
    data->ats_data.t1_tk = simple_array_alloc(&simple_array_config_uint8_t);
    return data;
}

void iso14443_4a_free(Iso14443_4aData *data) {
    if (data) {
        simple_array_free(data->ats_data.t1_tk);
        free(data->iso14443_3a_data);
        free(data);
    }
}

void iso14443_4a_reset(Iso14443_4aData *data) {
    expect(data != NULL, "iso14443_4a_reset should receive data");
    memset(data->iso14443_3a_data, 0, sizeof(*data->iso14443_3a_data));
    data->ats_data.tl = 1;
    data->ats_data.t0 = 0;
    data->ats_data.ta_1 = 0;
    data->ats_data.tb_1 = 0;
    data->ats_data.tc_1 = 0;
    simple_array_reset(data->ats_data.t1_tk);
}

void iso14443_4a_set_uid(Iso14443_4aData *data, const uint8_t *uid, size_t uid_len) {
    expect(data != NULL, "iso14443_4a_set_uid should receive data");
    expect(uid_len <= sizeof(data->iso14443_3a_data->uid),
           "iso14443_4a uid should fit the test stub");
    memcpy(data->iso14443_3a_data->uid, uid, uid_len);
    data->iso14443_3a_data->uid_len = (uint8_t)uid_len;
}

const uint8_t *iso14443_4a_get_uid(const Iso14443_4aData *data, size_t *uid_len) {
    expect(data != NULL, "iso14443_4a_get_uid should receive data");
    expect(uid_len != NULL, "iso14443_4a_get_uid should receive a length pointer");
    *uid_len = data->iso14443_3a_data->uid_len;
    return data->iso14443_3a_data->uid;
}

Iso14443_3aData *iso14443_4a_get_base_data(Iso14443_4aData *data) {
    expect(data != NULL, "iso14443_4a_get_base_data should receive data");
    return data->iso14443_3a_data;
}

SimpleArray *simple_array_alloc(const SimpleArrayConfig *config) {
    SimpleArray *instance = malloc(sizeof(*instance));

    expect(instance != NULL, "simple_array allocation should succeed");
    instance->config = config;
    instance->data = NULL;
    instance->count = 0;
    return instance;
}

void simple_array_free(SimpleArray *instance) {
    if (instance) {
        free(instance->data);
        free(instance);
    }
}

void simple_array_init(SimpleArray *instance, uint32_t count) {
    expect(instance != NULL, "simple_array_init should receive an instance");
    free(instance->data);
    instance->data = NULL;
    instance->count = count;
    if (count == 0) {
        return;
    }
    instance->data = calloc(count, instance->config->type_size);
    expect(instance->data != NULL, "simple_array_init should allocate backing storage");
}

void simple_array_reset(SimpleArray *instance) {
    expect(instance != NULL, "simple_array_reset should receive an instance");
    free(instance->data);
    instance->data = NULL;
    instance->count = 0;
}

void simple_array_copy(SimpleArray *instance, const SimpleArray *other) {
    expect(instance != NULL, "simple_array_copy should receive a destination");
    expect(other != NULL, "simple_array_copy should receive a source");
    simple_array_init(instance, other->count);
    if (other->count != 0) {
        memcpy(instance->data, other->data, other->count * instance->config->type_size);
    }
}

bool simple_array_is_equal(const SimpleArray *instance, const SimpleArray *other) {
    if (instance == other) {
        return true;
    }
    if (!instance || !other || instance->count != other->count) {
        return false;
    }
    return instance->count == 0 ||
           memcmp(instance->data, other->data, instance->count * instance->config->type_size) == 0;
}

uint32_t simple_array_get_count(const SimpleArray *instance) {
    expect(instance != NULL, "simple_array_get_count should receive an instance");
    return instance->count;
}

SimpleArrayElement *simple_array_get(SimpleArray *instance, uint32_t index) {
    expect(instance != NULL, "simple_array_get should receive an instance");
    expect(index < instance->count, "simple_array_get index should be in range");
    return &instance->data[index * instance->config->type_size];
}

const SimpleArrayElement *simple_array_cget(const SimpleArray *instance, uint32_t index) {
    expect(instance != NULL, "simple_array_cget should receive an instance");
    expect(index < instance->count, "simple_array_cget index should be in range");
    return &instance->data[index * instance->config->type_size];
}

SimpleArrayData *simple_array_get_data(SimpleArray *instance) {
    expect(instance != NULL, "simple_array_get_data should receive an instance");
    return instance->data;
}

const SimpleArrayData *simple_array_cget_data(const SimpleArray *instance) {
    expect(instance != NULL, "simple_array_cget_data should receive an instance");
    return instance->data;
}

static TestStorageFile *test_storage_file_slot(const char *path, bool create) {
    size_t free_index = SIZE_MAX;

    for (size_t i = 0; i < (sizeof(g_storage_files) / sizeof(g_storage_files[0])); ++i) {
        if (g_storage_files[i].in_use && strcmp(g_storage_files[i].path, path) == 0) {
            return &g_storage_files[i];
        }
        if (create && free_index == SIZE_MAX && !g_storage_files[i].in_use) {
            free_index = i;
        }
    }

    if (!create || free_index == SIZE_MAX) {
        return NULL;
    }

    g_storage_files[free_index].in_use = true;
    strncpy(g_storage_files[free_index].path, path, sizeof(g_storage_files[free_index].path) - 1);
    g_storage_files[free_index].path[sizeof(g_storage_files[free_index].path) - 1] = '\0';
    return &g_storage_files[free_index];
}

bool file_info_is_dir(const FileInfo *info) {
    UNUSED(info);
    return false;
}

FS_Error storage_common_remove(Storage *storage, const char *path) {
    TestStorageFile *slot = NULL;

    UNUSED(storage);
    slot = test_storage_file_slot(path, false);
    if (!slot || !slot->exists) {
        return FSE_NOT_EXIST;
    }

    slot->exists = false;
    slot->size = 0;
    memset(slot->data, 0, sizeof(slot->data));
    return FSE_OK;
}

FS_Error storage_common_rename(Storage *storage, const char *old_path, const char *new_path) {
    TestStorageFile *old_slot = NULL;
    TestStorageFile *new_slot = NULL;

    UNUSED(storage);
    old_slot = test_storage_file_slot(old_path, false);
    new_slot = test_storage_file_slot(new_path, true);
    if (!old_slot || !new_slot || !old_slot->exists) {
        return FSE_NOT_EXIST;
    }

    memcpy(new_slot->data, old_slot->data, old_slot->size);
    new_slot->size = old_slot->size;
    new_slot->exists = true;
    old_slot->exists = false;
    old_slot->size = 0;
    memset(old_slot->data, 0, sizeof(old_slot->data));
    return FSE_OK;
}

bool storage_dir_exists(Storage *storage, const char *path) {
    UNUSED(storage);
    if (strcmp(path, "/ext/apps_data") == 0) {
        return g_storage_root_exists;
    }
    if (strcmp(path, "/ext/apps_data/zerofido") == 0) {
        return g_storage_app_data_exists;
    }
    return false;
}

bool storage_simply_mkdir(Storage *storage, const char *path) {
    UNUSED(storage);
    if (strcmp(path, "/ext/apps_data") == 0) {
        g_storage_root_exists = true;
        return true;
    }
    if (strcmp(path, "/ext/apps_data/zerofido") == 0) {
        g_storage_app_data_exists = true;
        return true;
    }
    return false;
}

bool storage_dir_open(File *file, const char *path) {
    UNUSED(file);
    UNUSED(path);
    return false;
}

bool storage_dir_read(File *file, FileInfo *info, char *name, size_t name_size) {
    UNUSED(file);
    UNUSED(info);
    UNUSED(name);
    UNUSED(name_size);
    return false;
}

void storage_dir_close(File *file) {
    UNUSED(file);
}

File *storage_file_alloc(Storage *storage) {
    static File files[2];
    static size_t next_file = 0;
    File *file = NULL;

    UNUSED(storage);
    file = &files[next_file++ % (sizeof(files) / sizeof(files[0]))];
    memset(file, 0, sizeof(*file));
    return file;
}

void storage_file_free(File *file) {
    UNUSED(file);
}

bool storage_file_open(File *file, const char *path, FS_AccessMode access_mode,
                       FS_OpenMode open_mode) {
    TestStorageFile *slot = NULL;

    if (strncmp(path, "/ext/apps_data/zerofido/", strlen("/ext/apps_data/zerofido/")) == 0 &&
        !g_storage_app_data_exists) {
        return false;
    }

    slot =
        test_storage_file_slot(path, access_mode == FSAM_WRITE && open_mode == FSOM_CREATE_ALWAYS);
    if (!slot) {
        return false;
    }
    if (access_mode == FSAM_READ && (!slot->exists || open_mode != FSOM_OPEN_EXISTING)) {
        return false;
    }
    if (access_mode == FSAM_WRITE && open_mode == FSOM_CREATE_ALWAYS) {
        slot->size = 0;
        slot->exists = true;
        memset(slot->data, 0, sizeof(slot->data));
    }

    strncpy(file->path, path, sizeof(file->path) - 1);
    file->path[sizeof(file->path) - 1] = '\0';
    file->access_mode = access_mode;
    file->offset = 0;
    file->open = true;
    return true;
}

size_t storage_file_size(File *file) {
    TestStorageFile *slot = NULL;

    if (!file->open) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, false);
    if (!slot || !slot->exists) {
        return 0;
    }
    return slot->size;
}

size_t storage_file_read(File *file, void *buffer, size_t size) {
    TestStorageFile *slot = NULL;
    size_t remaining = 0;

    if (!file->open || file->access_mode != FSAM_READ) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, false);
    if (!slot || !slot->exists || file->offset >= slot->size) {
        return 0;
    }

    remaining = slot->size - file->offset;
    if (size > remaining) {
        size = remaining;
    }
    memcpy(buffer, slot->data + file->offset, size);
    file->offset += size;
    return size;
}

size_t storage_file_write(File *file, const void *buffer, size_t size) {
    TestStorageFile *slot = NULL;

    if (!file->open || file->access_mode != FSAM_WRITE) {
        return 0;
    }
    if (g_storage_fail_write_match && strstr(file->path, g_storage_fail_write_match) != NULL) {
        return 0;
    }
    slot = test_storage_file_slot(file->path, true);
    if (!slot || (file->offset + size) > sizeof(slot->data)) {
        return 0;
    }

    memcpy(slot->data + file->offset, buffer, size);
    file->offset += size;
    if (file->offset > slot->size) {
        slot->size = file->offset;
    }
    slot->exists = true;
    return size;
}

void storage_file_close(File *file) {
    file->open = false;
}

FlipperFormat *flipper_format_file_alloc(Storage *storage) {
    static FlipperFormat flipper_format;

    UNUSED(storage);
    return &flipper_format;
}

void flipper_format_free(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
}

bool flipper_format_file_open_always(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_open_existing(FlipperFormat *flipper_format, const char *path) {
    UNUSED(flipper_format);
    UNUSED(path);
    return false;
}

bool flipper_format_file_close(FlipperFormat *flipper_format) {
    UNUSED(flipper_format);
    return true;
}

bool flipper_format_write_header_cstr(FlipperFormat *flipper_format, const char *type,
                                      uint32_t version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_write_uint32(FlipperFormat *flipper_format, const char *key,
                                 const uint32_t *value, size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_write_hex(FlipperFormat *flipper_format, const char *key, const uint8_t *value,
                              size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

bool flipper_format_read_header(FlipperFormat *flipper_format, FuriString *type,
                                uint32_t *version) {
    UNUSED(flipper_format);
    UNUSED(type);
    UNUSED(version);
    return false;
}

bool flipper_format_read_uint32(FlipperFormat *flipper_format, const char *key, uint32_t *value,
                                size_t count) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(count);
    return false;
}

bool flipper_format_read_hex(FlipperFormat *flipper_format, const char *key, uint8_t *value,
                             size_t size) {
    UNUSED(flipper_format);
    UNUSED(key);
    UNUSED(value);
    UNUSED(size);
    return false;
}

FuriString *furi_string_alloc(void) {
    static FuriString string;

    memset(&string, 0, sizeof(string));
    return &string;
}

void furi_string_free(FuriString *string) {
    UNUSED(string);
}

const char *furi_string_get_cstr(const FuriString *string) {
    return string ? string->value : "";
}

const FuriHalUsbInterface usb_hid_u2f = {0};

size_t furi_hal_hid_u2f_get_request(uint8_t *packet) {
    size_t packet_len = 0;

    if (g_hid_request_index >= g_hid_request_count) {
        return 0;
    }

    packet_len = g_hid_request_packet_lens[g_hid_request_index];
    memcpy(packet, g_hid_request_packets[g_hid_request_index], packet_len);
    g_hid_request_index++;
    return packet_len;
}

void furi_hal_hid_u2f_send_response(const uint8_t *packet, size_t packet_len) {
    expect(packet_len <= sizeof(g_last_hid_response), "response frame should fit native capture");
    memcpy(g_last_hid_response, packet, packet_len);
    g_last_hid_response_len = packet_len;
    g_hid_response_count++;
}

void furi_hal_hid_u2f_set_callback(HidU2fCallback callback, void *context) {
    UNUSED(callback);
    UNUSED(context);
}

bool furi_hal_hid_u2f_is_connected(void) {
    return g_hid_connected;
}

FuriHalUsbInterface *furi_hal_usb_get_config(void) {
    return &g_previous_usb_config;
}

bool furi_hal_usb_set_config(const FuriHalUsbInterface *interface, void *context) {
    UNUSED(context);
    g_usb_set_config_count++;
    g_last_usb_set_config = interface;
    return g_usb_set_config_result;
}

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, uint32_t event) {
    UNUSED(app);
    UNUSED(event);
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *status) {
    UNUSED(app);
    if (status) {
        snprintf(g_last_status_text, sizeof(g_last_status_text), "%s", status);
    }
}

bool zerofido_ui_cancel_pending_interaction(ZerofidoApp *app) {
    UNUSED(app);
    g_cancel_pending_interaction_count++;
    return g_cancel_pending_interaction_result;
}

bool zerofido_ui_cancel_pending_interaction_locked(ZerofidoApp *app) {
    return zerofido_ui_cancel_pending_interaction(app);
}

void zerofido_ui_set_status_locked(ZerofidoApp *app, const char *status) {
    zerofido_ui_set_status(app, status);
}

void zerofido_ui_refresh_status(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_refresh_status_line(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_refresh_credentials_status(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected) {
    UNUSED(app);
    g_transport_connected_set_count++;
    if (connected) {
        g_transport_connected_true_count++;
    }
    g_last_transport_connected = connected;
}

void zerofido_notify_reset(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_error(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_success(ZerofidoApp *app) {
    UNUSED(app);
}

void zerofido_notify_prompt(ZerofidoApp *app) {
    UNUSED(app);
    g_notify_prompt_count++;
}

void zerofido_notify_wink(ZerofidoApp *app) {
    UNUSED(app);
}

bool zerofido_ui_request_approval(ZerofidoApp *app, ZfUiProtocol protocol, const char *operation,
                                  const char *rp_id, const char *user_text, uint32_t cid,
                                  bool *approved) {
    UNUSED(protocol);
    UNUSED(operation);
    UNUSED(rp_id);
    UNUSED(user_text);
    UNUSED(cid);
    if (g_auto_accept_requests || test_transport_auto_accept_enabled(app)) {
        if (approved) {
            *approved = true;
        }
        return true;
    }
    g_approval_request_count++;
    if (approved) {
        *approved = true;
    }
    return true;
}

const uint8_t *zf_attestation_get_leaf_cert_der(size_t *out_len) {
    static const uint8_t cert[] = {0x30};
    if (out_len) {
        *out_len = sizeof(cert);
    }
    return cert;
}

const uint8_t *zf_attestation_get_leaf_private_key(void) {
    static const uint8_t cert_key[32] = {0};
    return cert_key;
}

const uint8_t *zf_attestation_get_aaguid(void) {
    static const uint8_t aaguid[ZF_AAGUID_LEN] = {
        0xB5, 0x1A, 0x97, 0x6A, 0x0B, 0x02, 0x40, 0xAA,
        0x9D, 0x8A, 0x36, 0xC8, 0xB9, 0x1B, 0xBD, 0x1A,
    };
    return aaguid;
}

void zf_crypto_secure_zero(void *data, size_t size) {
    memset(data, 0, size);
}

void zf_crypto_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
    if (size > 0U) {
        expect(data != NULL, "sha256 input should be present when size is non-zero");
        expect(g_sha256_trace_len + size <= sizeof(g_sha256_trace),
               "sha256 trace buffer should fit");
        memcpy(&g_sha256_trace[g_sha256_trace_len], data, size);
        g_sha256_trace_len += size;
    }
    memset(out, 0, 32);
}

bool zf_crypto_hmac_sha256_parts_with_scratch(ZfHmacSha256Scratch *scratch, const uint8_t *key,
                                              size_t key_len, const uint8_t *first,
                                              size_t first_size, const uint8_t *second,
                                              size_t second_size, uint8_t out[32]) {
    uint8_t key_block[64] = {0};
    uint8_t inner_hash[32] = {0};
    uint8_t pad[64] = {0};
    mbedtls_sha256_context sha;

    UNUSED(scratch);
    if (!key || !out || (first_size > 0U && !first) || (second_size > 0U && !second)) {
        return false;
    }

    if (key_len > sizeof(key_block)) {
        mbedtls_sha256_init(&sha);
        mbedtls_sha256_starts(&sha, 0);
        mbedtls_sha256_update(&sha, key, key_len);
        mbedtls_sha256_finish(&sha, key_block);
        mbedtls_sha256_free(&sha);
    } else if (key_len > 0U) {
        memcpy(key_block, key, key_len);
    }

    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = key_block[i] ^ 0x36U;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, pad, sizeof(pad));
    if (first_size > 0U) {
        mbedtls_sha256_update(&sha, first, first_size);
    }
    if (second_size > 0U) {
        mbedtls_sha256_update(&sha, second, second_size);
    }
    mbedtls_sha256_finish(&sha, inner_hash);
    mbedtls_sha256_free(&sha);

    for (size_t i = 0; i < sizeof(pad); ++i) {
        pad[i] = key_block[i] ^ 0x5CU;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, pad, sizeof(pad));
    mbedtls_sha256_update(&sha, inner_hash, sizeof(inner_hash));
    mbedtls_sha256_finish(&sha, out);
    mbedtls_sha256_free(&sha);

    return true;
}

bool zf_crypto_hmac_sha256_parts(const uint8_t *key, size_t key_len, const uint8_t *first,
                                 size_t first_size, const uint8_t *second, size_t second_size,
                                 uint8_t out[32]) {
    ZfHmacSha256Scratch scratch;

    return zf_crypto_hmac_sha256_parts_with_scratch(&scratch, key, key_len, first, first_size,
                                                    second, second_size, out);
}

bool zf_crypto_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t size,
                           uint8_t out[32]) {
    return zf_crypto_hmac_sha256_parts(key, key_len, data, size, NULL, 0, out);
}

size_t zerofido_handle_ctap2(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                             size_t request_len, uint8_t *response, size_t response_capacity) {
    UNUSED(cid);
    if (!request || request_len == 0 || !response || response_capacity < 2) {
        return 0;
    }

    g_ctap2_request_response_overlap = request == response;
    if (request[0] == ZfCtapeCmdGetInfo) {
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA0;
        return 2;
    }
    if (request[0] == ZfCtapeCmdMakeCredential) {
        g_ctap2_saw_transport_auto_accept = test_transport_auto_accept_enabled(app);
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA0;
        return 2;
    }
    if (request[0] == ZfCtapeCmdClientPin) {
        g_ctap2_saw_transport_auto_accept = test_transport_auto_accept_enabled(app);
        if (g_ctap2_large_response_len != 0U) {
            const size_t response_len = g_ctap2_large_response_len < response_capacity
                                            ? g_ctap2_large_response_len
                                            : response_capacity;
            for (size_t i = 0U; i < response_len; ++i) {
                response[i] = (uint8_t)(0xA0U + (i & 0x0FU));
            }
            response[0] = ZF_CTAP_SUCCESS;
            response[1] = 0xA1U;
            return response_len;
        }
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA1;
        return 2;
    }

    return 0;
}

bool u2f_data_check(bool cert_only) {
    UNUSED(cert_only);
    return g_u2f_cert_assets_present;
}

bool u2f_data_cert_check(void) {
    return g_u2f_cert_assets_present && g_u2f_cert_check_result;
}

uint32_t u2f_data_cert_load(uint8_t *cert, size_t capacity) {
    if (capacity > 0) {
        cert[0] = 0;
        return 1;
    }

    return 0;
}

bool u2f_data_cert_key_load(uint8_t *cert_key) {
    if (!g_u2f_cert_assets_present || !g_u2f_cert_key_load_result) {
        memset(cert_key, 0, 32);
        return false;
    }
    memset(cert_key, 0, 32);
    return true;
}

bool u2f_data_cert_key_matches(const uint8_t *cert_key) {
    UNUSED(cert_key);
    return g_u2f_cert_key_matches_result;
}

bool u2f_data_ensure_local_attestation_assets(void) {
    g_u2f_attestation_ensure_call_count++;
    if (!g_u2f_attestation_ensure_result) {
        return false;
    }
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    return true;
}

bool u2f_data_generate_attestation_assets(void) {
    return u2f_data_ensure_local_attestation_assets();
}

bool u2f_data_key_exists(void) {
    return g_u2f_key_exists_result;
}

bool u2f_data_key_load(uint8_t *device_key) {
    memset(device_key, 0, 32);
    return g_u2f_key_load_result;
}

bool u2f_data_key_generate(uint8_t *device_key) {
    g_u2f_key_generate_count++;
    memset(device_key, 0, 32);
    return true;
}

bool u2f_data_cnt_exists(void) {
    return g_u2f_cnt_exists_result;
}

bool u2f_data_cnt_read(uint32_t *cnt) {
    *cnt = 0;
    return g_u2f_cnt_read_result;
}

bool u2f_data_cnt_write(uint32_t cnt) {
    g_u2f_cnt_write_count++;
    g_u2f_last_written_counter = cnt;
    return true;
}

bool u2f_data_cnt_reserve(uint32_t cnt, uint32_t *reserved_cnt) {
    g_u2f_cnt_reserve_count++;
    g_u2f_last_reserved_counter = cnt + ZF_COUNTER_RESERVATION_WINDOW;
    if (reserved_cnt) {
        *reserved_cnt = g_u2f_last_reserved_counter;
    }
    return true;
}

bool zf_crypto_p256_private_key_valid(const uint8_t private_key[ZF_PRIVATE_KEY_LEN]) {
    return private_key != NULL;
}

bool zf_crypto_p256_public_key_valid(const uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                     const uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    return public_x != NULL && public_y != NULL;
}

bool zf_crypto_compute_public_key_from_private(const uint8_t private_key[ZF_PRIVATE_KEY_LEN],
                                               uint8_t public_x[ZF_PUBLIC_KEY_LEN],
                                               uint8_t public_y[ZF_PUBLIC_KEY_LEN]) {
    UNUSED(private_key);
    if (!public_x || !public_y) {
        return false;
    }
    memset(public_x, 0x11, ZF_PUBLIC_KEY_LEN);
    memset(public_y, 0x22, ZF_PUBLIC_KEY_LEN);
    return true;
}

bool zf_crypto_sign_hash_raw(const uint8_t private_key[ZF_PRIVATE_KEY_LEN], const uint8_t hash[32],
                             uint8_t out[ZF_PUBLIC_KEY_LEN * 2U]) {
    UNUSED(private_key);
    UNUSED(hash);
    if (!out) {
        return false;
    }
    memset(out, 0x01, ZF_PUBLIC_KEY_LEN * 2U);
    return true;
}

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp) {
    UNUSED(grp);
}

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp) {
    UNUSED(grp);
}

int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, int id) {
    UNUSED(grp);
    UNUSED(id);
    return 0;
}

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt) {
    memset(pt, 0, sizeof(*pt));
}

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt) {
    UNUSED(pt);
}

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *r, const mbedtls_mpi *m,
                    const mbedtls_ecp_point *p, int (*f_rng)(void *, unsigned char *, unsigned int),
                    void *p_rng) {
    UNUSED(grp);
    UNUSED(r);
    UNUSED(m);
    UNUSED(p);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp, const mbedtls_mpi *d) {
    UNUSED(grp);
    UNUSED(d);
    return 0;
}

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt) {
    UNUSED(grp);
    UNUSED(pt);
    return 0;
}

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                   int format, size_t *olen, unsigned char *buf, size_t buflen) {
    UNUSED(grp);
    UNUSED(pt);
    UNUSED(format);
    if (buflen > 0) {
        memset(buf, 0, buflen);
        buf[0] = 0x04;
    }
    *olen = buflen;
    return 0;
}

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *q,
                            int (*f_rng)(void *, unsigned char *, unsigned int), void *p_rng) {
    UNUSED(grp);
    UNUSED(d);
    UNUSED(q);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_mpi_read_binary(mbedtls_mpi *x, const unsigned char *buf, size_t buflen) {
    UNUSED(x);
    UNUSED(buf);
    UNUSED(buflen);
    return 0;
}

int mbedtls_mpi_write_binary(const mbedtls_mpi *x, unsigned char *buf, size_t buflen) {
    UNUSED(x);
    memset(buf, 0, buflen);
    return 0;
}

int mbedtls_mpi_lset(mbedtls_mpi *x, int z) {
    UNUSED(x);
    UNUSED(z);
    return 0;
}

void mbedtls_mpi_init(mbedtls_mpi *x) {
    memset(x, 0, sizeof(*x));
}

void mbedtls_mpi_free(mbedtls_mpi *x) {
    UNUSED(x);
}

int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s, const mbedtls_mpi *d,
                       const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, unsigned), void *p_rng) {
    UNUSED(grp);
    UNUSED(r);
    UNUSED(s);
    UNUSED(d);
    UNUSED(buf);
    UNUSED(blen);
    UNUSED(f_rng);
    UNUSED(p_rng);
    return 0;
}

int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp, const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *q, const mbedtls_mpi *r, const mbedtls_mpi *s) {
    UNUSED(grp);
    UNUSED(buf);
    UNUSED(blen);
    UNUSED(q);
    UNUSED(r);
    UNUSED(s);
    return 0;
}

void mbedtls_md_init(mbedtls_md_context_t *ctx) {
    UNUSED(ctx);
}

void mbedtls_md_free(mbedtls_md_context_t *ctx) {
    UNUSED(ctx);
}

const mbedtls_md_info_t *mbedtls_md_info_from_type(int md_type) {
    static const mbedtls_md_info_t info = {0};
    UNUSED(md_type);
    return &info;
}

int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac) {
    UNUSED(ctx);
    UNUSED(md_info);
    UNUSED(hmac);
    return 0;
}

int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen) {
    UNUSED(ctx);
    UNUSED(key);
    UNUSED(keylen);
    return 0;
}

int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen) {
    UNUSED(ctx);
    UNUSED(input);
    UNUSED(ilen);
    return 0;
}

int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output) {
    UNUSED(ctx);
    memset(output, 0, 32);
    return 0;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    UNUSED(ctx);
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    UNUSED(ctx);
}

void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    UNUSED(ctx);
    UNUSED(is224);
}

void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {
    UNUSED(ctx);
    expect(g_sha256_trace_len + ilen <= sizeof(g_sha256_trace), "sha256 trace buffer should fit");
    memcpy(&g_sha256_trace[g_sha256_trace_len], input, ilen);
    g_sha256_trace_len += ilen;
}

void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32]) {
    UNUSED(ctx);
    memset(output, 0, 32);
}

#include "../src/u2f/apdu.c"
#include "../src/u2f/response_encode.c"
#include "../src/u2f/session.c"

#include "../src/transport/adapter.c"
#include "../src/zerofido_storage.c"
#include "../src/zerofido_runtime_config.c"
#include "../src/u2f/adapter.c"
#include "../src/transport/dispatch.c"
#include "../src/transport/usb_hid_session.c"
#include "../src/transport/usb_hid_worker.c"
#include "../src/transport/nfc_trace.c"
#include "../src/transport/nfc_protocol.c"
#include "../src/transport/nfc_iso_dep.c"
#include "../src/transport/nfc_session.c"
#include "../src/transport/nfc_dispatch.c"
#include "../src/transport/nfc_engine.c"
#include "../src/transport/nfc_worker.c"

static bool test_transport_auto_accept_enabled(const ZerofidoApp *app) {
    return app && app->transport_auto_accept_transaction;
}

uint8_t zf_ctap_build_get_info_response(const ZfResolvedCapabilities *capabilities,
                                        bool client_pin_set, uint8_t *out, size_t out_capacity,
                                        size_t *out_len) {
    UNUSED(client_pin_set);
    g_get_info_builder_called = true;
    g_get_info_builder_saw_nfc_transport =
        capabilities && capabilities->nfc_enabled && capabilities->advertise_nfc_transport;
    g_get_info_builder_saw_usb_transport =
        capabilities && capabilities->usb_hid_enabled && capabilities->advertise_usb_transport;
    expect(out != NULL && out_capacity > 0 && out_len != NULL,
           "test GetInfo builder should receive an output buffer");
    out[0] = 0xA0;
    *out_len = 1U;
    return ZF_CTAP_SUCCESS;
}

bool zerofido_pin_is_set(const ZfClientPinState *state) {
    return state && state->pin_set;
}

static size_t test_nfc_payload_len(void) {
    expect(g_last_nfc_tx_len >= 3, "nfc frame should include pcb and crc");
    return g_last_nfc_tx_len - 3;
}

static const uint8_t *test_nfc_payload(void) {
    expect(g_last_nfc_tx_len >= 3, "nfc frame should include pcb and crc");
    return &g_last_nfc_tx[1];
}

static void test_nfc_init_app(ZerofidoApp *app, FuriMutex *mutex) {
    memset(app, 0, sizeof(*app));
    app->ui_mutex = mutex;
    app->transport_adapter = &zf_transport_nfc_adapter;
    app->transport_state = &app->transport_nfc_state_storage;
    app->worker_thread = &g_nfc_worker_thread;
    app->transport_nfc_state_storage.nfc = nfc_alloc();
    app->transport_nfc_state_storage.tx_buffer = bit_buffer_alloc(320U);
    app->transport_nfc_state_storage.iso14443_4a_data = iso14443_4a_alloc();
    expect(zf_app_transport_arena_acquire(app), "NFC test app should allocate transport arena");
    zf_transport_nfc_attach_arena(&app->transport_nfc_state_storage, app->transport_arena,
                                  zf_app_transport_arena_capacity(app));
    zf_transport_nfc_prepare_listener(&app->transport_nfc_state_storage);
    app->transport_nfc_state_storage.listener_active = true;
}

static void test_nfc_deinit_app(ZerofidoApp *app);

static void test_nfc_listener_profile_is_valid_iso14443_4a(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    const Iso14443_3aData *base = NULL;
    const Iso14443_4aAtsData *ats = NULL;
    test_reset();
    test_nfc_init_app(&app, &mutex);

    base = app.transport_nfc_state_storage.iso14443_4a_data->iso14443_3a_data;
    ats = &app.transport_nfc_state_storage.iso14443_4a_data->ats_data;

    expect(base->uid_len == 7, "nfc listener should expose a double-size UID");
    expect(memcmp(base->uid, (const uint8_t[]){0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6}, 7) == 0,
           "nfc listener UID should remain stable across the SoloKey-style NFC profile");
    expect(base->atqa[0] == 0x44 && base->atqa[1] == 0x00,
           "nfc listener should expose a double-size ISO-DEP ATQA");
    expect(base->sak == 0x20, "nfc listener should advertise ISO-DEP without MIFARE Classic");
    expect(ats->tl == 0x05, "nfc listener should expose the Nitrokey-style ATS length");
    expect(ats->t0 == 0x78, "nfc listener should advertise the iOS-compatible FSC ATS format byte");
    expect(ats->ta_1 == 0x91, "nfc listener should expose ATS TA1 from the Nitrokey profile");
    expect(ats->tb_1 == 0xE8, "nfc listener should expose ATS TB1 with long FWT for CTAP2");
    expect(ats->tc_1 == 0x00, "nfc listener should expose ATS TC1 from the Nitrokey profile");
    expect(simple_array_get_count(ats->t1_tk) == 0,
           "nfc listener should not include ATS historical bytes");

    test_nfc_deinit_app(&app);
}

static void test_nfc_deinit_app(ZerofidoApp *app) {
    iso14443_4a_free(app->transport_nfc_state_storage.iso14443_4a_data);
    bit_buffer_free(app->transport_nfc_state_storage.tx_buffer);
    nfc_free(app->transport_nfc_state_storage.nfc);
    zf_app_transport_arena_release(app);
}

static void test_nfc_select_applet(ZerofidoApp *app) {
    static const uint8_t select_apdu[] = {
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
    };

    expect(zf_transport_nfc_handle_apdu(app, &app->transport_nfc_state_storage, select_apdu,
                                        sizeof(select_apdu)),
           "FIDO applet SELECT should be accepted");
    expect(app->transport_nfc_state_storage.applet_selected,
           "SELECT should mark the FIDO applet as selected");
}

static void test_nfc_select_applet_accepts_p2_no_fci(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t select_apdu[] = {
        0x00, 0xA4, 0x04, 0x0C, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, select_apdu,
                                        sizeof(select_apdu)),
           "FIDO applet SELECT should accept P2=0x0C without FCI");
    expect(app.transport_nfc_state_storage.applet_selected,
           "SELECT with P2=0x0C should mark the FIDO applet as selected");

    test_nfc_deinit_app(&app);
}

static void test_nfc_select_applet_returns_fido2_version_when_u2f_disabled(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    const uint8_t *payload = NULL;
    static const uint8_t select_apdu[] = {
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.runtime_config.transport_mode = ZfTransportModeNfc;
    app.runtime_config.u2f_enabled = false;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, select_apdu,
                                        sizeof(select_apdu)),
           "FIDO2-only applet SELECT should be accepted");
    expect(app.transport_nfc_state_storage.applet_selected,
           "FIDO2-only SELECT should mark the FIDO applet as selected");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 10U && memcmp(payload, "FIDO_2_0", 8) == 0 &&
               payload[8] == 0x90 && payload[9] == 0x00,
           "FIDO2-only SELECT should return FIDO_2_0 plus SW_SUCCESS");

    test_nfc_deinit_app(&app);
}

static void test_nfc_select_applet_accepts_le_and_legacy_nine_byte_aid(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t select_with_le[] = {
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00,
    };
    static const uint8_t select_lc9[] = {
        0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, select_with_le,
                                        sizeof(select_with_le)),
           "FIDO applet SELECT should accept canonical Le=0");
    expect(app.transport_nfc_state_storage.applet_selected,
           "SELECT with Le=0 should mark the FIDO applet as selected");
    expect(test_log_contains("FIDO SELECT"), "SELECT with Le=0 should expose the FIDO breadcrumb");
    expect(g_last_status_text[0] == '\0', "SELECT diagnostic should not update UI status");

    app.transport_nfc_state_storage.applet_selected = false;
    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, select_lc9,
                                        sizeof(select_lc9)),
           "FIDO applet SELECT should accept legacy Lc=9 AID-plus-zero form");
    expect(app.transport_nfc_state_storage.applet_selected,
           "legacy Lc=9 SELECT should mark the FIDO applet as selected");

    test_nfc_deinit_app(&app);
}

static void test_nfc_event_callback_accepts_bare_select_apdu(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06,
                                              0x47, 0x2F, 0x00, 0x01},
                            13U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "bare SELECT APDU should be accepted through the NFC listener callback");
    expect(app.transport_nfc_state_storage.applet_selected,
           "bare SELECT APDU should select the FIDO applet");
    expect(g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 &&
               memcmp(&g_last_nfc_tx[1], "U2F_V2", 6) == 0 && g_last_nfc_tx[7] == 0x90 &&
               g_last_nfc_tx[8] == 0x00,
           "bare SELECT APDU should still return U2F_V2 plus SW_SUCCESS inside an I-block");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_event_decodes_block_and_sends_framed_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "ISO14443-4A listener event should decode ISO-DEP blocks before APDU dispatch");
    expect(app.transport_nfc_state_storage.applet_selected,
           "decoded APDU SELECT should select the FIDO applet");
    expect(g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 &&
               memcmp(&g_last_nfc_tx[1], "U2F_V2", 6) == 0 && g_last_nfc_tx[7] == 0x90 &&
               g_last_nfc_tx[8] == 0x00,
           "decoded APDU SELECT should send a framed ISO-DEP response through the backport");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_raw60_returns_unsupported_via_send_block(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "decoded native DESFire GetVersion should receive an unsupported status");
    expect(g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 && g_last_nfc_tx[1] == 0xAF &&
               g_last_nfc_tx[2] == 0x04 && g_last_nfc_tx[8] == 0x05,
           "decoded native DESFire GetVersion should send status-first native version data");
    expect(test_log_contains("DESFire native version"),
           "decoded native DESFire GetVersion should expose the classifier breadcrumb");
    expect(g_last_status_text[0] == '\0',
           "decoded native DESFire diagnostic should not update UI status");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_native_desfire_payload_is_not_parsed_as_apdu(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02, 0x60}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "native DESFire payload inside an I-block should receive an unsupported status");
    expect(
        g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 && g_last_nfc_tx[1] == 0xAF &&
            g_last_nfc_tx[2] == 0x04 && g_last_nfc_tx[8] == 0x05,
        "native DESFire payload inside an I-block should return status-first native version data");
    expect(test_log_contains("DESFire native version"),
           "native DESFire payload inside an I-block should not fall through to APDU 6700");
    expect(g_last_status_text[0] == '\0',
           "native DESFire payload diagnostic should not update UI status");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "native DESFire payload inside an I-block should leave the FIDO applet unselected");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_desfire_deselect_sleeps_before_next_activation(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData iso4_data = {.buffer = buffer};
    Iso14443_4aListenerEvent iso4_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &iso4_data,
    };
    Iso14443_3aListenerEventData iso3_data = {.buffer = buffer};
    Iso14443_3aListenerEvent iso3_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &iso3_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &iso4_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02, 0x60}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "DESFire discovery should receive the native version shim");
    expect(g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 && g_last_nfc_tx[1] == 0xAF,
           "DESFire discovery should transmit the working native response");
    expect(app.transport_nfc_state_storage.iso4_last_tx_valid &&
               app.transport_nfc_state_storage.iso4_last_tx_len > 0U,
           "DESFire discovery response should be cached before deselect");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xC2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "DESFire S-DESELECT should sleep the current activation after ACKing");
    expect(g_last_nfc_tx_len == 3U && g_last_nfc_tx[0] == 0xC2U,
           "DESFire S-DESELECT should still receive the ISO-DEP deselect response");
    expect(!app.transport_nfc_state_storage.iso4_active &&
               !app.transport_nfc_state_storage.applet_selected,
           "DESFire S-DESELECT should clear ISO-DEP state before the next activation");
    expect(!app.transport_nfc_state_storage.iso4_last_tx_valid &&
               app.transport_nfc_state_storage.iso4_last_tx_len == 0U,
           "DESFire S-DESELECT should clear stale replay state before the next activation");
    expect(!zf_transport_nfc_replay_last_iso_response(&app.transport_nfc_state_storage),
           "DESFire S-DESELECT should not leave the previous response replayable");
    expect(g_transport_connected_set_count >= 1U && !g_last_transport_connected,
           "DESFire S-DESELECT should publish a disconnected activation boundary");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    event.protocol = NfcProtocolIso14443_3a;
    event.instance = NULL;
    event.event_data = &iso3_event;
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "RATS after DESFire S-DESELECT should start a clean activation");
    expect(app.transport_nfc_state_storage.iso4_active,
           "RATS after DESFire S-DESELECT should reactivate ISO-DEP");
    expect(g_last_nfc_tx_len == 7U &&
               memcmp(g_last_nfc_tx, (const uint8_t[]){0x05, 0x78, 0x91, 0xE8, 0x00}, 5U) == 0,
           "RATS after DESFire S-DESELECT should transmit the iOS ATS");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_rats_sends_ats_with_public_tx(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "3A RATS should be handled in-app");
    expect(app.transport_nfc_state_storage.iso4_active,
           "RATS should activate the local ISO-DEP layer");
    expect(g_nfc_tx_count == 1U && g_last_nfc_tx_len == 7U,
           "RATS should transmit ATS plus ISO14443A CRC through public nfc_listener_tx");
    expect(memcmp(g_last_nfc_tx, (const uint8_t[]){0x05, 0x78, 0x91, 0xE8, 0x00}, 5U) == 0,
           "RATS should receive the configured short ATS");
    expect(test_log_contains("NFC RATS E0 len=1 80"),
           "RATS should expose the activation breadcrumb");
    expect(g_last_status_text[0] == '\0', "RATS diagnostic should not update UI status");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_repeated_rats_resends_ats_instead_of_iso4_block(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "first RATS should activate ISO-DEP");

    app.transport_nfc_state_storage.applet_selected = true;
    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "repeated RATS should restart activation instead of falling through as an ISO4 block");
    expect(g_nfc_tx_count == 2U && g_last_nfc_tx_len == 7U,
           "repeated RATS should send ATS a second time");
    expect(memcmp(g_last_nfc_tx, (const uint8_t[]){0x05, 0x78, 0x91, 0xE8, 0x00}, 5U) == 0,
           "repeated RATS should receive the configured short ATS");
    expect(test_log_contains("NFC RATS E0 len=1 80"),
           "repeated RATS should keep the activation breadcrumb instead of NFC block");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "repeated RATS should clear stale FIDO applet selection");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_reqa_data_resets_active_iso_dep_session(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.applet_selected = true;

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x26}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandReset,
           "REQA delivered as data should reset the active ISO-DEP session");
    expect(!app.transport_nfc_state_storage.iso4_active,
           "REQA data should clear ISO-DEP active state");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "REQA data should clear stale FIDO applet selection");
    expect(test_log_contains("NFC poll restart 26 len=0"),
           "REQA data should expose the poll restart breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_iso_dep_select_decodes_and_responds(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "3A RATS should activate ISO-DEP before APDUs");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "3A listener should decode ISO-DEP I-blocks after ATS");
    expect(app.transport_nfc_state_storage.applet_selected,
           "3A ISO-DEP SELECT should select the FIDO applet");
    expect(g_last_nfc_tx[0] == 0x02, "3A ISO-DEP response should be an I-block");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 8U && memcmp(payload, "U2F_V2", 6) == 0 &&
               payload[6] == 0x90 && payload[7] == 0x00,
           "3A ISO-DEP SELECT should return U2F_V2 plus SW_SUCCESS");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_r_nak_replays_last_iso_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "3A RATS should activate ISO-DEP before replay testing");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "SELECT response should be cached for R-NAK replay");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xB3}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-NAK should be handled without resetting the NFC session");
    expect(g_nfc_tx_count == 3U, "R-NAK should transmit one replayed response");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "R-NAK should replay the cached ISO-DEP response byte-for-byte");
    expect(test_log_contains("NFC R-NAK replay B3 len=0"),
           "R-NAK replay should expose the reader PCB breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_r_ack_advances_chained_response_and_r_nak_replays(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t response[(ZF_NFC_TX_CHAIN_CHUNK_SIZE * 2U) + 88U] = {0};
    uint8_t cached_first[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_first_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)i;
    }

    expect(zf_transport_nfc_begin_chained_apdu_payload(&app.transport_nfc_state_storage, response,
                                                       sizeof(response), ZF_NFC_SW_SUCCESS),
           "oversized APDU payload should start ISO-DEP response chaining");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_active,
           "first chained block should leave remaining response bytes queued");
    expect(g_last_nfc_tx_len == ZF_NFC_TX_CHAIN_CHUNK_SIZE + 3U,
           "first chained response should fill one configured ISO-DEP chunk plus CRC");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) != 0U,
           "first chained response should set the ISO-DEP chaining bit");
    cached_first_len = g_last_nfc_tx_len;
    memcpy(cached_first, g_last_nfc_tx, cached_first_len);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xB2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-NAK should be handled while a response chain is active");
    expect(g_last_nfc_tx_len == cached_first_len &&
               memcmp(g_last_nfc_tx, cached_first, cached_first_len) == 0,
           "R-NAK should replay the first chained I-block byte-for-byte");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-ACK should advance to the next queued response I-block");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_active,
           "middle chained response block should leave remaining response bytes queued");
    expect(g_last_nfc_tx_len == ZF_NFC_TX_CHAIN_CHUNK_SIZE + 3U,
           "middle chained response should fill one configured ISO-DEP chunk plus CRC");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) != 0U,
           "middle chained response should keep the ISO-DEP chaining bit set");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA3}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "second R-ACK should advance to the final queued response I-block");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_active,
           "final chained response block should clear the queued response");
    expect(g_last_nfc_tx_len == 93U,
           "final chained response should carry remaining bytes plus CRC");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) == 0U,
           "final chained response should clear the ISO-DEP chaining bit");
    expect(g_last_nfc_tx[g_last_nfc_tx_len - 4U] == 0x90 &&
               g_last_nfc_tx[g_last_nfc_tx_len - 3U] == 0x00,
           "final chained response should terminate with SW_SUCCESS before CRC");
    expect(test_log_contains("NFC R-ACK chain A2 len=0"),
           "R-ACK chaining should expose the recovery breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_make_credential_sized_response_uses_single_i_block(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t response[176U] = {0};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)(0x40U + i);
    }

    expect(zf_transport_nfc_send_apdu_payload(&app.transport_nfc_state_storage, response,
                                              sizeof(response), ZF_NFC_SW_SUCCESS),
           "iOS MakeCredential-sized response should fit one ISO-DEP I-block");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_active &&
               !app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "MakeCredential-sized response should not enter outbound chaining");
    expect(g_last_nfc_tx_len == sizeof(response) + 5U,
           "MakeCredential-sized single I-block should include PCB, SW, and CRC");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) == 0U,
           "MakeCredential-sized single I-block should not set the chaining bit");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == sizeof(response) + 2U &&
               payload[test_nfc_payload_len() - 2U] == 0x90 &&
               payload[test_nfc_payload_len() - 1U] == 0x00,
           "MakeCredential-sized single I-block should terminate with SW_SUCCESS");

    test_nfc_deinit_app(&app);
}

static void test_nfc_terminal_r_ack_after_chained_response_keeps_fido_selected(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    static const uint8_t ctap2_get_info_apdu[] = {0x80, 0x10, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo};
    uint8_t response[190U] = {0};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)i;
    }

    expect(zf_transport_nfc_begin_chained_apdu_payload(&app.transport_nfc_state_storage, response,
                                                       sizeof(response), ZF_NFC_SW_SUCCESS),
           "oversized APDU payload should start ISO-DEP response chaining");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_active,
           "first chained block should leave remaining response bytes queued");

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-ACK should advance to the final chained response block");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "final chained block should wait for the reader's terminal ACK");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA3}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "terminal R-ACK should acknowledge the completed chain");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "terminal R-ACK should clear only the completed-chain latch");
    expect(app.transport_nfc_state_storage.applet_selected,
           "terminal R-ACK must not deselect the FIDO applet");
    expect(!app.transport_nfc_state_storage.post_success_cooldown_active,
           "terminal R-ACK should not arm post-success discovery cooldown");

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_get_info_apdu,
                                        sizeof(ctap2_get_info_apdu)),
           "a CTAP APDU after terminal R-ACK should still reach the selected FIDO applet");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() > 2U && payload[0] == ZF_CTAP_SUCCESS,
           "post-chain CTAP APDU should return a CTAP response instead of 6985");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_post_success_cooldown_allows_new_fido_select(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t response[(ZF_NFC_TX_CHAIN_CHUNK_SIZE * 2U) + 88U] = {0};

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    g_fake_tick = 1000U;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)i;
    }

    expect(zf_transport_nfc_begin_chained_apdu_payload(&app.transport_nfc_state_storage, response,
                                                       sizeof(response), ZF_NFC_SW_SUCCESS),
           "oversized APDU payload should start ISO-DEP response chaining");
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-ACK should send the middle chained response block");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_active,
           "middle chained block should keep remaining response bytes queued");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "middle chained block should not wait for a terminal ACK yet");
    expect(!app.transport_nfc_state_storage.post_success_cooldown_active,
           "cooldown should not start while response bytes remain queued");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA3}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "second R-ACK should send the final chained response block");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "final chained block should wait for the reader's terminal ACK");
    expect(!app.transport_nfc_state_storage.post_success_cooldown_active,
           "cooldown should not start until the final block is acknowledged");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "terminal R-ACK should complete the transaction");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "terminal R-ACK should clear the completed-chain latch");
    expect(!app.transport_nfc_state_storage.post_success_cooldown_active,
           "terminal R-ACK should not start the post-success cooldown by itself");
    expect(!app.transport_nfc_state_storage.post_success_probe_sleep_active,
           "terminal R-ACK should not arm post-success probe suppression by itself");
    expect(g_nfc_tx_count == 3U, "terminal R-ACK should not transmit another NFC frame");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "post-success cooldown should still allow a new ISO-DEP activation");
    expect(g_nfc_tx_count == 4U && g_last_nfc_tx_len == 7U,
           "cooldown RATS should transmit ATS so a real authentication can select FIDO");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "FIDO SELECT during cooldown should start a new session");
    expect(app.transport_nfc_state_storage.applet_selected,
           "FIDO SELECT during cooldown should select the applet");
    expect(!app.transport_nfc_state_storage.post_success_cooldown_active,
           "FIDO SELECT should clear post-success cooldown immediately");
    expect(!app.transport_nfc_state_storage.post_success_probe_sleep_active,
           "FIDO SELECT should clear post-success probe suppression");
    expect(g_nfc_tx_count == 5U && g_last_nfc_tx[0] == 0x02,
           "FIDO SELECT during cooldown should transmit the normal select response");

    app.transport_nfc_state_storage.post_success_cooldown_active = true;
    app.transport_nfc_state_storage.post_success_probe_sleep_active = true;
    app.transport_nfc_state_storage.post_success_cooldown_until_tick =
        g_fake_tick + ZF_NFC_POST_SUCCESS_COOLDOWN_MS;
    app.transport_nfc_state_storage.applet_selected = false;
    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "cooldown should still allow activation before suppressing non-FIDO probes");
    expect(g_nfc_tx_count == 6U && g_last_nfc_tx_len == 7U,
           "cooldown activation should send ATS before the NDEF probe is classified");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00,
                                              0x00, 0x85, 0x01, 0x01, 0x00},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "first NDEF SELECT during cooldown should be rejected so Safari can continue to FIDO");
    expect(g_nfc_tx_count == 7U && g_last_nfc_tx_len == 5U && g_last_nfc_tx[1] == 0x6A &&
               g_last_nfc_tx[2] == 0x82,
           "first cooldown NDEF SELECT should transmit the normal not-found response");

    app.transport_nfc_state_storage.applet_selected = false;
    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x03, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00,
                                              0x00, 0x85, 0x01, 0x01, 0x00},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "repeated NDEF SELECT during cooldown should stay responsive for same-run auth");
    expect(g_nfc_tx_count == 8U && g_last_nfc_tx_len == 5U && g_last_nfc_tx[1] == 0x6A &&
               g_last_nfc_tx[2] == 0x82,
           "repeated cooldown NDEF SELECT should transmit the normal not-found response");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "FIDO SELECT after repeated cooldown NDEF should still start same-run auth");
    expect(app.transport_nfc_state_storage.applet_selected,
           "FIDO SELECT after repeated cooldown NDEF should select the applet");
    expect(g_nfc_tx_count == 9U && g_last_nfc_tx[0] == 0x02,
           "FIDO SELECT after repeated cooldown NDEF should transmit the select response");

    g_fake_tick = app.transport_nfc_state_storage.post_success_cooldown_until_tick + 1U;
    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "expired post-success cooldown should allow normal discovery again");
    expect(g_nfc_tx_count == 10U && g_last_nfc_tx_len == 7U,
           "normal discovery should resume with one ATS transmission after cooldown expiry");

    app.transport_nfc_state_storage.post_success_probe_sleep_active = true;
    app.transport_nfc_state_storage.applet_selected = false;
    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00,
                                              0x00, 0x85, 0x01, 0x01, 0x00},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "post-success NDEF SELECT after cooldown expiry should use normal rejection");
    expect(g_nfc_tx_count == 11U && g_last_nfc_tx_len == 5U && g_last_nfc_tx[1] == 0x6A &&
               g_last_nfc_tx[2] == 0x82,
           "expired post-success NDEF SELECT should transmit the normal not-found response");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_empty_i_block_replays_cached_large_response_before_helper(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t response[ZF_NFC_MAX_TX_FRAME_INF_SIZE - 2U] = {0};
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)(0xA0U + i);
    }

    expect(zf_transport_nfc_send_apdu_payload(&app.transport_nfc_state_storage, response,
                                              sizeof(response), ZF_NFC_SW_SUCCESS),
           "max safe single-frame APDU response should be sent and cached");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "empty I-block should be intercepted before the ISO4 helper consumes it");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "empty I-block should replay the cached large response byte-for-byte");
    expect(test_log_contains("NFC I-empty replay 02 len=0"),
           "empty I-block replay should expose the recovery breadcrumb");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xB3}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-NAK after empty I-block recovery should still be handled");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "R-NAK after empty I-block should keep replaying the original response");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_empty_i_block_replays_encoded_frame_when_cache_flag_missing(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t response[ZF_NFC_MAX_TX_FRAME_INF_SIZE - 2U] = {0};
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)(0x20U + i);
    }

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "SELECT should prime the ISO-DEP helper response state");
    bit_buffer_reset(buffer);

    expect(zf_transport_nfc_send_apdu_payload(&app.transport_nfc_state_storage, response,
                                              sizeof(response), ZF_NFC_SW_SUCCESS),
           "max safe APDU response should leave an encoded ISO-DEP frame available");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);

    app.transport_nfc_state_storage.iso4_last_tx_valid = false;
    app.transport_nfc_state_storage.iso4_last_tx_len = 0U;
    memset(app.transport_nfc_state_storage.iso4_tx_frame, 0,
           sizeof(app.transport_nfc_state_storage.iso4_tx_frame));

    const size_t tx_count_before_empty_i = g_nfc_tx_count;

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "empty I-block should not use a stale helper-owned frame cache");
    expect(g_nfc_tx_count == tx_count_before_empty_i + 1U && g_last_nfc_tx_len == 3U &&
               g_last_nfc_tx[0] == 0xA2U,
           "empty I-block without an array replay should receive only a bounded R-ACK");
    expect(g_last_nfc_tx_len != cached_response_len ||
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) != 0,
           "disabled array replay must not fall back to mutable BitBuffer contents");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_late_pps_then_r_nak_replays_cached_large_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t response[ZF_NFC_MAX_TX_FRAME_INF_SIZE - 2U] = {0};
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)(0x40U + i);
    }

    expect(zf_transport_nfc_send_apdu_payload(&app.transport_nfc_state_storage, response,
                                              sizeof(response), ZF_NFC_SW_SUCCESS),
           "max safe APDU response should be cached before late PPS recovery");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xD9, 0x33, 0x63}, 3U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "late PPS-like frame should be handled after a large response");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "late PPS-like frame should not transmit or overwrite the cached large response");
    expect(test_log_contains("NFC PPS defer D9 len=2 33 63"),
           "late PPS-like frame should expose the deferred-control breadcrumb");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xB2}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "R-NAK after late PPS should be handled without deselecting");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "R-NAK after late PPS should replay the cached large response byte-for-byte");
    expect(test_log_contains("NFC R-NAK replay B2 len=0"),
           "R-NAK after late PPS should expose the replay breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_3a_late_pps_frame_is_acknowledged(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xE0, 0x80}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "3A RATS should activate ISO-DEP before PPS testing");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "SELECT should establish a live ISO-DEP exchange before late PPS");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xD9, 0x33, 0x63}, 3U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "late PPS-like frame should be acknowledged instead of being silently ignored");
    expect(g_nfc_tx_count == 3U && g_last_nfc_tx_len == 3U && g_last_nfc_tx[0] == 0xD9,
           "late PPS-like frame should echo PPSS through public NFC TX");
    expect(test_log_contains("NFC PPS ack D9 len=2 33 63"),
           "late PPS-like frame should expose the PPS ack breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_framed_select_response_uses_reader_block_number(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x03, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "framed SELECT APDU should be accepted through the NFC listener callback");
    expect(g_last_nfc_tx[0] == 0x03,
           "framed SELECT response should use the reader ISO-DEP block number");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 8 && memcmp(payload, "U2F_V2", 6) == 0 && payload[6] == 0x90 &&
               payload[7] == 0x00,
           "framed SELECT APDU should return U2F_V2 plus SW_SUCCESS inside an I-block");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_cache_last_iso_response_handles_frame_buffer_alias(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    const uint8_t frame[] = {0x03, 0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, 0x90, 0x00};
    uint8_t source[sizeof(frame)] = {0};

    test_reset();
    test_nfc_init_app(&app, &mutex);

    memcpy(source, frame, sizeof(source));
    zf_transport_nfc_cache_last_iso_response(&app.transport_nfc_state_storage, source,
                                             sizeof(source));
    memset(source, 0, sizeof(source));
    expect(app.transport_nfc_state_storage.iso4_last_tx_valid &&
               app.transport_nfc_state_storage.iso4_last_tx_len == sizeof(frame),
           "last ISO response cache should keep the aliased frame length");
    expect(memcmp(app.transport_nfc_state_storage.iso4_tx_frame, frame, sizeof(frame)) == 0,
           "last ISO response cache should be an owned byte-array snapshot");
    expect(app.transport_nfc_state_storage.tx_frame_len == 0U,
           "manual cache snapshot must not depend on a prior TX frame");

    test_nfc_deinit_app(&app);
}

static void test_nfc_unadvertised_cid_frame_is_ignored(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x0A, 0x05, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00,
                                              0x00, 0x06, 0x47, 0x2F, 0x00, 0x01},
                            15U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "CID-bearing framed SELECT APDU should be skipped when ATS did not advertise CID");
    expect(g_nfc_tx_count == 0U, "unadvertised CID frame should not receive a response");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "unadvertised CID frame should not select the FIDO applet");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_ndef_type4_select_is_rejected_for_fido_only_surface(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00,
                                              0x00, 0x85, 0x01, 0x01},
                            13U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "Type 4 NDEF app SELECT should be rejected for the authenticator-only surface");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "NDEF app SELECT should not select the FIDO applet");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6A && payload[1] == 0x82,
           "NDEF app SELECT should return SW_FILE_NOT_FOUND");
    expect(test_log_contains("NDEF reject"),
           "NDEF app SELECT should expose the authenticator-only breadcrumb");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_applet_select_is_required_before_ctap2(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t ctap2_apdu[] = {0x80, 0x10, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "CTAP2 APDU should be rejected with a status word before SELECT");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2,
           "pre-SELECT CTAP2 rejection should return only a status word");
    expect(payload[0] == 0x69 && payload[1] == 0x85,
           "pre-SELECT CTAP2 rejection should return SW_CONDITIONS_NOT_SATISFIED");

    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_apdu_80_60_reports_instruction_not_supported(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t probe_apdu[] = {0x80, 0x60, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, probe_apdu,
                                        sizeof(probe_apdu)),
           "pre-SELECT APDU 80 60 should receive a status word");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2 && payload[0] == 0x6D && payload[1] == 0x00,
           "pre-SELECT APDU 80 60 should report INS_NOT_SUPPORTED instead of wrong state");
    expect(test_log_contains("APDU 8060 reject"),
           "pre-SELECT APDU 80 60 should expose the exact status word breadcrumb");
    expect(g_last_status_text[0] == '\0',
           "pre-SELECT APDU 80 60 diagnostic should not update UI status");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "pre-SELECT APDU 80 60 should not select the FIDO applet");

    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_wrapped_apdu_90_60_bootstraps_fido_applet(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t probe_apdu[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, probe_apdu,
                                        sizeof(probe_apdu)),
           "pre-SELECT wrapped APDU 90 60 should receive an unsupported status");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 30U && payload[0] == 0x04 && payload[6] == 0x05 &&
               payload[7] == 0x04 && payload[14] == 0x04 && payload[28] == 0x91 &&
               payload[29] == 0x00,
           "pre-SELECT wrapped APDU 90 60 should return terminal DESFire GetVersion data");
    expect(test_log_contains("DESFire version done"),
           "pre-SELECT wrapped APDU 90 60 should expose the classifier breadcrumb");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "pre-SELECT wrapped APDU 90 60 should leave the FIDO applet unselected");

    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_wrapped_apdu_90_af_reports_cla_not_supported(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t more_apdu[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, more_apdu,
                                        sizeof(more_apdu)),
           "pre-SELECT wrapped APDU 90 AF should receive a CLA-invalid status word");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 9U && payload[0] == 0x04 && payload[6] == 0x05 &&
               payload[7] == 0x91 && payload[8] == 0xAF,
           "pre-SELECT wrapped APDU 90 AF should return a DESFire continuation frame");
    expect(test_log_contains("DESFire version"),
           "pre-SELECT wrapped APDU 90 AF should expose the classifier breadcrumb");

    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_wrapped_desfire_get_version_does_not_sequence(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t probe_apdu[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    static const uint8_t more_apdu[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, probe_apdu,
                                        sizeof(probe_apdu)),
           "pre-SELECT wrapped DESFire GetVersion should return a terminal status");
    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, more_apdu,
                                        sizeof(more_apdu)),
           "pre-SELECT wrapped DESFire continuation should remain terminal");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 9U && payload[7] == 0x91 && payload[8] == 0xAF,
           "DESFire continuation should return another continuation frame");

    test_nfc_deinit_app(&app);
}

static void test_nfc_selected_wrapped_desfire_get_version_is_terminal_unsupported(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t probe_apdu[] = {0x90, 0x60, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, probe_apdu,
                                        sizeof(probe_apdu)),
           "selected wrapped DESFire GetVersion should receive a terminal unsupported status");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 30U && payload[28] == 0x91 && payload[29] == 0x00,
           "selected wrapped DESFire GetVersion should return terminal DESFire GetVersion data");
    expect(app.transport_nfc_state_storage.applet_selected,
           "selected wrapped DESFire GetVersion should not clear FIDO applet selection");
    test_nfc_deinit_app(&app);
}

static void test_nfc_event_callback_bare_90_60_bootstraps_fido_applet(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x90, 0x60, 0x00, 0x00}, 4U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "bare 90 60 probe should receive an ISO-DEP-framed status even without Le");
    expect(g_nfc_tx_count == 1U && g_last_nfc_tx_len == 33U && g_last_nfc_tx[0] == 0x02 &&
               g_last_nfc_tx[1] == 0x04 && g_last_nfc_tx[29] == 0x91 && g_last_nfc_tx[30] == 0x00,
           "bare 90 60 probe should transmit a DESFire version APDU response inside an I-block");
    expect(test_log_contains("DESFire version done"),
           "bare 90 60 probe should expose the classifier breadcrumb");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "bare 90 60 probe should leave the FIDO applet unselected");

    listener_event.type = Iso14443_4aListenerEventTypeHalted;
    listener_event.data = NULL;
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "halt after the 90 60 response should sleep the NFC listener");
    expect(test_log_contains("DESFire version done"),
           "halt after the bare 90 60 probe should preserve the last APDU status");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "9060 probe reset should leave the selected applet state cleared");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_bare_90_60_is_iso_dep_framed(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x90, 0x60, 0x00, 0x00, 0x00}, 5U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "bare 90 60 from the official ISO4 listener should be dispatched as an APDU");
    expect(g_nfc_tx_count == 1U && g_last_nfc_tx_len == 33U && g_last_nfc_tx[0] == 0x02 &&
               g_last_nfc_tx[1] == 0x04 && g_last_nfc_tx[29] == 0x91 && g_last_nfc_tx[30] == 0x00,
           "bare 90 60 from the official ISO4 listener should return a DESFire version APDU");
    expect(test_log_contains("DESFire version done"),
           "bare 90 60 from the official ISO4 listener should keep the APDU status visible");

    listener_event.type = Iso14443_4aListenerEventTypeHalted;
    listener_event.data = NULL;
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "reader halt after bare 90 60 should reset the NFC session");
    expect(test_log_contains("DESFire version done"),
           "reader halt after bare 90 60 should not hide the rejection status");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_get_info_returns_immediately(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t ctap2_apdu[] = {0x80, 0x10, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "CTAP2 GetInfo APDU should complete immediately after SELECT");
    expect(g_get_info_builder_called, "NFC GetInfo should use the shared GetInfo builder");
    expect(g_get_info_builder_saw_nfc_transport,
           "NFC GetInfo should force-advertise the NFC transport");
    expect(!g_get_info_builder_saw_usb_transport,
           "NFC GetInfo should not inherit USB transport advertising");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() > 2U && test_nfc_payload_len() < 250U,
           "GetInfo response should return the shared CTAP GetInfo payload plus SW");
    expect(payload[0] == ZF_CTAP_SUCCESS,
           "GetInfo response should preserve the CTAP success status");
    expect(payload[test_nfc_payload_len() - 2U] == 0x90 &&
               payload[test_nfc_payload_len() - 1U] == 0x00,
           "GetInfo response should terminate with SW_SUCCESS");
    expect(test_log_contains("CTAP2 getInfo"),
           "GetInfo should expose the synchronous NFC breadcrumb");
    expect(!test_log_contains("apdu-tx-data"),
           "GetInfo diagnostics should avoid APDU payload previews in the NFC callback");
    expect(g_last_status_text[0] == '\0', "GetInfo NFC diagnostic should not update UI status");
    expect(g_notify_prompt_count == 0U, "NFC CTAP2 GetInfo should not start the prompt light");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_get_info_accepts_webkit_extended_apdu(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t ctap2_apdu[] = {
        0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo, 0x00, 0x00,
    };
    ZfNfcApdu parsed;
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_parse_apdu(ctap2_apdu, sizeof(ctap2_apdu), &parsed),
           "WebKit extended CTAP2 GetInfo APDU should parse");
    expect(parsed.extended && parsed.has_le && parsed.le == 0U,
           "WebKit extended CTAP2 GetInfo APDU should preserve extended Le=0000");
    expect(zf_transport_nfc_normalize_le(&parsed) == 65536U,
           "extended Le=0000 should normalize to the extended maximum response length");
    expect(parsed.data_len == 1U && parsed.data[0] == ZfCtapeCmdGetInfo,
           "WebKit extended CTAP2 GetInfo APDU should expose the CTAP command byte as data");

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "WebKit extended CTAP2 GetInfo APDU should complete immediately after SELECT");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() > 2U && test_nfc_payload_len() < 250U,
           "extended GetInfo response should return the shared CTAP GetInfo payload plus SW");
    expect(payload[0] == ZF_CTAP_SUCCESS,
           "extended GetInfo response should preserve the CTAP success status");
    expect(payload[test_nfc_payload_len() - 2U] == 0x90 &&
               payload[test_nfc_payload_len() - 1U] == 0x00,
           "extended GetInfo response should terminate with SW_SUCCESS");
    expect(test_log_contains("CTAP2 getInfo"),
           "extended GetInfo should expose the synchronous NFC breadcrumb");

    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_extended_get_info_is_iso_dep_framed(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    memset(g_last_nfc_tx, 0, sizeof(g_last_nfc_tx));
    g_last_nfc_tx_bits = 0;
    g_last_nfc_tx_len = 0;
    g_nfc_tx_count = 0;

    bit_buffer_append_bytes(
        buffer,
        (const uint8_t[]){0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo, 0x00, 0x00},
        10U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "WebKit extended CTAP2 GetInfo from the official ISO4 listener should dispatch as APDU");
    expect(g_nfc_tx_count >= 1U && g_last_nfc_tx_len >= 3U,
           "extended listener GetInfo should return an ISO-DEP-framed APDU response plus CRC");
    expect(g_last_nfc_tx[0] == 0x03 && g_last_nfc_tx[1] == ZF_CTAP_SUCCESS &&
               g_last_nfc_tx[g_last_nfc_tx_len - 4U] == 0x90 &&
               g_last_nfc_tx[g_last_nfc_tx_len - 3U] == 0x00,
           "extended listener GetInfo should return CTAP OK and SW_SUCCESS in an I-block");
    expect(test_log_contains("CTAP2 getInfo"),
           "extended listener GetInfo should expose the CTAP2 status");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_ctap2_msg_signals_worker_after_unlock(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    memset(g_last_nfc_tx, 0, sizeof(g_last_nfc_tx));
    g_last_nfc_tx_bits = 0;
    g_last_nfc_tx_len = 0;
    g_nfc_tx_count = 0;

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x80, 0x10, ZF_NFC_CTAP_MSG_P1_GET_RESPONSE, 0x00,
                                              0x00, 0x00, 0x01, ZfCtapeCmdMakeCredential, 0x00,
                                              0x00},
                            10U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "ISO4 listener CTAP2 MSG should queue worker processing");
    expect((g_last_thread_flags_set & ZF_NFC_WORKER_EVT_REQUEST) != 0U,
           "locked ISO4 CTAP2 MSG should signal the persistent NFC worker");

    zf_transport_nfc_process_request(&app);
    expect(test_log_contains("CTAP2 worker done"),
           "persistent NFC worker should reach CTAP2 processing");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_iso4_listener_busy_ctap2_retry_has_minimal_side_effects(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListener listener = {0};
    BitBuffer *buffer = bit_buffer_alloc(16U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .instance = &listener,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    g_transport_connected_set_count = 0;
    memset(g_last_status_text, 0, sizeof(g_last_status_text));
    memset(g_last_nfc_tx, 0, sizeof(g_last_nfc_tx));
    g_last_nfc_tx_bits = 0;
    g_last_nfc_tx_len = 0;
    g_nfc_tx_count = 0;

    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.request_pending = false;
    app.transport_nfc_state_storage.response_ready = false;

    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x80, 0x10, ZF_NFC_CTAP_MSG_P1_GET_RESPONSE, 0x00,
                                              0x00, 0x00, 0x01, ZfCtapeCmdMakeCredential, 0x00,
                                              0x00},
                            10U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "busy ISO4 CTAP2 retry should still return STATUS_UPDATE");
    expect(g_last_nfc_tx_len >= 5U && g_last_nfc_tx[1] == ZF_NFC_STATUS_PROCESSING &&
               g_last_nfc_tx[2] == 0x91 && g_last_nfc_tx[3] == 0x00,
           "busy ISO4 CTAP2 retry should emit processing status plus SW");
    expect(g_transport_connected_set_count <= 1U,
           "busy ISO4 CTAP2 retry should avoid per-retry transport UI churn");
    expect(g_last_status_text[0] == '\0',
           "busy ISO4 CTAP2 retry should not update the visible APDU status");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_msg_queues_worker_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t ctap2_apdu[] = {0x80, 0x10, ZF_NFC_CTAP_MSG_P1_GET_RESPONSE,
                                         0x00, 0x01, ZfCtapeCmdMakeCredential};
    static const uint8_t get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "NFC CTAP2 MSG should queue worker processing and return a status update");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 3U,
           "queued NFC CTAP2 response should return processing status plus SW");
    expect(payload[0] == ZF_NFC_STATUS_PROCESSING && payload[1] == 0x91 && payload[2] == 0x00,
           "queued NFC CTAP2 response should use STATUS_UPDATE");
    expect(app.transport_nfc_state_storage.processing &&
               app.transport_nfc_state_storage.request_pending,
           "queued NFC CTAP2 should leave a worker request pending");
    expect((g_last_thread_flags_set & ZF_NFC_WORKER_EVT_REQUEST) != 0U,
           "queued NFC CTAP2 should signal the persistent NFC worker");

    zf_transport_nfc_process_request(&app);
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "worker-completed NFC CTAP2 should clear the background request");
    expect(g_notify_prompt_count == 0U,
           "queued NFC CTAP2 auto-accept should not start the user-presence prompt light");
    expect(g_ctap2_saw_transport_auto_accept,
           "worker NFC CTAP2 should auto-satisfy user presence for bring-up");
    expect(!app.transport_auto_accept_transaction,
           "worker NFC CTAP2 should restore the auto-accept override");
    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "worker-completed NFC CTAP2 should expose the response through GET_RESPONSE");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 4U,
           "worker-completed NFC CTAP2 response should include CTAP body and SW");
    expect(payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA0,
           "worker-completed NFC CTAP2 response should preserve the CTAP response body");
    expect(payload[2] == 0x90 && payload[3] == 0x00,
           "worker-completed NFC CTAP2 response should terminate with SW_SUCCESS");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_msg_without_get_response_returns_direct_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t ctap2_apdu[] = {0x80, 0x10, 0x00, 0x00, 0x01, ZfCtapeCmdMakeCredential};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "NFC CTAP2 MSG without GET_RESPONSE support should complete directly");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 4U, "direct no-GR NFC CTAP2 should include CTAP body and SW");
    expect(payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA0 && payload[2] == 0x90 &&
               payload[3] == 0x00,
           "direct no-GR NFC CTAP2 should return CTAP OK and SW_SUCCESS");
    expect(g_ctap2_saw_transport_auto_accept,
           "direct no-GR NFC CTAP2 should auto-satisfy user presence");
    expect(!g_ctap2_request_response_overlap,
           "direct no-GR NFC CTAP2 should not pass the shared arena as both request and response");
    expect(g_notify_prompt_count == 0U,
           "direct no-GR NFC CTAP2 should not start the user-presence prompt light");
    expect(!app.transport_auto_accept_transaction,
           "direct no-GR NFC CTAP2 should restore the auto-accept override");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending &&
               !app.transport_nfc_state_storage.response_ready,
           "direct no-GR NFC CTAP2 should not leave a background request");
    test_nfc_deinit_app(&app);
}

static void test_nfc_large_ctap2_msg_without_get_response_uses_iso_response_chaining(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t ctap2_apdu[45] = {0x80, 0x10, 0x00, 0x00, 0x28, ZfCtapeCmdClientPin};
    static const uint8_t get_response_apdu[] = {0x00, ZF_NFC_INS_ISO_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;
    const size_t first_chunk_len = ZF_NFC_GET_RESPONSE_CHUNK_SIZE;
    const size_t response_len = ZF_NFC_MAX_TX_FRAME_INF_SIZE + 50U;
    const size_t remaining_len = response_len - first_chunk_len;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    g_ctap2_large_response_len = response_len;

    for (size_t i = 6U; i < sizeof(ctap2_apdu); ++i) {
        ctap2_apdu[i] = (uint8_t)i;
    }

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "large NFC CTAP2 MSG without GET_RESPONSE support should start APDU response chaining");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == first_chunk_len + 2U,
           "large no-GR CTAP2 response should return one APDU response page plus SW");
    expect(payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA1,
           "large no-GR CTAP2 response should start with the CTAP response body");
    expect(payload[first_chunk_len] == 0x61U &&
               payload[first_chunk_len + 1U] == (uint8_t)remaining_len,
           "large no-GR CTAP2 response should advertise remaining bytes with SW_BYTES_REMAINING");
    expect(g_ctap2_saw_transport_auto_accept,
           "large no-GR CTAP2 should auto-satisfy user presence");
    expect(!g_ctap2_request_response_overlap,
           "large no-GR CTAP2 should copy request bytes away from the response arena");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending &&
               app.transport_nfc_state_storage.response_ready &&
               app.transport_nfc_state_storage.response_offset == first_chunk_len &&
               !app.transport_nfc_state_storage.iso4_tx_chain_active,
           "large no-GR CTAP2 should stage the remainder for ISO GET RESPONSE");

    size_t remaining_after_page = remaining_len;
    while (remaining_after_page > ZF_NFC_GET_RESPONSE_CHUNK_SIZE) {
        expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage,
                                            get_response_apdu, sizeof(get_response_apdu)),
               "large no-GR CTAP2 response should continue through ISO GET RESPONSE");
        payload = test_nfc_payload();
        expect(test_nfc_payload_len() == ZF_NFC_GET_RESPONSE_CHUNK_SIZE + 2U,
               "intermediate no-GR CTAP2 response page should stay within the NFC page budget");
        expect(payload[ZF_NFC_GET_RESPONSE_CHUNK_SIZE] == 0x61U,
               "intermediate no-GR CTAP2 response page should advertise more bytes");
        remaining_after_page -= ZF_NFC_GET_RESPONSE_CHUNK_SIZE;
    }

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "large no-GR CTAP2 response should finish through ISO GET RESPONSE");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == remaining_after_page + 2U,
           "final no-GR CTAP2 response page should include remaining bytes plus SW");
    expect(payload[remaining_after_page] == 0x90U && payload[remaining_after_page + 1U] == 0x00U,
           "final no-GR CTAP2 response page should terminate with SW_SUCCESS");
    expect(!app.transport_nfc_state_storage.response_ready,
           "final no-GR CTAP2 response page should clear the staged response");

    test_nfc_deinit_app(&app);
}

static void test_nfc_packed_attestation_sized_extended_response_finishes_iso_dep_chain(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    static uint8_t response[822U] = {0};
    const size_t total_len = sizeof(response) + 2U;
    const size_t full_chunks = total_len / ZF_NFC_TX_CHAIN_CHUNK_SIZE;
    const size_t final_payload_len = total_len - (full_chunks * ZF_NFC_TX_CHAIN_CHUNK_SIZE);
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;
    for (size_t i = 0; i < sizeof(response); ++i) {
        response[i] = (uint8_t)(0x30U + i);
    }

    expect(zf_transport_nfc_begin_chained_apdu_payload(&app.transport_nfc_state_storage, response,
                                                       sizeof(response), ZF_NFC_SW_SUCCESS),
           "packed attestation sized response should start ISO-DEP response chaining");
    expect(test_nfc_payload_len() == ZF_NFC_TX_CHAIN_CHUNK_SIZE,
           "packed attestation chain should send a bounded first ISO-DEP payload");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) != 0U,
           "packed attestation first block should set the chaining bit");

    for (size_t ack_index = 0U; ack_index < full_chunks; ++ack_index) {
        const uint8_t ack = (ack_index % 2U) == 0U ? 0xA2U : 0xA3U;

        bit_buffer_reset(buffer);
        bit_buffer_append_bytes(buffer, &ack, 1U);
        expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
               "packed attestation R-ACK should advance the ISO-DEP response chain");
    }

    payload = test_nfc_payload();
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_active &&
               app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "packed attestation final block should wait for the terminal reader ACK");
    expect(test_nfc_payload_len() == final_payload_len,
           "packed attestation final block should carry only remaining bytes and SW");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) == 0U,
           "packed attestation final block should clear the chaining bit");
    expect(payload[final_payload_len - 2U] == 0x90U && payload[final_payload_len - 1U] == 0x00U,
           "packed attestation final block should terminate with SW_SUCCESS");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA2U}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "packed attestation terminal R-ACK should complete the ISO-DEP transaction");
    expect(!app.transport_nfc_state_storage.iso4_tx_chain_completed,
           "packed attestation terminal R-ACK should clear the completed-chain latch");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_large_extended_ctap2_msg_without_get_response_uses_extended_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t ctap2_apdu[47] = {0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x28, ZfCtapeCmdClientPin};
    const uint8_t *payload = NULL;
    const size_t response_len = ZF_NFC_MAX_TX_FRAME_INF_SIZE + 50U;
    uint8_t first_pcb = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    g_ctap2_large_response_len = response_len;

    for (size_t i = 8U; i < sizeof(ctap2_apdu); ++i) {
        ctap2_apdu[i] = (uint8_t)i;
    }

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, ctap2_apdu,
                                        sizeof(ctap2_apdu)),
           "large extended NFC CTAP2 MSG should start an extended APDU response");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == ZF_NFC_TX_CHAIN_CHUNK_SIZE,
           "large extended CTAP2 response should use bounded ISO-DEP response chunks");
    expect(payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA1,
           "large extended CTAP2 response should start with the CTAP response body");
    expect((g_last_nfc_tx[0] & ZF_NFC_PCB_CHAIN) != 0U,
           "large extended CTAP2 response should continue via ISO-DEP chaining");
    expect(app.transport_nfc_state_storage.iso4_tx_chain_active &&
               !app.transport_nfc_state_storage.response_ready,
           "large extended CTAP2 response must not use short APDU GET RESPONSE chaining");
    expect(test_log_contains("CTAP2 direct ext"),
           "large extended CTAP2 response should expose the extended-response breadcrumb");
    first_pcb = g_last_nfc_tx[0];

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0xA3U}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "extended CTAP2 R-ACK should advance the ISO-DEP response chain");
    expect(g_last_nfc_tx[0] != first_pcb,
           "extended CTAP2 R-ACK should transmit the next chained I-block");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_chained_ctap2_request_acknowledges_next_block_number(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(160U);
    Iso14443_3aListenerEventData event_data = {.buffer = buffer};
    Iso14443_3aListenerEvent listener_event = {
        .type = Iso14443_3aListenerEventTypeReceivedStandardFrame,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_3a,
        .event_data = &listener_event,
    };
    uint8_t chained_frame[126U] = {0x12U, 0x80U, 0x10U, 0x00U, 0x00U, 0x00U, 0x00U, 0xA5U};
    const char *chain_log = NULL;
    const char *ack_log = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    app.transport_nfc_state_storage.iso4_active = true;
    for (size_t i = 8U; i < sizeof(chained_frame); ++i) {
        chained_frame[i] = (uint8_t)i;
    }

    bit_buffer_append_bytes(buffer, chained_frame, sizeof(chained_frame));
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "first chained NFC CTAP2 APDU block should be accepted");
    expect(g_nfc_tx_count > 0U && g_last_nfc_tx_len == 3U && g_last_nfc_tx[0] == 0xA2U,
           "I-chain block number 0 should be acknowledged with the working iOS R-ACK A2");
    expect(app.transport_nfc_state_storage.command_chain_active,
           "first chained NFC CTAP2 APDU block should leave command assembly active");
    expect(test_log_contains("NFC I-chain 12"),
           "chained NFC CTAP2 APDU should expose the I-chain breadcrumb");
    chain_log = strstr(g_log_text, "NFC I-chain 12");
    ack_log = strstr(g_log_text, "iso-tx len=1 head=A2");
    expect(chain_log && ack_log && chain_log < ack_log,
           "iOS receive-chain ACK should preserve the previous working command order");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_duplicate_chained_i_block_does_not_corrupt_assembled_apdu(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t apdu[174U] = {0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0xA5, ZfCtapeCmdMakeCredential};
    const size_t first_len = 125U;
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;

    for (size_t i = 8U; i < 172U; ++i) {
        apdu[i] = (uint8_t)i;
    }

    furi_mutex_acquire(&mutex, FuriWaitForever);
    expect(zf_transport_nfc_handle_iso4_payload_locked(&app, &app.transport_nfc_state_storage, apdu,
                                                       first_len, 0x12, true,
                                                       false) == NfcCommandContinue,
           "first chained I-block should be accepted");
    expect(mutex.depth == 0U, "first chained I-block should release the callback mutex");
    expect(app.transport_nfc_state_storage.command_chain_active &&
               app.transport_nfc_state_storage.request_len == first_len,
           "first chained I-block should seed APDU assembly");

    furi_mutex_acquire(&mutex, FuriWaitForever);
    expect(zf_transport_nfc_handle_iso4_payload_locked(&app, &app.transport_nfc_state_storage, apdu,
                                                       first_len, 0x12, true,
                                                       false) == NfcCommandContinue,
           "retransmitted chained I-block should be acknowledged");
    expect(mutex.depth == 0U, "duplicate chained I-block should release the callback mutex");
    expect(app.transport_nfc_state_storage.command_chain_active &&
               app.transport_nfc_state_storage.request_len == first_len,
           "duplicate chained I-block must not be appended twice");
    expect(test_log_contains("NFC I-chain dup"),
           "duplicate chained I-block should expose a replay breadcrumb");

    furi_mutex_acquire(&mutex, FuriWaitForever);
    expect(zf_transport_nfc_handle_iso4_payload_locked(&app, &app.transport_nfc_state_storage,
                                                       &apdu[first_len], sizeof(apdu) - first_len,
                                                       0x02, false, false) == NfcCommandContinue,
           "terminal I-block should complete APDU assembly after a duplicate");
    expect(mutex.depth == 0U, "terminal I-block should release the callback mutex");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 4U && payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA0 &&
               payload[2] == 0x90 && payload[3] == 0x00,
           "deduplicated no-GR CTAP2 APDU should complete directly");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending &&
               !app.transport_nfc_state_storage.response_ready,
           "deduplicated no-GR APDU should not leave background worker state");

    test_nfc_deinit_app(&app);
}

static void test_nfc_duplicate_chained_i_block_stall_resets_exchange(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t apdu[126U] = {0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0xA5, ZfCtapeCmdMakeCredential};
    NfcCommand command = NfcCommandContinue;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    app.transport_nfc_state_storage.iso4_active = true;
    app.transport_nfc_state_storage.iso_pcb = ZF_NFC_PCB_BLOCK;

    for (size_t i = 8U; i < sizeof(apdu); ++i) {
        apdu[i] = (uint8_t)i;
    }

    furi_mutex_acquire(&mutex, FuriWaitForever);
    expect(zf_transport_nfc_handle_iso4_payload_locked(&app, &app.transport_nfc_state_storage, apdu,
                                                       sizeof(apdu), 0x12, true,
                                                       false) == NfcCommandContinue,
           "first chained I-block should start APDU assembly");
    expect(app.transport_nfc_state_storage.command_chain_active &&
               app.transport_nfc_state_storage.request_len == sizeof(apdu),
           "first chained I-block should be retained");

    for (size_t i = 0U; i < 9U; ++i) {
        furi_mutex_acquire(&mutex, FuriWaitForever);
        command = zf_transport_nfc_handle_iso4_payload_locked(
            &app, &app.transport_nfc_state_storage, apdu, sizeof(apdu), 0x12, true, false);
    }

    expect(command == NfcCommandReset,
           "repeated duplicate chained I-blocks should break the RF exchange");
    expect(mutex.depth == 0U, "stalled chained I-block reset should release the callback mutex");
    expect(!app.transport_nfc_state_storage.command_chain_active &&
               app.transport_nfc_state_storage.request_len == 0U &&
               !app.transport_nfc_state_storage.rx_chain_last_valid,
           "stalled chained I-block reset should discard partial APDU assembly");
    expect(test_log_contains("NFC I-chain stall"),
           "stalled chained I-block reset should expose a diagnostic breadcrumb");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_msg_rejects_invalid_p1_p2(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t rfu_p1_apdu[] = {0x80, 0x10, 0x01, 0x00, 0x01, ZfCtapeCmdMakeCredential};
    static const uint8_t rfu_p2_apdu[] = {0x80, 0x10, ZF_NFC_CTAP_MSG_P1_GET_RESPONSE,
                                          0x01, 0x01, ZfCtapeCmdMakeCredential};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, rfu_p1_apdu,
                                        sizeof(rfu_p1_apdu)),
           "NFC CTAP2 MSG should reject RFU P1 bits");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6B && payload[1] == 0x00,
           "RFU P1 bits should return SW_WRONG_P1P2");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "RFU P1 rejection must not queue NFC background processing");

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, rfu_p2_apdu,
                                        sizeof(rfu_p2_apdu)),
           "NFC CTAP2 MSG should reject RFU P2");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6B && payload[1] == 0x00,
           "RFU P2 should return SW_WRONG_P1P2");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "RFU P2 rejection must not queue NFC background processing");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap2_get_info_rejects_invalid_p1_p2(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t rfu_p1_get_info_apdu[] = {0x80, 0x10, 0x01, 0x00, 0x01, ZfCtapeCmdGetInfo};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage,
                                        rfu_p1_get_info_apdu, sizeof(rfu_p1_get_info_apdu)),
           "immediate NFC CTAP2 GetInfo should reject RFU P1/P2");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6B && payload[1] == 0x00,
           "immediate NFC CTAP2 GetInfo RFU P1/P2 should return SW_WRONG_P1P2");

    test_nfc_deinit_app(&app);
}

static void test_nfc_locked_ctap2_get_info_does_not_reenter_ui_mutex(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t get_info_apdu[] = {0x80, 0x10, 0x00, 0x00, 0x01, ZfCtapeCmdGetInfo};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    g_mutex_max_depth = 0;

    furi_mutex_acquire(&mutex, FuriWaitForever);
    expect(zf_transport_nfc_handle_apdu_locked(&app, &app.transport_nfc_state_storage,
                                               get_info_apdu, sizeof(get_info_apdu)),
           "locked NFC CTAP2 GetInfo should complete");
    expect(mutex.depth == 1U, "locked NFC CTAP2 GetInfo should return with caller mutex held");
    furi_mutex_release(&mutex);

    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 4U && payload[0] == ZF_CTAP_SUCCESS && payload[1] == 0xA0 &&
               payload[2] == 0x90 && payload[3] == 0x00,
           "locked NFC CTAP2 GetInfo should return the immediate response");
    expect(g_mutex_max_depth == 1U, "locked NFC CTAP2 GetInfo must not re-acquire UI mutex");

    test_nfc_deinit_app(&app);
}

static void test_nfc_stale_worker_completion_preserves_new_request(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t first_request[] = {ZfCtapeCmdMakeCredential};
    static const uint8_t second_request[] = {ZfCtapeCmdGetAssertion};
    static const uint8_t stale_response[] = {ZF_CTAP_SUCCESS};
    ZfTransportSessionId old_session = 0;
    uint32_t old_generation = 0U;
    uint32_t new_generation = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_queue_request_locked(&app, &app.transport_nfc_state_storage,
                                                 ZfNfcRequestKindCtap2, first_request,
                                                 sizeof(first_request)),
           "first NFC CTAP2 request should queue");
    old_session = app.transport_nfc_state_storage.processing_session_id;
    old_generation = app.transport_nfc_state_storage.processing_generation;

    zf_transport_nfc_reset_exchange_locked(&app.transport_nfc_state_storage);
    expect(zf_transport_nfc_queue_request_locked(&app, &app.transport_nfc_state_storage,
                                                 ZfNfcRequestKindCtap2, second_request,
                                                 sizeof(second_request)),
           "second NFC CTAP2 request should queue after reset");
    new_generation = app.transport_nfc_state_storage.processing_generation;
    expect(new_generation != old_generation, "new NFC request should get a new generation token");

    zf_transport_nfc_store_response(&app, &app.transport_nfc_state_storage, old_session,
                                    old_generation, stale_response, sizeof(stale_response), false,
                                    false, ZF_NFC_SW_SUCCESS);
    expect(app.transport_nfc_state_storage.processing &&
               app.transport_nfc_state_storage.request_pending,
           "stale NFC completion should not clear the newer queued request");
    expect(app.transport_nfc_state_storage.processing_generation == new_generation,
           "stale NFC completion should not overwrite the newer generation");
    expect(!app.transport_nfc_state_storage.response_ready,
           "stale NFC completion should not publish a response");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap_control_end_clears_selected_applet(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t control_end_apdu[] = {0x80, ZF_NFC_INS_CTAP_CONTROL, 0x01, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    expect(app.transport_nfc_state_storage.applet_selected,
           "test should begin with the FIDO applet selected");

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, control_end_apdu,
                                        sizeof(control_end_apdu)),
           "NFCCTAP_CONTROL END should return success");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x90 && payload[1] == 0x00,
           "NFCCTAP_CONTROL END should return SW_SUCCESS");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "NFCCTAP_CONTROL END should clear FIDO applet selection");
    expect(test_log_contains("CTAP control END"),
           "NFCCTAP_CONTROL END should expose a clear status breadcrumb");

    test_nfc_deinit_app(&app);
}

static void test_nfc_u2f_version_returns_immediately(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t version_apdu[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    expect(zf_u2f_adapter_init(&app), "U2F should initialize before NFC VERSION");
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, version_apdu,
                                        sizeof(version_apdu)),
           "U2F VERSION APDU should complete immediately after SELECT");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 8, "U2F VERSION should return U2F_V2 plus SW_SUCCESS");
    expect(memcmp(payload, "U2F_V2", 6) == 0, "U2F VERSION should return U2F_V2 over NFC");
    expect(payload[6] == 0x90 && payload[7] == 0x00,
           "U2F VERSION over NFC should terminate with SW_SUCCESS");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "U2F VERSION over NFC should not leave a queued background request");
    expect(test_log_contains("U2F VERSION"),
           "U2F VERSION over NFC should expose the immediate-version breadcrumb");

    zf_u2f_adapter_deinit(&app);
    test_nfc_deinit_app(&app);
}

static void test_nfc_u2f_version_fallback_selects_fido_surface(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t version_apdu[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, version_apdu,
                                        sizeof(version_apdu)),
           "pre-SELECT U2F VERSION fallback should complete immediately");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 8U && memcmp(payload, "U2F_V2", 6) == 0 &&
               payload[6] == 0x90 && payload[7] == 0x00,
           "pre-SELECT U2F VERSION fallback should return U2F_V2 plus SW_SUCCESS");
    expect(app.transport_nfc_state_storage.applet_selected,
           "pre-SELECT U2F VERSION fallback should select the FIDO surface");
    expect(test_log_contains("U2F VERSION fallback"),
           "pre-SELECT U2F VERSION fallback should expose the fallback breadcrumb");

    test_nfc_deinit_app(&app);
}

static void test_nfc_u2f_disabled_rejects_immediately_without_processing(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t version_apdu[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.runtime_config.transport_mode = ZfTransportModeNfc;
    app.runtime_config.u2f_enabled = false;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    test_nfc_select_applet(&app);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, version_apdu,
                                        sizeof(version_apdu)),
           "disabled U2F should still return a status word over NFC");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2 && payload[0] == 0x6D && payload[1] == 0x00,
           "disabled U2F should reject NFC U2F APDUs with SW_INS_NOT_SUPPORTED");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "disabled U2F should not queue NFC background processing");

    test_nfc_deinit_app(&app);
}

static void test_nfc_u2f_check_only_authenticate_returns_immediately(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t authenticate_apdu[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {
        0x00,
        U2F_CMD_AUTHENTICATE,
        U2fCheckOnly,
        0x00,
        0x00,
        0x00,
        U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64,
    };
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    test_nfc_select_applet(&app);
    authenticate_apdu[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, authenticate_apdu,
                                        sizeof(authenticate_apdu)),
           "U2F check-only AUTHENTICATE over NFC should complete immediately");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U,
           "U2F check-only AUTHENTICATE should return a status word without STATUS_UPDATE");
    expect(payload[0] == 0x69 && payload[1] == 0x85,
           "valid U2F check-only AUTHENTICATE should report user presence required");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "U2F check-only AUTHENTICATE must not leave a queued NFC request");
    expect(g_approval_request_count == 0U,
           "U2F check-only AUTHENTICATE must not ask for local approval");
    expect(test_log_contains("U2F check-only"),
           "U2F check-only AUTHENTICATE should expose the immediate U2F breadcrumb");

    zf_u2f_adapter_deinit(&app);
    test_nfc_deinit_app(&app);
}

static void test_nfc_u2f_register_returns_without_status_update(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    uint8_t register_apdu[5 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = {
        0x00, U2F_CMD_REGISTER, 0x00, 0x00, U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE,
    };
    static const uint8_t get_response_apdu[] = {0x00, ZF_NFC_INS_ISO_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;
    size_t payload_len = 0U;
    size_t guard = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    expect(zf_u2f_adapter_init(&app), "U2F should initialize before NFC REGISTER");
    test_nfc_select_applet(&app);
    memset(&register_apdu[5], 0xA5, U2F_CHALLENGE_SIZE);
    memset(&register_apdu[5 + U2F_CHALLENGE_SIZE], 0x5A, U2F_APP_ID_SIZE);

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, register_apdu,
                                        sizeof(register_apdu)),
           "U2F REGISTER over NFC should complete on the raw APDU path");
    payload = test_nfc_payload();
    payload_len = test_nfc_payload_len();
    expect(!(payload_len == 3U && payload[0] == ZF_NFC_STATUS_PROCESSING && payload[1] == 0x91 &&
             payload[2] == 0x00),
           "U2F REGISTER over NFC must not use CTAP STATUS_UPDATE polling");
    expect(!app.transport_nfc_state_storage.processing &&
               !app.transport_nfc_state_storage.request_pending,
           "U2F REGISTER over NFC must not leave a queued background request");
    expect(g_approval_request_count == 0U,
           "U2F REGISTER over NFC should use transport presence instead of approval UI");

    while (payload_len >= 2U && payload[payload_len - 2U] == 0x61U && guard++ < 8U) {
        expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage,
                                            get_response_apdu, sizeof(get_response_apdu)),
               "U2F REGISTER ISO response chain should continue via GET RESPONSE");
        payload = test_nfc_payload();
        payload_len = test_nfc_payload_len();
        expect(!(payload_len == 3U && payload[0] == ZF_NFC_STATUS_PROCESSING &&
                 payload[1] == 0x91 && payload[2] == 0x00),
               "U2F REGISTER response chaining must not use CTAP STATUS_UPDATE polling");
    }

    expect(payload_len >= 2U && payload[payload_len - 2U] == 0x90 &&
               payload[payload_len - 1U] == 0x00,
           "U2F REGISTER over NFC should finish with the U2F success status word");
    expect(test_log_contains("U2F immediate"),
           "U2F REGISTER over NFC should expose the immediate U2F breadcrumb");

    zf_u2f_adapter_deinit(&app);
    test_nfc_deinit_app(&app);
}

static void test_nfc_get_response_reports_remaining_bytes(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t get_response_apdu[] = {0x80, 0xC0, 0x00, 0x00, 0x0A};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    memset(app.transport_arena, 0xAB, zf_app_transport_arena_capacity(&app));
    app.transport_nfc_state_storage.response_ready = true;
    app.transport_nfc_state_storage.response_len = 300;
    app.transport_nfc_state_storage.response_offset = 0;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "GET RESPONSE should return a partial chunk when Le is smaller than the response");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 12, "partial GET RESPONSE should return Le bytes plus SW");
    expect(payload[10] == 0x61 && payload[11] == 0x00,
           "partial GET RESPONSE should advertise remaining bytes with SW_BYTES_REMAINING");
    expect(app.transport_nfc_state_storage.response_offset == 10,
           "partial GET RESPONSE should advance the response offset");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap_get_response_ins_11_rejects_processing_without_advertised_support(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.response_ready = false;
    app.transport_nfc_state_storage.ctap_get_response_supported = false;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "CTAP GET_RESPONSE INS=0x11 should be rejected when support was not advertised");
    payload = test_nfc_payload();
    expect(
        test_nfc_payload_len() == 2U && payload[0] == 0x69 && payload[1] == 0x85,
        "CTAP GET_RESPONSE without advertised support should return SW_CONDITIONS_NOT_SATISFIED");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap_get_response_ins_11_rejects_invalid_p1_p2(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t rfu_p1_get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x01,
                                                       0x00, 0x00};
    static const uint8_t rfu_p2_get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x00,
                                                       0x01, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.response_ready = false;
    app.transport_nfc_state_storage.ctap_get_response_supported = true;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage,
                                        rfu_p1_get_response_apdu, sizeof(rfu_p1_get_response_apdu)),
           "NFCCTAP_GETRESPONSE should reject RFU P1");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6B && payload[1] == 0x00,
           "NFCCTAP_GETRESPONSE RFU P1 should return SW_WRONG_P1P2");

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage,
                                        rfu_p2_get_response_apdu, sizeof(rfu_p2_get_response_apdu)),
           "NFCCTAP_GETRESPONSE should reject RFU P2");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 2U && payload[0] == 0x6B && payload[1] == 0x00,
           "NFCCTAP_GETRESPONSE RFU P2 should return SW_WRONG_P1P2");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap_get_response_ins_11_reports_processing_with_advertised_support(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.response_ready = false;
    app.transport_nfc_state_storage.ctap_get_response_supported = true;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "CTAP GET_RESPONSE INS=0x11 should be accepted while processing");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 3U,
           "CTAP GET_RESPONSE INS=0x11 should return processing status plus SW");
    expect(payload[0] == ZF_NFC_STATUS_PROCESSING && payload[1] == 0x91 && payload[2] == 0x00,
           "CTAP GET_RESPONSE INS=0x11 should return STATUS_UPDATE while processing");

    test_nfc_deinit_app(&app);
}

static void test_nfc_busy_u2f_request_preserves_shared_arena(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t version_apdu[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    app.transport_arena[0] = 0xAB;
    app.transport_arena[1] = 0xCD;
    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.request_pending = true;
    app.transport_nfc_state_storage.response_ready = false;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, version_apdu,
                                        sizeof(version_apdu)),
           "busy NFC U2F request should return a status-update response");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 3U,
           "busy NFC U2F request should return processing status plus SW");
    expect(payload[0] == ZF_NFC_STATUS_PROCESSING && payload[1] == 0x91 && payload[2] == 0x00,
           "busy NFC U2F request should report STATUS_UPDATE");
    expect(app.transport_arena[0] == 0xAB && app.transport_arena[1] == 0xCD,
           "busy NFC U2F request should not clobber the shared arena");

    test_nfc_deinit_app(&app);
}

static void test_nfc_ctap_get_response_ins_11_returns_ready_response(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    static const uint8_t get_response_apdu[] = {0x80, ZF_NFC_INS_CTAP_GET_RESPONSE, 0x00, 0x00,
                                                0x00};
    const uint8_t *payload = NULL;
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);

    app.transport_arena[0] = 0xAB;
    app.transport_arena[1] = 0xCD;
    app.transport_nfc_state_storage.response_ready = true;
    app.transport_nfc_state_storage.response_len = 2U;
    app.transport_nfc_state_storage.response_offset = 0U;

    expect(zf_transport_nfc_handle_apdu(&app, &app.transport_nfc_state_storage, get_response_apdu,
                                        sizeof(get_response_apdu)),
           "CTAP GET_RESPONSE INS=0x11 should return a ready CTAP response");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 4U,
           "CTAP GET_RESPONSE INS=0x11 should return response bytes plus SW");
    expect(payload[0] == 0xAB && payload[1] == 0xCD && payload[2] == 0x90 && payload[3] == 0x00,
           "CTAP GET_RESPONSE INS=0x11 should terminate the ready response with SW_SUCCESS");
    expect(!app.transport_nfc_state_storage.response_ready,
           "complete CTAP GET_RESPONSE should clear the queued response");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);
    expect(zf_transport_nfc_replay_last_iso_response(&app.transport_nfc_state_storage),
           "complete CTAP GET_RESPONSE should remain replayable for reader R-NAK");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "complete CTAP GET_RESPONSE replay should resend the same ISO-DEP frame");

    test_nfc_deinit_app(&app);
}

static void test_nfc_field_off_marks_current_session_canceled(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    Iso14443_4aListenerEvent listener_event = {.type = Iso14443_4aListenerEventTypeFieldOff};
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    test_nfc_select_applet(&app);
    app.transport_nfc_state_storage.processing = true;
    app.transport_nfc_state_storage.request_pending = true;
    app.transport_nfc_state_storage.processing_session_id =
        app.transport_nfc_state_storage.session_id;

    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "field-off should put the NFC listener to sleep");
    expect(zf_transport_nfc_poll_cbor_control(&app, app.transport_nfc_state_storage.session_id) ==
               ZF_CTAP_ERR_KEEPALIVE_CANCEL,
           "field-off should surface transport cancellation for the active NFC session");
    expect(g_cancel_pending_interaction_count == 1,
           "field-off should cancel any pending user interaction");
    expect(g_transport_connected_set_count == 1 && !g_last_transport_connected,
           "field-off should publish that the NFC transport disconnected");

    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_raw60_sends_iso_status(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "raw 0x60 should receive an unsupported status before SELECT");
    expect(g_nfc_tx_count == 1U && g_last_nfc_tx_len == 11U && g_last_nfc_tx[0] == 0x02 &&
               g_last_nfc_tx[1] == 0xAF && g_last_nfc_tx[2] == 0x04,
           "raw 0x60 should transmit status-first native DESFire version data inside an I-block");
    expect(test_log_contains("DESFire native version"),
           "raw 0x60 should expose the classifier breadcrumb");
    expect(g_transport_connected_set_count == 1U && g_last_transport_connected,
           "raw 0x60 ISO status handling should leave the NFC transport active");
    expect(g_cancel_pending_interaction_count == 0U,
           "raw 0x60 ISO status handling should not cancel pending NFC interaction");
    expect(!app.transport_nfc_state_storage.applet_selected,
           "raw native probe should not mark the FIDO applet selected");

    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);
    expect(zf_transport_nfc_replay_last_iso_response(&app.transport_nfc_state_storage),
           "first raw 0x60 response should remain replayable for discovery recovery");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "first raw 0x60 replay should resend the DESFire discovery response");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_repeated_native_desfire_probe_keeps_discovery_compatible(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    g_fake_tick = 1000U;

    for (size_t i = 0; i < 2U; ++i) {
        bit_buffer_reset(buffer);
        bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02, 0x60}, 2U);
        expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
               "first native DESFire discovery probes should remain compatible");
        expect(g_last_nfc_tx_len == 11U && (g_last_nfc_tx[0] & 0xFEU) == 0x02 &&
                   g_last_nfc_tx[1] == 0xAF,
               "allowed native DESFire discovery should return the version shim");
        g_fake_tick += 100U;
    }

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x02, 0x60}, 2U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "repeated native DESFire discovery should remain compatible with the known-good path");
    expect(g_nfc_tx_count == 3U && g_last_nfc_tx_len == 11U && (g_last_nfc_tx[0] & 0xFEU) == 0x02 &&
               g_last_nfc_tx[1] == 0xAF,
           "repeated native DESFire discovery should keep returning the version shim");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x02, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "native DESFire discovery should not block FIDO SELECT");
    expect(app.transport_nfc_state_storage.applet_selected,
           "FIDO SELECT after repeated DESFire discovery should select the applet");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_native_desfire_preserves_existing_fido_replay(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    static const uint8_t fido_response[] = {0x01, 0xA0};
    uint8_t cached_response[sizeof(g_last_nfc_tx)] = {0};
    size_t cached_response_len = 0U;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    expect(zf_transport_nfc_send_apdu_payload(&app.transport_nfc_state_storage, fido_response,
                                              sizeof(fido_response), ZF_NFC_SW_SUCCESS),
           "test should prime an existing FIDO replay response");
    cached_response_len = g_last_nfc_tx_len;
    memcpy(cached_response, g_last_nfc_tx, cached_response_len);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "native DESFire discovery should still be answered while a FIDO replay exists");
    expect(g_last_nfc_tx_len != cached_response_len ||
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) != 0,
           "native DESFire discovery should transmit its own response first");

    expect(zf_transport_nfc_replay_last_iso_response(&app.transport_nfc_state_storage),
           "native DESFire discovery should preserve the existing FIDO replay cache");
    expect(g_last_nfc_tx_len == cached_response_len &&
               memcmp(g_last_nfc_tx, cached_response, cached_response_len) == 0,
           "replay after native DESFire discovery should resend the prior FIDO response");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_raw60_does_not_make_next_framed_select_bare(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(32U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };
    const uint8_t *payload = NULL;

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "raw 0x60 should receive an unsupported status before SELECT");
    expect(g_nfc_tx_count == 1U && g_last_nfc_tx[0] == 0x02 && g_last_nfc_tx[1] == 0xAF &&
               g_last_nfc_tx[2] == 0x04,
           "raw 0x60 should be answered as status-first native DESFire version data");

    bit_buffer_reset(buffer);
    bit_buffer_append_bytes(buffer,
                            (const uint8_t[]){0x03, 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00,
                                              0x06, 0x47, 0x2F, 0x00, 0x01},
                            14U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "framed SELECT after raw 0x60 should still be accepted");
    expect(g_last_nfc_tx[0] == 0x03,
           "framed SELECT after raw 0x60 should receive an ISO-DEP I-block response");
    payload = test_nfc_payload();
    expect(test_nfc_payload_len() == 8U && memcmp(payload, "U2F_V2", 6) == 0 &&
               payload[6] == 0x90 && payload[7] == 0x00,
           "framed SELECT after raw 0x60 should not be sent as a bare APDU response");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_preselect_raw_native_probe_traces_halt(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "raw 0x60 should be observed before halt");

    listener_event.type = Iso14443_4aListenerEventTypeHalted;
    listener_event.data = NULL;
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "halt after raw native probe should sleep the NFC listener");
    expect(g_last_transport_connected == false,
           "halt after raw 0x60 should publish that NFC disconnected");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_nfc_selected_raw_native_probe_traces_selected_state(void) {
    ZerofidoApp app;
    FuriMutex mutex = {0};
    BitBuffer *buffer = bit_buffer_alloc(8U);
    Iso14443_4aListenerEventData event_data = {.buffer = buffer};
    Iso14443_4aListenerEvent listener_event = {
        .type = Iso14443_4aListenerEventTypeReceivedData,
        .data = &event_data,
    };
    NfcGenericEvent event = {
        .protocol = NfcProtocolIso14443_4a,
        .event_data = &listener_event,
    };

    test_reset();
    test_nfc_init_app(&app, &mutex);
    app.transport_nfc_state_storage.applet_selected = true;

    bit_buffer_append_bytes(buffer, (const uint8_t[]){0x60}, 1U);
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandContinue,
           "raw 0x60 should be observed after SELECT");
    expect(test_log_contains("DESFire native version"),
           "selected raw 0x60 should expose the terminal ISO status breadcrumb");
    expect(app.transport_nfc_state_storage.applet_selected,
           "selected raw 0x60 ISO status should preserve the selected applet state");

    listener_event.type = Iso14443_4aListenerEventTypeHalted;
    listener_event.data = NULL;
    expect(zf_transport_nfc_event_callback(event, &app) == NfcCommandSleep,
           "halt after selected raw 0x60 should sleep the NFC listener");
    expect(g_last_transport_connected == false,
           "halt after selected raw 0x60 should publish that NFC disconnected");

    bit_buffer_free(buffer);
    test_nfc_deinit_app(&app);
}

static void test_short_u2f_version_request_is_accepted(void) {
    uint8_t request[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};

    expect(u2f_validate_request(request, sizeof(request)) == 0,
           "5-byte short U2F VERSION APDUs must validate");
}

static void test_header_only_u2f_version_request_is_accepted_for_stock_compatibility(void) {
    uint8_t request[] = {0x00, U2F_CMD_VERSION, 0x00, 0x00};

    expect(u2f_validate_request(request, sizeof(request)) == 0,
           "4-byte header-only U2F VERSION APDUs must validate for stock compatibility");
}

static void test_u2f_version_accepts_exact_response_buffer(void) {
    U2fData u2f = {0};
    uint8_t request[8] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00};

    u2f.ready = true;
    expect(u2f_msg_parse(&u2f, request, 5, 8) == 8,
           "U2F VERSION should fit in an exact-size response buffer");
    expect(memcmp(request, "U2F_V2", 6) == 0,
           "U2F VERSION response should include the version string");
    expect(request[6] == 0x90 && request[7] == 0x00,
           "U2F VERSION response should include success status bytes");
}

static void test_u2f_version_accepts_extended_length_encoding(void) {
    U2fData u2f = {0};
    uint8_t request[8] = {0x00, U2F_CMD_VERSION, 0x00, 0x00, 0x00, 0x00, 0x00};

    u2f.ready = true;
    expect(u2f_validate_request(request, 7) == 0,
           "7-byte extended-length U2F VERSION APDUs must validate");
    expect(u2f_msg_parse(&u2f, request, 7, 8) == 8,
           "7-byte extended-length U2F VERSION APDUs should return U2F_V2");
    expect(memcmp(request, "U2F_V2", 6) == 0,
           "extended-length U2F VERSION should return the version string");
    expect(request[6] == 0x90 && request[7] == 0x00,
           "extended-length U2F VERSION should include success status bytes");
}

static void test_u2f_version_extended_length_with_data_returns_wrong_length(void) {
    const uint8_t raw_request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16,
        0xfa, 0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92,
        0xf1, 0xef, 0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08,
        0x44, 0x3b, 0x4a, 0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };
    uint8_t request[sizeof(raw_request)] = {0};
    uint8_t response[2] = {0};

    memcpy(request, raw_request, sizeof(request));
    expect(u2f_validate_request(request, sizeof(request)) == 2,
           "extended-length U2F VERSION APDU with data must be rejected");
    expect(request[0] == 0x67 && request[1] == 0x00,
           "extended-length U2F VERSION APDU with data must return SW_WRONG_LENGTH");
    memcpy(request, raw_request, sizeof(request));
    expect(u2f_validate_request_into_response(request, sizeof(request), response,
                                              sizeof(response)) == 2,
           "extended-length U2F VERSION APDU with data must encode a two-byte status response");
    expect(response[0] == 0x67 && response[1] == 0x00,
           "extended-length U2F VERSION APDU with data must encode SW_WRONG_LENGTH");
}

static void test_u2f_register_allows_nonzero_p1_p2_for_stock_compatibility(void) {
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = {0};

    request[0] = 0x00;
    request[1] = U2F_CMD_REGISTER;
    request[2] = 0x03;
    request[3] = 0x01;
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE;

    expect(u2f_validate_request(request, sizeof(request)) == 0,
           "REGISTER should accept nonzero P1/P2 to match stock U2F compatibility handling");
}

static void test_u2f_dont_enforce_authenticate_mode_is_accepted_without_presence(void) {
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {0};
    const char *operation = NULL;
    U2fData u2f = {0};
    uint16_t response_len = 0;

    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fDontEnforce;
    request[3] = 0x00;
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;

    u2f.ready = true;
    expect(u2f_validate_request(request, sizeof(request)) == 0,
           "dont-enforce U2F authenticate mode should be accepted");
    expect(!u2f_request_needs_user_presence(request, sizeof(request), &operation),
           "dont-enforce U2F authenticate mode should not request user presence");
    response_len = u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request));
    expect(response_len > sizeof(U2fAuthResp),
           "dont-enforce U2F authenticate mode should produce a signature response");
    expect(request[0] == 0x00,
           "dont-enforce U2F authenticate mode should not set the UP bit without presence");
    expect(request[response_len - 2] == 0x90 && request[response_len - 1] == 0x00,
           "dont-enforce U2F authenticate mode should return success status");
}

static void test_u2f_enforce_authenticate_rejects_invalid_handle_before_presence(void) {
    U2fData u2f = {0};
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {0};

    u2f.ready = true;
    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fEnforce;
    request[3] = 0x00;
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;
    memset(&request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1], 0xAB, 64);

    expect(u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request)) == 2,
           "invalid-handle U2F AUTHENTICATE should return a status word");
    expect(request[0] == 0x6A && request[1] == 0x80,
           "invalid-handle U2F AUTHENTICATE should return wrong data before user presence");
}

static void test_u2f_invalid_handle_clears_consumed_presence(void) {
    U2fData u2f = {0};
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {0};

    u2f.ready = true;
    u2f.user_present = true;
    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fEnforce;
    request[3] = 0x00;
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;
    memset(&request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1], 0xAB, 64);

    expect(u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request)) == 2,
           "invalid-handle U2F AUTHENTICATE should return a status word");
    expect(!u2f.user_present,
           "invalid-handle U2F AUTHENTICATE should not leave user presence latched");
}

static void test_u2f_enforce_authenticate_hash_includes_user_presence_flag(void) {
    U2fData u2f = {0};
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {0};
    uint16_t response_len = 0;

    test_reset();
    u2f.ready = true;
    u2f.user_present = true;
    u2f.counter = 7;
    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fEnforce;
    request[3] = 0x00;
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;

    response_len = u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request));

    expect(response_len > sizeof(U2fAuthResp),
           "enforce authenticate should produce a signature response when presence is available");
    const size_t preimage_len = U2F_APP_ID_SIZE + 1 + sizeof(uint32_t) + U2F_CHALLENGE_SIZE;
    const uint8_t *preimage = g_sha256_trace;

    expect(g_sha256_trace_len >= preimage_len,
           "authenticate signature preimage should cover appId, flags, counter, and challenge");
    preimage = &g_sha256_trace[g_sha256_trace_len - preimage_len];
    expect(preimage[U2F_APP_ID_SIZE] == 0x01,
           "authenticate signature preimage should include the UP flag when presence was consumed");
    expect(request[0] == 0x01, "authenticate response should also expose the UP flag");
}

static void test_u2f_authenticate_reserves_counter_window(void) {
    U2fData u2f = {0};
    uint8_t request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64] = {0};
    uint16_t response_len = 0;

    test_reset();
    u2f.ready = true;
    u2f.counter = 7;
    u2f.counter_high_water = 7;

    u2f.user_present = true;
    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fEnforce;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;
    response_len = u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request));

    expect(response_len > sizeof(U2fAuthResp), "first authenticate should succeed");
    expect(u2f.counter == 8, "first authenticate should advance the in-memory counter");
    expect(g_u2f_cnt_reserve_count == 1, "first authenticate should reserve a counter window");
    expect(u2f.counter_high_water == g_u2f_last_reserved_counter,
           "reserved counter high-water should be cached in memory");

    memset(request, 0, sizeof(request));
    u2f.user_present = true;
    request[0] = 0x00;
    request[1] = U2F_CMD_AUTHENTICATE;
    request[2] = U2fEnforce;
    request[6] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE + 1 + 64;
    request[7 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = 64;
    response_len = u2f_msg_parse(&u2f, request, sizeof(request), sizeof(request));

    expect(response_len > sizeof(U2fAuthResp), "second authenticate should succeed");
    expect(u2f.counter == 9, "second authenticate should advance the in-memory counter");
    expect(g_u2f_cnt_reserve_count == 1,
           "second authenticate inside the window should not rewrite the counter file");
}

static void test_zf_u2f_adapter_init_allows_missing_attestation_assets(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_u2f_cert_assets_present = false;

    expect(zf_u2f_adapter_init(&app), "U2F init should generate missing attestation assets");
    expect(g_u2f_attestation_ensure_call_count == 1,
           "U2F init should synthesize local attestation assets when none are present");
    expect(app.u2f != NULL && app.u2f->ready,
           "U2F instance should be ready after generating attestation assets");
    expect(app.u2f->cert_ready, "generated U2F attestation should enable U2F register");

    zf_u2f_adapter_deinit(&app);
}

static void test_zf_u2f_adapter_init_creates_missing_device_key_and_counter(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_u2f_key_load_result = false;
    g_u2f_key_exists_result = false;
    g_u2f_cnt_read_result = false;
    g_u2f_cnt_exists_result = false;

    expect(zf_u2f_adapter_init(&app),
           "U2F init should generate missing filesystem-backed key material");
    expect(g_u2f_key_generate_count == 1,
           "U2F init should generate the device key when the key file is missing");
    expect(g_u2f_cnt_write_count == 1,
           "U2F init should create the counter file when the counter file is missing");
    expect(g_u2f_last_written_counter == 0,
           "U2F init should initialize a missing counter file to zero");
    expect(app.u2f != NULL && app.u2f->ready,
           "U2F instance should be ready after creating missing key material");

    zf_u2f_adapter_deinit(&app);
}

static void test_zf_u2f_adapter_init_allows_invalid_attestation_assets(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = false;

    expect(zf_u2f_adapter_init(&app),
           "U2F init should replace attestation assets that fail validation");
    expect(g_u2f_attestation_ensure_call_count == 1,
           "U2F init should synthesize local attestation assets when existing assets are invalid");
    expect(app.u2f != NULL && app.u2f->ready,
           "U2F instance should be ready after replacing invalid attestation assets");
    expect(app.u2f->cert_ready, "regenerated U2F attestation should enable U2F register");

    zf_u2f_adapter_deinit(&app);
}

static void test_u2f_adapter_auto_accept_bypasses_approval_prompt(void) {
    ZerofidoApp app = {0};
    uint8_t request[5 + U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE] = {0};
    uint8_t response[512] = {0};
    size_t response_len = 0;

    test_reset();
    g_auto_accept_requests = true;
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.runtime_config.auto_accept_requests = true;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_u2f_adapter_init(&app), "U2F init should succeed before auto-accept register");
    request[0] = 0x00;
    request[1] = U2F_CMD_REGISTER;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = U2F_CHALLENGE_SIZE + U2F_APP_ID_SIZE;

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len > 2, "auto-accept U2F register should still return a full response");
    expect(response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00,
           "auto-accept U2F register should succeed");
    expect(g_approval_request_count == 0,
           "auto-accept U2F register should bypass the approval prompt");

    zf_u2f_adapter_deinit(&app);
}

static void test_u2f_adapter_invalid_cla_returns_cla_not_supported(void) {
    ZerofidoApp app = {0};
    uint8_t request[5] = {0};
    uint8_t response[16] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_u2f_adapter_init(&app), "U2F init should succeed before invalid-CLA adapter test");

    request[0] = 0x01;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x00;

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len == 2, "invalid-CLA U2F APDU should return only a status word");
    expect(response[0] == 0x6E && response[1] == 0x00,
           "invalid-CLA U2F APDU should return SW_CLA_NOT_SUPPORTED");
    expect(g_approval_request_count == 0,
           "invalid-CLA U2F APDU should not trigger an approval request");

    zf_u2f_adapter_deinit(&app);
}

static void test_u2f_adapter_invalid_cla_returns_cla_not_supported_without_live_backend(void) {
    ZerofidoApp app = {0};
    uint8_t request[5] = {0};
    uint8_t response[16] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    request[0] = 0x01;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x00;

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len == 2,
           "invalid-CLA U2F APDU should still return a status word without a live backend");
    expect(response[0] == 0x6E && response[1] == 0x00,
           "invalid-CLA U2F APDU should still return SW_CLA_NOT_SUPPORTED without a live backend");
}

static void test_u2f_adapter_version_returns_u2f_v2_without_live_backend(void) {
    ZerofidoApp app = {0};
    uint8_t request[5] = {0};
    uint8_t response[16] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    request[0] = 0x00;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x00;

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len == 8, "VERSION U2F APDU should still return U2F_V2 without a live backend");
    expect(memcmp(response, "U2F_V2", 6) == 0,
           "VERSION U2F APDU should return the version string without a live backend");
    expect(response[6] == 0x90 && response[7] == 0x00,
           "VERSION U2F APDU should return SW_NO_ERROR without a live backend");
}

static void test_u2f_adapter_version_with_data_returns_wrong_length_without_full_copy(void) {
    ZerofidoApp app = {0};
    uint8_t request[5 + 64] = {0};
    uint8_t response[2] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    request[0] = 0x00;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 64;
    memset(&request[5], 0xA5, 64);

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len == 2, "VERSION APDU with unexpected data should return a status word "
                              "without a full request copy");
    expect(response[0] == 0x67 && response[1] == 0x00,
           "VERSION APDU with unexpected data should return SW_WRONG_LENGTH");
}

static void test_u2f_adapter_version_extended_length_with_data_returns_wrong_length(void) {
    ZerofidoApp app = {0};
    uint8_t request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16,
        0xfa, 0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92,
        0xf1, 0xef, 0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08,
        0x44, 0x3b, 0x4a, 0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };
    uint8_t response[2] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    response_len = zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response,
                                             sizeof(response));

    expect(response_len == 2,
           "extended-length VERSION APDU with data should return only a status word");
    expect(response[0] == 0x67 && response[1] == 0x00,
           "extended-length VERSION APDU with data should return SW_WRONG_LENGTH");
}

static void test_transport_reclaims_lru_cid_when_table_is_full(void) {
    ZfTransportState transport = {0};

    test_reset();
    for (size_t i = 0; i < ZF_MAX_ALLOCATED_CIDS; ++i) {
        g_fake_tick = 100U + (uint32_t)i;
        expect(zf_transport_remember_cid(&transport, 0x01020300U + (uint32_t)i),
               "fill transport CID table");
    }

    g_fake_tick = 500U;
    expect(zf_transport_remember_cid(&transport, 0xAABBCCDDU),
           "remembering a new CID should reclaim the least-recently-used slot when full");
    expect(transport.allocated_count == ZF_MAX_ALLOCATED_CIDS,
           "CID table should stay bounded after reclaiming a full table");
    expect(!zf_transport_cid_is_allocated(&transport, 0x01020300U),
           "the least-recently-used CID should be reclaimed first");
    expect(zf_transport_cid_is_allocated(&transport, 0xAABBCCDDU),
           "new CID should be tracked after reclaiming an old slot");
}

static void test_transport_allocate_cid_reclaims_lru_when_table_is_full(void) {
    ZfTransportState transport = {0};
    uint32_t allocated_cid = 0;

    test_reset();
    for (size_t i = 0; i < ZF_MAX_ALLOCATED_CIDS; ++i) {
        g_fake_tick = 200U + (uint32_t)i;
        expect(zf_transport_remember_cid(&transport, 0x02030400U + (uint32_t)i),
               "fill allocator CID table");
    }

    g_random_values[0] = 0xCAFEBABEU;
    g_random_count = 1;
    g_fake_tick = 800U;
    expect(zf_transport_allocate_cid(&transport, &allocated_cid),
           "broadcast INIT should reclaim a least-recently-used CID when the table is full");
    expect(allocated_cid == 0xCAFEBABEU, "allocator should return the newly assigned CID");
    expect(!zf_transport_cid_is_allocated(&transport, 0x02030400U),
           "allocator should reclaim the oldest tracked CID first");
    expect(zf_transport_cid_is_allocated(&transport, 0xCAFEBABEU),
           "reclaimed allocation should remember the new CID");
}

static void test_transport_cancel_marks_processing_request_without_pending_approval(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t cancel_packet[7] = {0};
    uint32_t actions = 0;

    test_reset();
    app.transport_state = &transport;
    transport.processing = true;
    transport.cmd = ZF_CTAPHID_CBOR;
    transport.cid = 0x01020304U;

    memcpy(cancel_packet, &transport.cid, sizeof(transport.cid));
    cancel_packet[4] = ZF_CTAPHID_CANCEL;

    expect(zf_transport_handle_init_command(&app, &transport, transport.cid, ZF_CTAPHID_CANCEL, 0,
                                            cancel_packet, sizeof(cancel_packet), &actions),
           "matching CANCEL should be handled while a CBOR request is processing");
    expect(transport.processing_cancel_requested,
           "CANCEL should mark the outstanding CBOR request as cancelled");
    expect(actions & ZF_TRANSPORT_ACTION_CANCEL_PENDING_INTERACTION,
           "CANCEL should request pending-interaction dismissal");
    expect(zf_transport_usb_hid_poll_cbor_control(&app, transport.cid) ==
               ZF_CTAP_ERR_KEEPALIVE_CANCEL,
           "polling should surface a previously latched cancel request");
}

static void test_transport_active_other_cid_short_init_returns_busy(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[5] = {0};
    uint32_t cid = 0x0A0B0C0DU;

    test_reset();
    transport.active = true;
    transport.cid = 0x01020304U;
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_INIT;

    zf_transport_handle_init_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response_len == sizeof(g_last_hid_response),
           "busy init should emit a single HID error frame");
    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "busy init should return a HID error response");
    expect(g_last_hid_response[7] == ZF_HID_ERR_CHANNEL_BUSY,
           "busy init should classify the packet as channel busy");
}

static void test_transport_processing_other_cid_short_init_returns_busy(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[5] = {0};
    uint32_t cid = 0x0A0B0C0DU;

    test_reset();
    transport.processing = true;
    transport.cid = 0x01020304U;
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_INIT;

    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response_len == sizeof(g_last_hid_response),
           "busy processing init should emit a single HID error frame");
    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "busy processing init should return a HID error response");
    expect(g_last_hid_response[7] == ZF_HID_ERR_CHANNEL_BUSY,
           "busy processing init should classify the packet as channel busy");
}

static void test_transport_processing_broadcast_init_recovers_channel(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[15] = {0};
    static const uint8_t nonce[8] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97};
    const uint32_t cid = 0x01020304U;
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;
    uint32_t assigned_cid = 0U;

    test_reset();
    transport.processing = true;
    transport.cid = cid;
    transport.cmd = ZF_CTAPHID_MSG;
    g_random_values[0] = 0x55667788U;
    g_random_count = 1;

    memcpy(packet, &broadcast_cid, sizeof(broadcast_cid));
    packet[4] = ZF_CTAPHID_INIT;
    packet[5] = 0x00;
    packet[6] = 0x08;
    memcpy(&packet[7], nonce, sizeof(nonce));

    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "broadcast INIT should recover from a processing U2F transaction");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "broadcast INIT recovery should echo the request nonce");
    memcpy(&assigned_cid, &g_last_hid_response[15], sizeof(assigned_cid));
    expect(assigned_cid == 0x55667788U, "broadcast INIT recovery should allocate a fresh channel");
    expect(!transport.processing, "broadcast INIT recovery should stop the stale transaction");
    expect(transport.processing_cancel_requested,
           "broadcast INIT recovery should mark the stale transaction canceled");
}

static void test_usb_restore_keeps_previous_config_after_restore_failure(void) {
    ZerofidoApp app = {0};

    test_reset();
    app.previous_usb = &g_previous_usb_config;
    g_usb_set_config_result = false;

    zf_transport_restore_usb(&app);

    expect(g_usb_set_config_count == 1, "restore should attempt the previous USB config");
    expect(g_last_usb_set_config == &g_previous_usb_config,
           "restore should pass the saved USB config back to HAL");
    expect(app.previous_usb == &g_previous_usb_config,
           "failed restore should keep previous USB config for a retry");
    expect(strcmp(g_last_status_text, "USB restore failed") == 0,
           "failed restore should publish a status message");

    g_usb_set_config_result = true;
    zf_transport_restore_usb(&app);

    expect(g_usb_set_config_count == 2, "retry should attempt USB restore again");
    expect(app.previous_usb == NULL, "successful restore should clear previous USB config");
}

static void test_usb_worker_polls_while_idle_and_assembling(void) {
    ZfTransportState transport = {0};

    expect(zf_transport_worker_next_timeout(&transport) == ZF_WORKER_POLL_MS,
           "idle USB worker should poll for queued HID requests without a wakeup");
    transport.active = true;
    expect(zf_transport_worker_next_timeout(&transport) == ZF_WORKER_POLL_MS,
           "active USB assembly still needs timeout polling");
}

static void test_nfc_worker_waits_forever_while_idle(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_thread_flag_results[0] = ZF_NFC_WORKER_EVT_STOP;
    g_thread_flag_result_count = 1;

    expect(zf_transport_nfc_worker(&app) == 0, "NFC worker should exit cleanly on stop");
    expect(g_last_thread_wait_timeout == FuriWaitForever,
           "idle NFC worker should wait indefinitely for request or stop events");
}

static void test_nfc_worker_releases_transport_arena_on_listener_alloc_failure(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_nfc_listener_alloc_result = false;

    expect(zf_transport_nfc_worker(&app) == 0, "NFC worker should exit cleanly on listener OOM");
    expect(app.transport_arena == NULL, "NFC listener failure should release the transport arena");
    expect(app.transport_arena_size == 0,
           "NFC listener failure should clear the transport arena size");
    expect(strcmp(g_last_status_text, "NFC listener failed") == 0,
           "NFC listener failure should publish a status message");
}

static void test_nfc_worker_releases_transport_arena_on_resource_alloc_failure(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_nfc_alloc_result = false;

    expect(zf_transport_nfc_worker(&app) == 0, "NFC worker should exit cleanly on resource OOM");
    expect(app.transport_arena == NULL, "NFC resource failure should release the transport arena");
    expect(app.transport_arena_size == 0,
           "NFC resource failure should clear the transport arena size");
    expect(strcmp(g_last_status_text, "NFC init failed") == 0,
           "NFC resource failure should publish a status message");
}

static void test_transport_worker_processes_disconnect_when_coalesced_with_interaction(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_cancel_pending_interaction_result = true;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    g_thread_flag_results[0] = ZF_WORKER_EVT_APPROVAL | ZF_WORKER_EVT_DISCONNECT;
    g_thread_flag_results[1] = ZF_WORKER_EVT_STOP;
    g_thread_flag_result_count = 2;

    expect(zf_transport_usb_hid_worker(&app) == 0, "worker should exit cleanly in native harness");
    expect(g_cancel_pending_interaction_count >= 1,
           "disconnect work should not be dropped when interaction shares the wakeup");
    expect(g_transport_connected_set_count >= 1,
           "disconnect work should still update transport connection state");
    expect(!g_last_transport_connected, "disconnect work should mark transport as disconnected");
}

static void test_wait_for_interaction_processes_disconnect_when_coalesced_with_completion(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    FuriSemaphore done = {0};
    bool approved = false;

    test_reset();
    app.transport_state = &transport;
    app.approval.done = &done;
    app.approval.state = ZfApprovalApproved;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    g_cancel_pending_interaction_result = true;
    g_semaphore_results[0] = 1;
    g_semaphore_results[1] = FuriStatusOk;
    g_semaphore_result_count = 2;
    g_thread_flag_results[0] = ZF_WORKER_EVT_APPROVAL | ZF_WORKER_EVT_DISCONNECT;
    g_thread_flag_result_count = 1;

    expect(zf_transport_usb_hid_wait_for_interaction(&app, 0x01020304, &approved),
           "interaction wait should still complete in native harness");
    expect(approved, "interaction wait should preserve the approved state");
    expect(g_cancel_pending_interaction_count == 1,
           "interaction wakeups should still drain disconnect work while waiting");
    expect(g_transport_connected_set_count == 1,
           "interaction wait should still update transport state for disconnects");
    expect(!g_last_transport_connected, "interaction wait should mark transport as disconnected");
}

static void test_wait_for_interaction_sends_immediate_keepalive(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    FuriSemaphore done = {0};
    bool approved = false;
    const uint32_t cid = 0x01020304;

    test_reset();
    app.transport_state = &transport;
    app.approval.done = &done;
    app.approval.state = ZfApprovalApproved;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    transport.cmd = ZF_CTAPHID_CBOR;
    g_semaphore_results[0] = 1;
    g_semaphore_results[1] = FuriStatusOk;
    g_semaphore_result_count = 2;

    expect(zf_transport_usb_hid_wait_for_interaction(&app, cid, &approved),
           "interaction wait should complete after immediate keepalive");
    expect(approved, "interaction wait should preserve approved result after keepalive");
    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "immediate keepalive should emit one HID frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "keepalive frame should target the active CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_KEEPALIVE,
           "interaction wait should emit CTAPHID_KEEPALIVE immediately");
    expect(g_last_hid_response[5] == 0 && g_last_hid_response[6] == 1,
           "keepalive frame should advertise a one-byte payload");
    expect(g_last_hid_response[7] == ZF_KEEPALIVE_UPNEEDED,
           "interaction wait should use STATUS_UPNEEDED for touch prompts");
    expect(g_last_thread_wait_timeout == ZF_KEEPALIVE_INTERVAL_MS,
           "interaction wait should sleep only until the next keepalive interval");
}

static void test_wait_for_interaction_repeats_keepalive_on_timeout(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    FuriSemaphore done = {0};
    bool approved = false;
    const uint32_t cid = 0x01020304U;

    test_reset();
    app.transport_state = &transport;
    app.approval.done = &done;
    app.approval.state = ZfApprovalApproved;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    transport.cmd = ZF_CTAPHID_CBOR;
    g_semaphore_results[0] = 1;
    g_semaphore_results[1] = FuriStatusOk;
    g_semaphore_result_count = 2;

    expect(zf_transport_usb_hid_wait_for_interaction(&app, cid, &approved),
           "interaction wait should complete after a timeout-driven keepalive retry");
    expect(approved, "interaction wait should preserve approved result after timeout retry");
    expect(g_hid_response_count == 2,
           "timeout-driven keepalive should emit an immediate and a repeated keepalive");
    expect(g_last_thread_wait_timeout == ZF_KEEPALIVE_INTERVAL_MS,
           "interaction wait should use the keepalive interval as its timeout");
}

static void test_wait_for_interaction_omits_keepalive_for_u2f_msg(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    FuriSemaphore done = {0};
    bool approved = false;

    test_reset();
    app.transport_state = &transport;
    app.approval.done = &done;
    app.approval.state = ZfApprovalApproved;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    transport.cmd = ZF_CTAPHID_MSG;
    g_semaphore_results[0] = 1;
    g_semaphore_results[1] = FuriStatusOk;
    g_semaphore_result_count = 2;

    expect(zf_transport_usb_hid_wait_for_interaction(&app, 0x01020304U, &approved),
           "U2F MSG interaction wait should complete without keepalive");
    expect(approved, "U2F MSG interaction wait should preserve approved result");
    expect(g_hid_response_count == 0,
           "U2F MSG approval wait should not interleave CTAPHID_KEEPALIVE frames");
}

static void test_transport_fragment_expires_on_session_tick(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before fragmented PING for timeout handling");

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x00;
    packet[6] = 0x3C;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);

    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active, "fragmented PING should remain active until continuation arrives");
    g_fake_tick = transport.last_activity + ZF_ASSEMBLY_TIMEOUT_MS;
    zf_transport_session_tick(&transport, g_fake_tick);
    expect(!transport.active, "session tick should expire fragmented assemblies");
    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "expired assembly should emit a HID error response");
    expect(g_last_hid_response[7] == ZF_HID_ERR_MSG_TIMEOUT,
           "expired assembly should report MSG_TIMEOUT");
}

static void test_transport_request_wakeup_processes_one_complete_transaction(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce_a[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    static const uint8_t nonce_b[8] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();

    memcpy(g_hid_request_packets[0], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[0][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[0][5] = 0x00;
    g_hid_request_packets[0][6] = 0x08;
    memcpy(&g_hid_request_packets[0][7], nonce_a, sizeof(nonce_a));
    g_hid_request_packet_lens[0] = 15;

    memcpy(g_hid_request_packets[1], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[1][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[1][5] = 0x00;
    g_hid_request_packets[1][6] = 0x08;
    memcpy(&g_hid_request_packets[1][7], nonce_b, sizeof(nonce_b));
    g_hid_request_packet_lens[1] = 15;

    g_hid_request_count = 2;

    zf_transport_handle_request(&app, &transport, ZF_WORKER_EVT_REQUEST, packet);

    expect(g_hid_request_index == 1,
           "request wakeup should leave later complete transactions for a later worker pass");
    expect(g_hid_response_count == 1, "one worker pass should produce one complete HID response");
    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "the first queued packet should complete normally");
    expect(memcmp(&g_last_hid_response[7], nonce_a, sizeof(nonce_a)) == 0,
           "the first INIT response should echo the first queued request nonce");
}

static void test_transport_request_without_wakeup_marks_connected_and_processes_packet(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce[8] = {0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A};
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();

    memcpy(g_hid_request_packets[0], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[0][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[0][5] = 0x00;
    g_hid_request_packets[0][6] = 0x08;
    memcpy(&g_hid_request_packets[0][7], nonce, sizeof(nonce));
    g_hid_request_packet_lens[0] = 15;
    g_hid_request_count = 1;

    zf_transport_handle_request(&app, &transport, 0, packet);

    expect(g_transport_connected_set_count == 1,
           "observed HID traffic should mark transport connected even without a request event");
    expect(g_last_transport_connected,
           "observed HID traffic should switch the UI state to connected");
    expect(g_hid_response_count == 1,
           "observed HID traffic should still be processed without a request event");
    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "fallback request processing should complete the INIT transaction");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "fallback request processing should echo the INIT nonce");
}

static void test_transport_worker_idle_poll_processes_immediate_u2f_invalid_cla(void) {
    ZerofidoApp app = {0};
    static const uint8_t nonce[8] = {0x1B, 0x61, 0x8C, 0x6B, 0xC8, 0xC7, 0x07, 0x42};
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;
    const uint32_t cid = 0x9DD5F6E9U;
    const uint8_t request[] = {0x6D, U2F_CMD_VERSION, 0x00, 0x00, 0x00, 0x00, 0x00};

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_random_values[0] = cid;
    g_random_count = 1;

    memcpy(g_hid_request_packets[0], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[0][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[0][5] = 0x00;
    g_hid_request_packets[0][6] = 0x08;
    memcpy(&g_hid_request_packets[0][7], nonce, sizeof(nonce));
    g_hid_request_packet_lens[0] = 15;

    memcpy(g_hid_request_packets[1], &cid, sizeof(cid));
    g_hid_request_packets[1][4] = ZF_CTAPHID_MSG;
    g_hid_request_packets[1][5] = 0x00;
    g_hid_request_packets[1][6] = sizeof(request);
    memcpy(&g_hid_request_packets[1][7], request, sizeof(request));
    g_hid_request_packet_lens[1] = 7 + sizeof(request);
    g_hid_request_count = 2;

    g_thread_flag_results[0] = FuriFlagErrorTimeout;
    g_thread_flag_results[1] = FuriFlagErrorTimeout;
    g_thread_flag_results[2] = ZF_WORKER_EVT_STOP;
    g_thread_flag_result_count = 3;

    expect(zf_transport_usb_hid_worker(&app) == 0, "worker should exit cleanly in native harness");
    expect(g_hid_request_index == g_hid_request_count,
           "idle polls should drain the queued INIT and immediate U2F MSG over separate passes");
    expect(g_hid_response_count == 2,
           "idle poll should answer both the INIT and invalid-CLA U2F MSG");
    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "invalid-CLA U2F MSG should emit a HID response frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "invalid-CLA U2F MSG should reply on the assigned CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_MSG,
           "invalid-CLA U2F APDU should respond on CTAPHID_MSG");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x02,
           "invalid-CLA U2F APDU should return a two-byte status word");
    expect(g_last_hid_response[7] == 0x6E && g_last_hid_response[8] == 0x00,
           "invalid-CLA U2F APDU should return SW_CLA_NOT_SUPPORTED");
    expect(g_last_thread_wait_timeout == ZF_WORKER_POLL_MS,
           "worker should use a bounded poll timeout while idle");
}

static void test_transport_worker_idle_poll_processes_immediate_u2f_version_data(void) {
    ZerofidoApp app = {0};
    static const uint8_t nonce[8] = {0x36, 0xBB, 0x45, 0xBF, 0x98, 0xB6, 0x3C, 0xF0};
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;
    const uint32_t cid = 0xF0EE7690U;
    const uint8_t request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x22, 0x59, 0x38, 0xE9, 0x9C, 0xC9, 0x69, 0x5E,
        0x75, 0x61, 0x77, 0xE6, 0x71, 0x37, 0xB5, 0x88, 0xD2, 0xE5, 0x4A, 0x5E, 0xCA, 0xEF,
        0x4A, 0x29, 0x1E, 0x7B, 0xA1, 0x11, 0x5D, 0x0C, 0xA5, 0xE2, 0x70, 0xAD, 0x92,
    };

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    g_random_values[0] = cid;
    g_random_count = 1;

    memcpy(g_hid_request_packets[0], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[0][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[0][5] = 0x00;
    g_hid_request_packets[0][6] = 0x08;
    memcpy(&g_hid_request_packets[0][7], nonce, sizeof(nonce));
    g_hid_request_packet_lens[0] = 15;

    memcpy(g_hid_request_packets[1], &cid, sizeof(cid));
    g_hid_request_packets[1][4] = ZF_CTAPHID_MSG;
    g_hid_request_packets[1][5] = 0x00;
    g_hid_request_packets[1][6] = sizeof(request);
    memcpy(&g_hid_request_packets[1][7], request, sizeof(request));
    g_hid_request_packet_lens[1] = 7 + sizeof(request);
    g_hid_request_count = 2;

    g_thread_flag_results[0] = FuriFlagErrorTimeout;
    g_thread_flag_results[1] = FuriFlagErrorTimeout;
    g_thread_flag_results[2] = ZF_WORKER_EVT_STOP;
    g_thread_flag_result_count = 3;

    expect(zf_transport_usb_hid_worker(&app) == 0, "worker should exit cleanly in native harness");
    expect(g_hid_request_index == g_hid_request_count,
           "idle polls should drain the queued INIT and U2F VERSION-with-data MSG");
    expect(g_hid_response_count == 2,
           "idle poll should answer both the INIT and VERSION-with-data U2F MSG");
    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "VERSION-with-data U2F MSG should emit a HID response frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "VERSION-with-data U2F MSG should reply on the assigned CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_MSG,
           "VERSION-with-data U2F APDU should respond on CTAPHID_MSG");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x02,
           "VERSION-with-data U2F APDU should return a two-byte status word");
    expect(g_last_hid_response[7] == 0x67 && g_last_hid_response[8] == 0x00,
           "VERSION-with-data U2F APDU should return SW_WRONG_LENGTH");
}

static void test_transport_request_wakeup_invalid_seq_allows_followup_init(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint32_t cid = 0x01020304U;
    const uint32_t other_cid = 0x0A0B0C0DU;
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before queued fragmented PING");
    expect(zf_transport_remember_cid(&transport, other_cid),
           "seed second CID before queued fragmented PING");
    g_random_values[0] = 0x55667788U;
    g_random_count = 1;

    memcpy(g_hid_request_packets[0], &cid, sizeof(cid));
    g_hid_request_packets[0][4] = ZF_CTAPHID_PING;
    g_hid_request_packets[0][5] = 0x04;
    g_hid_request_packets[0][6] = 0x00;
    memset(&g_hid_request_packets[0][7], 0xAA, ZF_CTAPHID_PACKET_SIZE - 7);
    g_hid_request_packet_lens[0] = ZF_CTAPHID_PACKET_SIZE;

    memcpy(g_hid_request_packets[1], &cid, sizeof(cid));
    g_hid_request_packets[1][4] = 0x00;
    memset(&g_hid_request_packets[1][5], 0xBB, ZF_CTAPHID_PACKET_SIZE - 5);
    g_hid_request_packet_lens[1] = ZF_CTAPHID_PACKET_SIZE;

    memcpy(g_hid_request_packets[2], &other_cid, sizeof(other_cid));
    g_hid_request_packets[2][4] = 0x02;
    memset(&g_hid_request_packets[2][5], 0xCC, ZF_CTAPHID_PACKET_SIZE - 5);
    g_hid_request_packet_lens[2] = ZF_CTAPHID_PACKET_SIZE;

    memcpy(g_hid_request_packets[3], &broadcast_cid, sizeof(broadcast_cid));
    g_hid_request_packets[3][4] = ZF_CTAPHID_INIT;
    g_hid_request_packets[3][5] = 0x00;
    g_hid_request_packets[3][6] = 0x08;
    memcpy(&g_hid_request_packets[3][7], nonce, sizeof(nonce));
    g_hid_request_packet_lens[3] = 15;

    g_hid_request_count = 4;

    zf_transport_handle_request(&app, &transport, ZF_WORKER_EVT_REQUEST, packet);

    expect(g_hid_request_index < g_hid_request_count,
           "request wakeup should leave later queued packets for a later worker pass");

    while (g_hid_request_index < g_hid_request_count) {
        zf_transport_handle_request(&app, &transport, ZF_WORKER_EVT_REQUEST, packet);
    }

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "follow-up INIT should succeed after queued invalid sequence reset");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "follow-up INIT should echo its nonce after queued invalid sequence reset");
}

static void test_transport_same_cid_init_like_invalid_seq_allows_followup_init(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint32_t cid = 0x01020304U;
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before fragmented PING");
    g_random_values[0] = 0x55667788U;
    g_random_count = 1;

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x04;
    packet[6] = 0x00;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active, "fragmented PING should leave the assembly active");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x82;
    packet[5] = 0x00;
    packet[6] = 0x00;
    zf_transport_session_handle_packet(&app, &transport, packet, 7, NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "unexpected init-like packet should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "unexpected init-like packet on the active CID should return ERR_INVALID_SEQ");
    expect(!transport.active,
           "unexpected init-like packet on the active CID should reset the assembly");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &broadcast_cid, sizeof(broadcast_cid));
    packet[4] = ZF_CTAPHID_INIT;
    packet[5] = 0x00;
    packet[6] = 0x08;
    memcpy(&packet[7], nonce, sizeof(nonce));
    zf_transport_session_handle_packet(&app, &transport, packet, 15, NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "follow-up INIT should succeed after unexpected init-like invalid sequence");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "follow-up INIT should echo the nonce after unexpected init-like invalid sequence");
}

static void test_transport_out_of_order_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t init_packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    uint8_t cont_packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before fragmented PING");

    memcpy(init_packet, &cid, sizeof(cid));
    init_packet[4] = ZF_CTAPHID_PING;
    init_packet[5] = 0x00;
    init_packet[6] = 0x3C;
    memset(&init_packet[7], 0xAA, sizeof(init_packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, init_packet, sizeof(init_packet), NULL);

    expect(transport.active, "fragmented PING should leave transport waiting for continuations");
    expect(transport.next_seq == 0, "first continuation should expect sequence zero");

    memcpy(cont_packet, &cid, sizeof(cid));
    cont_packet[4] = 0x01;
    memset(&cont_packet[5], 0xBB, sizeof(cont_packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, cont_packet, sizeof(cont_packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "out-of-order continuation should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "out-of-order continuation should return ERR_INVALID_SEQ");
    expect(!transport.active, "out-of-order continuation should reset the in-flight assembly");
}

static void test_transport_large_ping_out_of_order_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before large fragmented PING");

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x04;
    packet[6] = 0x00;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active,
           "large fragmented PING should leave transport waiting for continuations");
    expect(transport.received_len == 57, "large fragmented PING should capture the init payload");
    expect(transport.next_seq == 0, "large fragmented PING should expect sequence zero first");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x00;
    memset(&packet[5], 0xBB, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active, "first large continuation should keep the assembly active");
    expect(transport.received_len == 116, "first large continuation should extend the payload");
    expect(transport.next_seq == 1, "second large continuation should expect sequence one");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x02;
    memset(&packet[5], 0xCC, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "large out-of-order continuation should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "large out-of-order continuation should return ERR_INVALID_SEQ");
    expect(!transport.active,
           "large out-of-order continuation should reset the in-flight assembly");
}

static void
test_transport_large_ping_other_cid_out_of_order_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;
    const uint32_t other_cid = 0x0A0B0C0DU;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before large fragmented PING");
    expect(zf_transport_remember_cid(&transport, other_cid),
           "seed second CID before large fragmented PING");

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x04;
    packet[6] = 0x00;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x00;
    memset(&packet[5], 0xBB, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active, "first large continuation should keep the assembly active");
    expect(transport.next_seq == 1, "second large continuation should expect sequence one");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &other_cid, sizeof(other_cid));
    packet[4] = 0x02;
    memset(&packet[5], 0xCC, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "other-CID out-of-order continuation should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "other-CID out-of-order continuation should prioritize ERR_INVALID_SEQ");
    expect(!transport.active,
           "other-CID out-of-order continuation should reset the active assembly");
}

static void test_transport_large_ping_other_cid_invalid_seq_allows_followup_init(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint32_t cid = 0x01020304U;
    const uint32_t other_cid = 0x0A0B0C0DU;
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID before fragmented PING");
    expect(zf_transport_remember_cid(&transport, other_cid),
           "seed second CID before fragmented PING");
    g_random_values[0] = 0x55667788U;
    g_random_count = 1;

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x04;
    packet[6] = 0x00;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x00;
    memset(&packet[5], 0xBB, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &other_cid, sizeof(other_cid));
    packet[4] = 0x02;
    memset(&packet[5], 0xCC, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(!transport.active, "invalid sequence should clear the active assembly");

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &broadcast_cid, sizeof(broadcast_cid));
    packet[4] = ZF_CTAPHID_INIT;
    packet[5] = 0x00;
    packet[6] = 0x08;
    memcpy(&packet[7], nonce, sizeof(nonce));
    zf_transport_session_handle_packet(&app, &transport, packet, 15, NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "broadcast INIT should succeed after invalid sequence reset");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "broadcast INIT should echo the request nonce after invalid sequence reset");
}

static void test_transport_processing_same_cid_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;

    test_reset();
    transport.processing = true;
    transport.cid = cid;
    transport.cmd = ZF_CTAPHID_PING;

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = 0x00;
    memset(&packet[5], 0xDD, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "same-CID continuation during processing should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "same-CID continuation during processing should return ERR_INVALID_SEQ");
    expect(transport.processing,
           "same-CID continuation during processing should not drop the active transaction");
}

static void test_transport_processing_other_cid_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;
    const uint32_t other_cid = 0x0A0B0C0DU;

    test_reset();
    transport.processing = true;
    transport.cid = cid;
    transport.cmd = ZF_CTAPHID_PING;

    memcpy(packet, &other_cid, sizeof(other_cid));
    packet[4] = 0x00;
    memset(&packet[5], 0xEE, sizeof(packet) - 5);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "other-CID continuation during processing should return CTAPHID_ERROR");
    expect(g_last_hid_response[7] == ZF_HID_ERR_INVALID_SEQ,
           "other-CID continuation during processing should prioritize ERR_INVALID_SEQ");
    expect(transport.processing,
           "other-CID continuation during processing should not drop the active transaction");
}

static void test_transport_lock_zero_returns_success(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[8] = {0};
    const uint32_t cid = 0x01020304U;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid), "seed CID for lock request");

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_LOCK;
    packet[5] = 0x00;
    packet[6] = 0x01;
    packet[7] = 0x00;

    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(g_last_hid_response_len == sizeof(g_last_hid_response),
           "lock response should emit one HID frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "lock response should target the request CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_LOCK,
           "lock request should reply with CTAPHID_LOCK");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x00,
           "lock response should have an empty payload");
}

static void test_transport_lock_blocks_other_cid_until_released(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t lock_packet[8] = {0};
    uint8_t init_packet[15] = {0};
    static const uint8_t nonce[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint32_t lock_cid = 0x01020304U;
    const uint32_t other_cid = 0x11121314U;
    uint32_t echoed_new_cid = 0;

    test_reset();
    expect(zf_transport_remember_cid(&transport, lock_cid), "seed lock owner CID");
    expect(zf_transport_remember_cid(&transport, other_cid), "seed second CID");

    memcpy(lock_packet, &lock_cid, sizeof(lock_cid));
    lock_packet[4] = ZF_CTAPHID_LOCK;
    lock_packet[5] = 0x00;
    lock_packet[6] = 0x01;
    lock_packet[7] = 0x08;
    zf_transport_session_handle_packet(&app, &transport, lock_packet, sizeof(lock_packet), NULL);
    expect(g_last_hid_response[4] == ZF_CTAPHID_LOCK, "lock acquisition should succeed");

    memcpy(init_packet, &other_cid, sizeof(other_cid));
    init_packet[4] = ZF_CTAPHID_INIT;
    init_packet[5] = 0x00;
    init_packet[6] = 0x08;
    memcpy(&init_packet[7], nonce, sizeof(nonce));
    zf_transport_session_handle_packet(&app, &transport, init_packet, sizeof(init_packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_ERROR,
           "INIT on another CID should fail while the device is locked");
    expect(g_last_hid_response[7] == ZF_HID_ERR_CHANNEL_BUSY,
           "locked transport should report channel busy to other CIDs");

    lock_packet[7] = 0x00;
    zf_transport_session_handle_packet(&app, &transport, lock_packet, sizeof(lock_packet), NULL);
    expect(g_last_hid_response[4] == ZF_CTAPHID_LOCK, "lock release should succeed");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x00,
           "lock release response should have an empty payload");

    zf_transport_session_handle_packet(&app, &transport, init_packet, sizeof(init_packet), NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "INIT on the other CID should succeed after releasing the lock");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 17,
           "INIT success should advertise the standard 17-byte payload");
    expect(memcmp(&g_last_hid_response[7], nonce, sizeof(nonce)) == 0,
           "INIT success should echo the request nonce");
    memcpy(&echoed_new_cid, &g_last_hid_response[15], sizeof(echoed_new_cid));
    expect(echoed_new_cid == other_cid,
           "INIT on an allocated CID should report that CID as the active channel");
    expect(g_last_hid_response[19] == 2, "INIT success should report CTAPHID interface version 2");
}

static void test_transport_disconnect_keeps_allocated_cids(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};

    test_reset();
    expect(zf_transport_remember_cid(&transport, 0x01020304U),
           "seed an allocated CID before disconnect");

    zf_transport_handle_worker_flags(&app, &transport, ZF_WORKER_EVT_DISCONNECT);

    expect(zf_transport_cid_is_allocated(&transport, 0x01020304U),
           "disconnect handling should not forget allocated CIDs");
}

static void test_transport_connect_keeps_allocated_cids(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};

    test_reset();
    expect(zf_transport_remember_cid(&transport, 0x01020304U),
           "seed an allocated CID before connect");

    zf_transport_handle_worker_flags(&app, &transport, ZF_WORKER_EVT_CONNECT);

    expect(zf_transport_cid_is_allocated(&transport, 0x01020304U),
           "connect handling should not forget allocated CIDs");
}

static void test_transport_worker_syncs_initial_hal_connection_state(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_hid_connected = true;
    g_thread_flag_results[0] = ZF_WORKER_EVT_STOP;
    g_thread_flag_result_count = 1;

    expect(zf_transport_usb_hid_worker(&app) == 0, "worker should exit cleanly in native harness");
    expect(g_transport_connected_true_count >= 1,
           "worker should publish an initial connected state when the HAL is already connected");
}

static void test_transport_dispatch_cbor_preserves_response_buffer(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    const uint8_t request[] = {ZfCtapeCmdGetInfo};

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZfTransportProtocolKindCtap2,
                                           request, sizeof(request));

    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "CBOR dispatch should emit a HID response frame");
    expect(g_last_hid_response[4] == ZF_CTAPHID_CBOR,
           "GetInfo should respond on the CBOR command channel");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x02,
           "GetInfo should return the stub CTAP payload length");
    expect(g_last_hid_response[7] == ZF_CTAP_SUCCESS,
           "GetInfo should return a CTAP success status byte");
}

static void test_transport_dispatch_u2f_version_with_data_returns_wrong_length(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    uint8_t request[5 + 64] = {0};

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    expect(zf_u2f_adapter_init(&app), "U2F init should succeed before transport MSG test");

    request[0] = 0x00;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 64;
    memset(&request[5], 0xA5, 64);

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZfTransportProtocolKindU2f,
                                           request, sizeof(request));

    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "invalid VERSION APDU should emit a HID response frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "invalid VERSION APDU should reply on the request CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_MSG,
           "invalid VERSION APDU should still respond on CTAPHID_MSG");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x02,
           "invalid VERSION APDU should return a two-byte status word");
    expect(g_last_hid_response[7] == 0x67 && g_last_hid_response[8] == 0x00,
           "invalid VERSION APDU should return SW_WRONG_LENGTH");

    zf_u2f_adapter_deinit(&app);
}

static void
test_transport_dispatch_u2f_version_extended_length_with_data_returns_wrong_length(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    uint8_t request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16,
        0xfa, 0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92,
        0xf1, 0xef, 0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08,
        0x44, 0x3b, 0x4a, 0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    expect(zf_u2f_adapter_init(&app),
           "transport extended-length invalid VERSION test should initialize U2F");

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZfTransportProtocolKindU2f,
                                           request, sizeof(request));

    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "extended-length invalid VERSION APDU should emit a HID response frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "extended-length invalid VERSION APDU should reply on the request CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_MSG,
           "extended-length invalid VERSION APDU should still respond on CTAPHID_MSG");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x02,
           "extended-length invalid VERSION APDU should return a two-byte status word");
    expect(g_last_hid_response[7] == 0x67 && g_last_hid_response[8] == 0x00,
           "extended-length invalid VERSION APDU should return SW_WRONG_LENGTH");

    zf_u2f_adapter_deinit(&app);
}

static void test_transport_dispatch_u2f_version_without_live_backend_returns_version(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    uint8_t request[5] = {0};

    test_reset();
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    request[0] = 0x00;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x00;

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZfTransportProtocolKindU2f,
                                           request, sizeof(request));

    expect(g_last_hid_response_len == ZF_CTAPHID_PACKET_SIZE,
           "VERSION APDU without live backend should emit a HID response frame");
    expect(memcmp(g_last_hid_response, &cid, sizeof(cid)) == 0,
           "VERSION APDU without live backend should reply on the request CID");
    expect(g_last_hid_response[4] == ZF_CTAPHID_MSG,
           "VERSION APDU without live backend should still respond on CTAPHID_MSG");
    expect(g_last_hid_response[5] == 0x00 && g_last_hid_response[6] == 0x08,
           "VERSION APDU without live backend should return an 8-byte payload");
    expect(memcmp(&g_last_hid_response[7], "U2F_V2", 6) == 0,
           "VERSION APDU without live backend should return U2F_V2");
    expect(g_last_hid_response[13] == 0x90 && g_last_hid_response[14] == 0x00,
           "VERSION APDU without live backend should return SW_NO_ERROR");
}

int main(void) {
    test_nfc_listener_profile_is_valid_iso14443_4a();
    test_nfc_select_applet_accepts_p2_no_fci();
    test_nfc_select_applet_returns_fido2_version_when_u2f_disabled();
    test_nfc_select_applet_accepts_le_and_legacy_nine_byte_aid();
    test_nfc_event_callback_accepts_bare_select_apdu();
    test_nfc_iso4_listener_event_decodes_block_and_sends_framed_response();
    test_nfc_iso4_listener_raw60_returns_unsupported_via_send_block();
    test_nfc_iso4_listener_native_desfire_payload_is_not_parsed_as_apdu();
    test_nfc_desfire_deselect_sleeps_before_next_activation();
    test_nfc_3a_rats_sends_ats_with_public_tx();
    test_nfc_3a_repeated_rats_resends_ats_instead_of_iso4_block();
    test_nfc_3a_reqa_data_resets_active_iso_dep_session();
    test_nfc_3a_iso_dep_select_decodes_and_responds();
    test_nfc_3a_r_nak_replays_last_iso_response();
    test_nfc_3a_r_ack_advances_chained_response_and_r_nak_replays();
    test_nfc_make_credential_sized_response_uses_single_i_block();
    test_nfc_terminal_r_ack_after_chained_response_keeps_fido_selected();
    test_nfc_post_success_cooldown_allows_new_fido_select();
    test_nfc_3a_empty_i_block_replays_cached_large_response_before_helper();
    test_nfc_3a_empty_i_block_replays_encoded_frame_when_cache_flag_missing();
    test_nfc_3a_late_pps_then_r_nak_replays_cached_large_response();
    test_nfc_3a_late_pps_frame_is_acknowledged();
    test_nfc_framed_select_response_uses_reader_block_number();
    test_nfc_cache_last_iso_response_handles_frame_buffer_alias();
    test_nfc_unadvertised_cid_frame_is_ignored();
    test_nfc_ndef_type4_select_is_rejected_for_fido_only_surface();
    test_nfc_applet_select_is_required_before_ctap2();
    test_nfc_preselect_apdu_80_60_reports_instruction_not_supported();
    test_nfc_preselect_wrapped_apdu_90_60_bootstraps_fido_applet();
    test_nfc_preselect_wrapped_apdu_90_af_reports_cla_not_supported();
    test_nfc_preselect_wrapped_desfire_get_version_does_not_sequence();
    test_nfc_selected_wrapped_desfire_get_version_is_terminal_unsupported();
    test_nfc_event_callback_bare_90_60_bootstraps_fido_applet();
    test_nfc_iso4_listener_bare_90_60_is_iso_dep_framed();
    test_nfc_ctap2_get_info_returns_immediately();
    test_nfc_ctap2_get_info_accepts_webkit_extended_apdu();
    test_nfc_iso4_listener_extended_get_info_is_iso_dep_framed();
    test_nfc_iso4_listener_ctap2_msg_signals_worker_after_unlock();
    test_nfc_iso4_listener_busy_ctap2_retry_has_minimal_side_effects();
    test_nfc_ctap2_msg_queues_worker_response();
    test_nfc_ctap2_msg_without_get_response_returns_direct_response();
    test_nfc_large_ctap2_msg_without_get_response_uses_iso_response_chaining();
    test_nfc_packed_attestation_sized_extended_response_finishes_iso_dep_chain();
    test_nfc_large_extended_ctap2_msg_without_get_response_uses_extended_response();
    test_nfc_chained_ctap2_request_acknowledges_next_block_number();
    test_nfc_duplicate_chained_i_block_does_not_corrupt_assembled_apdu();
    test_nfc_duplicate_chained_i_block_stall_resets_exchange();
    test_nfc_ctap2_msg_rejects_invalid_p1_p2();
    test_nfc_ctap2_get_info_rejects_invalid_p1_p2();
    test_nfc_locked_ctap2_get_info_does_not_reenter_ui_mutex();
    test_nfc_stale_worker_completion_preserves_new_request();
    test_nfc_ctap_control_end_clears_selected_applet();
    test_nfc_u2f_version_returns_immediately();
    test_nfc_u2f_version_fallback_selects_fido_surface();
    test_nfc_u2f_disabled_rejects_immediately_without_processing();
    test_nfc_u2f_check_only_authenticate_returns_immediately();
    test_nfc_u2f_register_returns_without_status_update();
    test_nfc_get_response_reports_remaining_bytes();
    test_nfc_ctap_get_response_ins_11_rejects_processing_without_advertised_support();
    test_nfc_ctap_get_response_ins_11_rejects_invalid_p1_p2();
    test_nfc_ctap_get_response_ins_11_reports_processing_with_advertised_support();
    test_nfc_busy_u2f_request_preserves_shared_arena();
    test_nfc_ctap_get_response_ins_11_returns_ready_response();
    test_nfc_field_off_marks_current_session_canceled();
    test_nfc_preselect_raw60_sends_iso_status();
    test_nfc_repeated_native_desfire_probe_keeps_discovery_compatible();
    test_nfc_native_desfire_preserves_existing_fido_replay();
    test_nfc_raw60_does_not_make_next_framed_select_bare();
    test_nfc_preselect_raw_native_probe_traces_halt();
    test_nfc_selected_raw_native_probe_traces_selected_state();
    test_short_u2f_version_request_is_accepted();
    test_header_only_u2f_version_request_is_accepted_for_stock_compatibility();
    test_u2f_version_accepts_exact_response_buffer();
    test_u2f_version_accepts_extended_length_encoding();
    test_u2f_version_extended_length_with_data_returns_wrong_length();
    test_u2f_register_allows_nonzero_p1_p2_for_stock_compatibility();
    test_u2f_dont_enforce_authenticate_mode_is_accepted_without_presence();
    test_u2f_enforce_authenticate_rejects_invalid_handle_before_presence();
    test_u2f_invalid_handle_clears_consumed_presence();
    test_u2f_enforce_authenticate_hash_includes_user_presence_flag();
    test_u2f_authenticate_reserves_counter_window();
    test_zf_u2f_adapter_init_allows_missing_attestation_assets();
    test_zf_u2f_adapter_init_creates_missing_device_key_and_counter();
    test_zf_u2f_adapter_init_allows_invalid_attestation_assets();
    test_u2f_adapter_auto_accept_bypasses_approval_prompt();
    test_u2f_adapter_invalid_cla_returns_cla_not_supported();
    test_u2f_adapter_invalid_cla_returns_cla_not_supported_without_live_backend();
    test_u2f_adapter_version_returns_u2f_v2_without_live_backend();
    test_u2f_adapter_version_with_data_returns_wrong_length_without_full_copy();
    test_u2f_adapter_version_extended_length_with_data_returns_wrong_length();
    test_transport_reclaims_lru_cid_when_table_is_full();
    test_transport_allocate_cid_reclaims_lru_when_table_is_full();
    test_transport_cancel_marks_processing_request_without_pending_approval();
    test_transport_active_other_cid_short_init_returns_busy();
    test_transport_processing_other_cid_short_init_returns_busy();
    test_transport_processing_broadcast_init_recovers_channel();
    test_usb_restore_keeps_previous_config_after_restore_failure();
    test_usb_worker_polls_while_idle_and_assembling();
    test_nfc_worker_waits_forever_while_idle();
    test_nfc_worker_releases_transport_arena_on_listener_alloc_failure();
    test_nfc_worker_releases_transport_arena_on_resource_alloc_failure();
    test_transport_worker_processes_disconnect_when_coalesced_with_interaction();
    test_wait_for_interaction_processes_disconnect_when_coalesced_with_completion();
    test_wait_for_interaction_sends_immediate_keepalive();
    test_wait_for_interaction_repeats_keepalive_on_timeout();
    test_wait_for_interaction_omits_keepalive_for_u2f_msg();
    test_transport_fragment_expires_on_session_tick();
    test_transport_request_wakeup_processes_one_complete_transaction();
    test_transport_request_without_wakeup_marks_connected_and_processes_packet();
    test_transport_worker_idle_poll_processes_immediate_u2f_invalid_cla();
    test_transport_worker_idle_poll_processes_immediate_u2f_version_data();
    test_transport_request_wakeup_invalid_seq_allows_followup_init();
    test_transport_same_cid_init_like_invalid_seq_allows_followup_init();
    test_transport_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_other_cid_out_of_order_continuation_returns_invalid_seq();
    test_transport_large_ping_other_cid_invalid_seq_allows_followup_init();
    test_transport_processing_same_cid_continuation_returns_invalid_seq();
    test_transport_processing_other_cid_continuation_returns_invalid_seq();
    test_transport_lock_zero_returns_success();
    test_transport_lock_blocks_other_cid_until_released();
    test_transport_disconnect_keeps_allocated_cids();
    test_transport_connect_keeps_allocated_cids();
    test_transport_worker_syncs_initial_hal_connection_state();
    test_transport_dispatch_cbor_preserves_response_buffer();
    test_transport_dispatch_u2f_version_with_data_returns_wrong_length();
    test_transport_dispatch_u2f_version_extended_length_with_data_returns_wrong_length();
    test_transport_dispatch_u2f_version_without_live_backend_returns_version();
    puts("native transport/u2f regressions passed");
    return 0;
}
