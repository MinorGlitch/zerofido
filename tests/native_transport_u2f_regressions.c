#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "furi.h"
#include "furi_hal.h"
#include "furi_hal_random.h"
#include "furi_hal_usb_hid_u2f.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "storage/storage.h"
#include "zerofido_ui_format.h"

#define FURI_PACKED __attribute__((packed))
#define FURI_LOG_E(tag, fmt, ...) ((void)0)
#define FURI_LOG_W(tag, fmt, ...) ((void)0)
#define FURI_LOG_D(tag, fmt, ...) ((void)0)
#define furi_assert(expr) ((void)(expr))

typedef int FuriStatus;
typedef struct ZerofidoApp ZerofidoApp;

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

struct FuriHalUsbInterface {
    int unused;
};

struct FuriThread {
    int unused;
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
    int unused;
};

#define FuriStatusOk 0
#define FuriFlagError 0x80000000U
#define FuriFlagErrorTimeout 0x40000000U
#define FuriFlagWaitAny 0U
#define FuriWaitForever 0U

static uint32_t g_fake_tick = 0;
static uint32_t g_random_values[16];
static size_t g_random_count = 0;
static size_t g_random_index = 0;
static uint32_t g_thread_flag_results[8];
static size_t g_thread_flag_result_count = 0;
static size_t g_thread_flag_result_index = 0;
static uint32_t g_last_thread_wait_timeout = 0;
static size_t g_thread_flag_wait_call_count = 0;
static FuriStatus g_semaphore_results[8];
static size_t g_semaphore_result_count = 0;
static size_t g_semaphore_result_index = 0;
static size_t g_cancel_pending_interaction_count = 0;
static bool g_cancel_pending_interaction_result = false;
static size_t g_approval_request_count = 0;
static bool g_auto_accept_requests = false;
static size_t g_transport_connected_set_count = 0;
static bool g_last_transport_connected = false;
static uint8_t g_last_hid_response[64];
static size_t g_last_hid_response_len = 0;
static size_t g_hid_response_count = 0;
static bool g_u2f_cert_assets_present = true;
static bool g_u2f_cert_check_result = true;
static bool g_u2f_cert_key_load_result = true;
static bool g_u2f_cert_key_matches_result = true;
static size_t g_u2f_bootstrap_call_count = 0;
static bool g_u2f_bootstrap_result = true;
static bool g_u2f_key_load_result = true;
static bool g_u2f_cnt_read_result = true;
static uint8_t g_hid_request_packets[8][64];
static size_t g_hid_request_packet_lens[8];
static size_t g_hid_request_count = 0;
static size_t g_hid_request_index = 0;
static bool g_hid_connected = false;
static uint8_t g_sha256_trace[1024];
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

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_reset(void) {
    g_fake_tick = 0;
    memset(g_random_values, 0, sizeof(g_random_values));
    g_random_count = 0;
    g_random_index = 0;
    memset(g_thread_flag_results, 0, sizeof(g_thread_flag_results));
    g_thread_flag_result_count = 0;
    g_thread_flag_result_index = 0;
    g_last_thread_wait_timeout = 0;
    g_thread_flag_wait_call_count = 0;
    memset(g_semaphore_results, 0, sizeof(g_semaphore_results));
    g_semaphore_result_count = 0;
    g_semaphore_result_index = 0;
    g_cancel_pending_interaction_count = 0;
    g_cancel_pending_interaction_result = false;
    g_approval_request_count = 0;
    g_auto_accept_requests = false;
    g_transport_connected_set_count = 0;
    g_last_transport_connected = false;
    memset(g_last_hid_response, 0, sizeof(g_last_hid_response));
    g_last_hid_response_len = 0;
    g_hid_response_count = 0;
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    g_u2f_bootstrap_call_count = 0;
    g_u2f_bootstrap_result = true;
    g_u2f_key_load_result = true;
    g_u2f_cnt_read_result = true;
    memset(g_hid_request_packets, 0, sizeof(g_hid_request_packets));
    memset(g_hid_request_packet_lens, 0, sizeof(g_hid_request_packet_lens));
    g_hid_request_count = 0;
    g_hid_request_index = 0;
    g_hid_connected = false;
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
    UNUSED(flags);
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

FuriStatus furi_semaphore_acquire(FuriSemaphore *sem, uint32_t timeout) {
    UNUSED(sem);
    UNUSED(timeout);
    if (g_semaphore_result_index < g_semaphore_result_count) {
        return g_semaphore_results[g_semaphore_result_index++];
    }
    return 1;
}

FuriStatus furi_mutex_acquire(FuriMutex *mutex, uint32_t timeout) {
    UNUSED(mutex);
    UNUSED(timeout);
    return FuriStatusOk;
}

void furi_mutex_release(FuriMutex *mutex) {
    UNUSED(mutex);
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

    slot = test_storage_file_slot(path, access_mode == FSAM_WRITE && open_mode == FSOM_CREATE_ALWAYS);
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
    return (FuriHalUsbInterface *)&usb_hid_u2f;
}

bool furi_hal_usb_set_config(const FuriHalUsbInterface *interface, void *context) {
    UNUSED(interface);
    UNUSED(context);
    return true;
}

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, uint32_t event) {
    UNUSED(app);
    UNUSED(event);
}

bool zerofido_ui_cancel_pending_interaction(ZerofidoApp *app) {
    UNUSED(app);
    g_cancel_pending_interaction_count++;
    return g_cancel_pending_interaction_result;
}

void zerofido_ui_set_status(ZerofidoApp *app, const char *status) {
    UNUSED(app);
    UNUSED(status);
}

void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected) {
    UNUSED(app);
    g_transport_connected_set_count++;
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

void zerofido_notify_wink(ZerofidoApp *app) {
    UNUSED(app);
}

bool zerofido_ui_request_approval(ZerofidoApp *app, ZfUiProtocol protocol, const char *operation,
                                  const char *rp_id, const char *user_text, uint32_t cid,
                                  bool *approved) {
    UNUSED(app);
    UNUSED(protocol);
    UNUSED(operation);
    UNUSED(rp_id);
    UNUSED(user_text);
    UNUSED(cid);
    if (g_auto_accept_requests) {
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

size_t zerofido_handle_ctap2(ZerofidoApp *app, uint32_t cid, const uint8_t *request,
                             size_t request_len, uint8_t *response, size_t response_capacity) {
    UNUSED(app);
    UNUSED(cid);
    if (!request || request_len == 0 || !response || response_capacity < 2) {
        return 0;
    }

    if (request[0] == ZfCtapeCmdGetInfo) {
        response[0] = ZF_CTAP_SUCCESS;
        response[1] = 0xA0;
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

bool u2f_data_bootstrap_attestation_assets(const uint8_t *cert, size_t cert_len,
                                           const uint8_t *cert_key, size_t cert_key_len) {
    UNUSED(cert);
    UNUSED(cert_key);
    g_u2f_bootstrap_call_count++;
    if (!g_u2f_bootstrap_result || cert_len == 0 || cert_key_len != 32) {
        return false;
    }
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = true;
    g_u2f_cert_key_load_result = true;
    g_u2f_cert_key_matches_result = true;
    return true;
}

bool u2f_data_key_exists(void) {
    return true;
}

bool u2f_data_key_load(uint8_t *device_key) {
    memset(device_key, 0, 32);
    return g_u2f_key_load_result;
}

bool u2f_data_key_generate(uint8_t *device_key) {
    memset(device_key, 0, 32);
    return true;
}

bool u2f_data_cnt_exists(void) {
    return true;
}

bool u2f_data_cnt_read(uint32_t *cnt) {
    *cnt = 0;
    return g_u2f_cnt_read_result;
}

bool u2f_data_cnt_write(uint32_t cnt) {
    UNUSED(cnt);
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
#include "../src/zerofido_runtime_config.c"
#include "../src/u2f/adapter.c"
#include "../src/transport/dispatch.c"
#include "../src/transport/usb_hid_session.c"
#include "../src/transport/usb_hid_worker.c"

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
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16, 0xfa,
        0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92, 0xf1, 0xef,
        0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08, 0x44, 0x3b, 0x4a,
        0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };
    uint8_t request[sizeof(raw_request)] = {0};
    uint8_t response[2] = {0};

    memcpy(request, raw_request, sizeof(request));
    expect(u2f_validate_request(request, sizeof(request)) == 2,
           "extended-length U2F VERSION APDU with data must be rejected");
    expect(request[0] == 0x67 && request[1] == 0x00,
           "extended-length U2F VERSION APDU with data must return SW_WRONG_LENGTH");
    memcpy(request, raw_request, sizeof(request));
    expect(u2f_validate_request_into_response(request, sizeof(request), response, sizeof(response)) == 2,
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
    expect(g_sha256_trace_len == U2F_APP_ID_SIZE + 1 + sizeof(uint32_t) + U2F_CHALLENGE_SIZE,
           "authenticate signature preimage should cover appId, flags, counter, and challenge");
    expect(g_sha256_trace[U2F_APP_ID_SIZE] == 0x01,
           "authenticate signature preimage should include the UP flag when presence was consumed");
    expect(request[0] == 0x01, "authenticate response should also expose the UP flag");
}

static void test_zf_u2f_adapter_init_bootstraps_missing_attestation_assets(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_u2f_cert_assets_present = false;

    expect(zf_u2f_adapter_init(&app), "U2F init should bootstrap missing attestation assets");
    expect(g_u2f_bootstrap_call_count == 1,
           "U2F init should attempt a single attestation asset bootstrap");
    expect(app.u2f != NULL && app.u2f->ready,
           "bootstrapped U2F instance should be ready for requests");

    zf_u2f_adapter_deinit(&app);
}

static void test_zf_u2f_adapter_init_bootstraps_invalid_attestation_assets(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_u2f_cert_assets_present = true;
    g_u2f_cert_check_result = false;

    expect(zf_u2f_adapter_init(&app),
           "U2F init should recover when attestation assets exist but fail validation");
    expect(g_u2f_bootstrap_call_count == 1,
           "U2F init should rebootstrap invalid attestation assets once");
    expect(app.u2f != NULL && app.u2f->ready,
           "rebootstrapped U2F instance should be ready for requests");

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

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

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

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

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

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

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

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

    expect(response_len == 8,
           "VERSION U2F APDU should still return U2F_V2 without a live backend");
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

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

    expect(response_len == 2,
           "VERSION APDU with unexpected data should return a status word without a full request copy");
    expect(response[0] == 0x67 && response[1] == 0x00,
           "VERSION APDU with unexpected data should return SW_WRONG_LENGTH");
}

static void test_u2f_adapter_version_extended_length_with_data_returns_wrong_length(void) {
    ZerofidoApp app = {0};
    uint8_t request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16, 0xfa,
        0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92, 0xf1, 0xef,
        0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08, 0x44, 0x3b, 0x4a,
        0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };
    uint8_t response[2] = {0};
    size_t response_len = 0;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    response_len =
        zf_u2f_adapter_handle_msg(&app, 0x01020304U, request, sizeof(request), response, sizeof(response));

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

static void test_transport_worker_processes_disconnect_when_coalesced_with_interaction(void) {
    ZerofidoApp app = {0};

    test_reset();
    g_cancel_pending_interaction_result = true;
    app.transport_adapter = &zf_transport_usb_hid_adapter;
    g_thread_flag_results[0] = ZF_WORKER_EVT_APPROVAL | ZF_WORKER_EVT_DISCONNECT;
    g_thread_flag_results[1] = ZF_WORKER_EVT_STOP;
    g_thread_flag_result_count = 2;

    expect(zf_transport_usb_hid_worker(&app) == 0, "worker should exit cleanly in native harness");
    expect(g_cancel_pending_interaction_count == 1,
           "disconnect work should not be dropped when interaction shares the wakeup");
    expect(g_transport_connected_set_count == 1,
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

static void test_transport_request_wakeup_drains_all_queued_packets(void) {
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

    expect(g_hid_request_index == g_hid_request_count,
           "request wakeup should drain every queued HID packet");
    expect(g_hid_response_count == 2,
           "each drained INIT request should produce its own HID response");
    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "the last drained packet should still complete normally");
    expect(memcmp(&g_last_hid_response[7], nonce_b, sizeof(nonce_b)) == 0,
           "the final INIT response should echo the final queued request nonce");
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

static void test_transport_init_caps_drop_cbor_when_fido2_disabled(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    static const uint8_t nonce[8] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
    const uint32_t broadcast_cid = ZF_BROADCAST_CID;

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    app.runtime_config.fido2_enabled = false;
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    memcpy(packet, &broadcast_cid, sizeof(broadcast_cid));
    packet[4] = ZF_CTAPHID_INIT;
    packet[5] = 0x00;
    packet[6] = 0x08;
    memcpy(&packet[7], nonce, sizeof(nonce));

    zf_transport_session_handle_packet(&app, &transport, packet, 15, NULL);

    expect(g_last_hid_response[4] == ZF_CTAPHID_INIT,
           "INIT should still succeed when FIDO2 is disabled");
    expect(g_last_hid_response[23] == ZF_CAPABILITY_WINK,
           "INIT capabilities should stop advertising CBOR when FIDO2 is disabled");
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
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before queued fragmented PING");
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

    expect(g_hid_request_index == g_hid_request_count,
           "request wakeup should drain the invalid-seq queue");
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
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before fragmented PING");
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
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before fragmented PING");

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
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before large fragmented PING");

    memcpy(packet, &cid, sizeof(cid));
    packet[4] = ZF_CTAPHID_PING;
    packet[5] = 0x04;
    packet[6] = 0x00;
    memset(&packet[7], 0xAA, sizeof(packet) - 7);
    zf_transport_session_handle_packet(&app, &transport, packet, sizeof(packet), NULL);

    expect(transport.active, "large fragmented PING should leave transport waiting for continuations");
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

static void test_transport_large_ping_other_cid_out_of_order_continuation_returns_invalid_seq(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    uint8_t packet[ZF_CTAPHID_PACKET_SIZE] = {0};
    const uint32_t cid = 0x01020304U;
    const uint32_t other_cid = 0x0A0B0C0DU;

    test_reset();
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before large fragmented PING");
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
    expect(zf_transport_remember_cid(&transport, cid),
           "seed CID before fragmented PING");
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
    expect(g_transport_connected_set_count == 1,
           "worker should publish an initial connected state when the HAL is already connected");
    expect(g_last_transport_connected,
           "initial HAL connection sync should mark transport connected");
}

static void test_transport_dispatch_cbor_preserves_response_buffer(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    const uint8_t request[] = {ZfCtapeCmdGetInfo};

    test_reset();
    app.capabilities_resolved = true;
    app.capabilities.usb_hid_enabled = true;
    app.capabilities.fido2_enabled = true;

    zf_transport_dispatch_complete_message(
        &app, &transport, cid, ZF_CTAPHID_CBOR, request, sizeof(request));

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

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZF_CTAPHID_MSG, request,
                                           sizeof(request));

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

static void test_transport_dispatch_u2f_version_extended_length_with_data_returns_wrong_length(void) {
    ZerofidoApp app = {0};
    ZfTransportState transport = {0};
    const uint32_t cid = 0x01020304U;
    uint8_t request[] = {
        0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2c, 0x7c, 0xd7, 0xb3, 0x5e, 0x16, 0xfa,
        0x3c, 0xc2, 0x57, 0xb0, 0x5e, 0xaf, 0xa7, 0xc7, 0xcc, 0x77, 0x92, 0xf1, 0xef,
        0x37, 0xe3, 0x1b, 0x1e, 0x4c, 0x77, 0x38, 0xac, 0x41, 0x08, 0x44, 0x3b, 0x4a,
        0x46, 0x72, 0x2d, 0xee, 0x2b, 0xea, 0x32, 0x00, 0x00,
    };

    test_reset();
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;
    expect(zf_u2f_adapter_init(&app),
           "transport extended-length invalid VERSION test should initialize U2F");

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZF_CTAPHID_MSG, request,
                                           sizeof(request));

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
    zf_runtime_config_load_defaults(&app.runtime_config);
    zf_runtime_config_resolve_capabilities(&app.runtime_config, &app.capabilities);
    app.capabilities_resolved = true;

    request[0] = 0x00;
    request[1] = U2F_CMD_VERSION;
    request[2] = 0x00;
    request[3] = 0x00;
    request[4] = 0x00;

    zf_transport_dispatch_complete_message(&app, &transport, cid, ZF_CTAPHID_MSG, request,
                                           sizeof(request));

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
    test_zf_u2f_adapter_init_bootstraps_missing_attestation_assets();
    test_zf_u2f_adapter_init_bootstraps_invalid_attestation_assets();
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
    test_transport_worker_processes_disconnect_when_coalesced_with_interaction();
    test_wait_for_interaction_processes_disconnect_when_coalesced_with_completion();
    test_wait_for_interaction_sends_immediate_keepalive();
    test_wait_for_interaction_repeats_keepalive_on_timeout();
    test_transport_fragment_expires_on_session_tick();
    test_transport_request_wakeup_drains_all_queued_packets();
    test_transport_request_without_wakeup_marks_connected_and_processes_packet();
    test_transport_init_caps_drop_cbor_when_fido2_disabled();
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
