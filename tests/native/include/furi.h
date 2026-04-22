#pragma once

#include <stdbool.h>
#include <stdint.h>

#define UNUSED(x) ((void)(x))

typedef struct FuriSemaphore FuriSemaphore;
typedef struct FuriTimer FuriTimer;
typedef struct FuriThread FuriThread;
typedef struct FuriMutex FuriMutex;
typedef void *FuriThreadId;

typedef enum {
    FuriTimerTypeOnce = 0,
    FuriTimerTypePeriodic = 1,
} FuriTimerType;

typedef void (*FuriTimerCallback)(void *context);

FuriThreadId furi_thread_get_current_id(void);
uint32_t furi_thread_get_stack_space(FuriThreadId thread_id);
void *furi_record_open(const char *name);
void furi_record_close(const char *name);
FuriTimer *furi_timer_alloc(FuriTimerCallback callback, FuriTimerType type, void *context);
void furi_timer_free(FuriTimer *timer);
void furi_timer_start(FuriTimer *timer, uint32_t timeout);
void furi_timer_stop(FuriTimer *timer);
