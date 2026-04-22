#pragma once

#include <stdbool.h>

typedef struct ZerofidoApp ZerofidoApp;

bool zerofido_notify_init(ZerofidoApp *app);
void zerofido_notify_deinit(ZerofidoApp *app);
void zerofido_notify_prompt(ZerofidoApp *app);
void zerofido_notify_wink(ZerofidoApp *app);
void zerofido_notify_success(ZerofidoApp *app);
void zerofido_notify_error(ZerofidoApp *app);
void zerofido_notify_reset(ZerofidoApp *app);
