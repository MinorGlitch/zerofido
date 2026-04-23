#pragma once

#include "../zerofido_app_i.h"

ZerofidoApp *zf_app_lifecycle_alloc(void);
bool zf_app_lifecycle_open(ZerofidoApp *app);
bool zf_app_lifecycle_startup(ZerofidoApp *app);
void zf_app_lifecycle_shutdown(ZerofidoApp *app);
void zf_app_lifecycle_free(ZerofidoApp *app);
