#pragma once

#include <stdbool.h>

#include "../zerofido_app_i.h"

void zerofido_ui_status_bind_view(ZerofidoApp *app);
void zerofido_ui_apply_transport_connected(ZerofidoApp *app, bool connected);
