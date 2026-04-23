#pragma once

#include <stdbool.h>

typedef struct ZerofidoApp ZerofidoApp;

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, ZfCustomEvent event);
void zerofido_ui_show_interaction(ZerofidoApp *app);
void zerofido_ui_hide_interaction(ZerofidoApp *app);
