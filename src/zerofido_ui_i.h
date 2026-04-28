/*
 * ZeroFIDO
 * Copyright (C) 2026 Alex Stoyanov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>

typedef struct ZerofidoApp ZerofidoApp;

void zerofido_ui_dispatch_custom_event(ZerofidoApp *app, ZfCustomEvent event);
void zerofido_ui_switch_to_view(ZerofidoApp *app, ZfViewId view_id);
void zerofido_ui_show_interaction(ZerofidoApp *app);
void zerofido_ui_hide_interaction(ZerofidoApp *app);
