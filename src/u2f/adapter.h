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
#include <stddef.h>
#include <stdint.h>

#include "../zerofido_types.h"

typedef struct ZerofidoApp ZerofidoApp;

bool zf_u2f_adapter_init(ZerofidoApp *app);
bool zf_u2f_adapter_ensure_init(ZerofidoApp *app);
void zf_u2f_adapter_deinit(ZerofidoApp *app);
bool zf_u2f_adapter_is_available(const ZerofidoApp *app);
void zf_u2f_adapter_set_connected(ZerofidoApp *app, bool connected);
size_t zf_u2f_adapter_handle_msg(ZerofidoApp *app, ZfTransportSessionId session_id,
                                 const uint8_t *request, size_t request_len, uint8_t *response,
                                 size_t response_capacity);
void zf_u2f_adapter_wink(ZerofidoApp *app);
