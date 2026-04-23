#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "zerofido_app_i.h"
#include "zerofido_store.h"

bool zerofido_ui_init(ZerofidoApp *app);
void zerofido_ui_deinit(ZerofidoApp *app);
void zerofido_ui_refresh_status(ZerofidoApp *app);
void zerofido_ui_set_status(ZerofidoApp *app, const char *text);
void zerofido_ui_set_transport_connected(ZerofidoApp *app, bool connected);
bool zerofido_ui_request_approval(ZerofidoApp *app, ZfUiProtocol protocol, const char *operation,
                                  const char *target_id, const char *user_text,
                                  uint32_t current_cid, bool *approved);
bool zerofido_ui_request_assertion_selection(ZerofidoApp *app, const char *rp_id,
                                             const uint16_t *match_indices, size_t match_count,
                                             uint32_t current_cid, uint32_t *selected_record_index);
bool zerofido_ui_deny_pending_interaction(ZerofidoApp *app);
bool zerofido_ui_cancel_pending_interaction(ZerofidoApp *app);
bool zerofido_ui_expire_pending_interaction(ZerofidoApp *app);
ZfApprovalState zerofido_ui_get_interaction_state(ZerofidoApp *app);
