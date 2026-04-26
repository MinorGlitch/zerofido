#include "adapter.h"

#include "nfc_worker.h"
#ifndef ZF_NFC_ONLY
#include "usb_hid_session.h"
#include "usb_hid_worker.h"
#endif
#include "../zerofido_app_i.h"

static const ZfTransportAdapterOps *zf_transport_get_adapter(const ZerofidoApp *app) {
    if (!app) {
        return NULL;
    }

    return app->transport_adapter;
}

#ifndef ZF_NFC_ONLY
const ZfTransportAdapterOps zf_transport_usb_hid_adapter = {
    .worker = zf_transport_usb_hid_worker,
    .worker_stack_size = 6 * 1024,
    .stop = zf_transport_usb_hid_stop,
    .send_dispatch_result = zf_transport_usb_hid_send_dispatch_result,
    .wait_for_interaction = zf_transport_usb_hid_wait_for_interaction,
    .notify_interaction_changed = zf_transport_usb_hid_notify_interaction_changed,
    .poll_cbor_control = zf_transport_usb_hid_poll_cbor_control,
};
#endif

const ZfTransportAdapterOps zf_transport_nfc_adapter = {
    .worker = zf_transport_nfc_worker,
    .worker_stack_size = 5 * 1024,
    .stop = zf_transport_nfc_stop,
    .send_dispatch_result = zf_transport_nfc_send_dispatch_result,
    .wait_for_interaction = zf_transport_nfc_wait_for_interaction,
    .notify_interaction_changed = zf_transport_nfc_notify_interaction_changed,
    .poll_cbor_control = zf_transport_nfc_poll_cbor_control,
};

void zf_transport_stop(ZerofidoApp *app) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->stop(app);
    }
}

void zf_transport_send_dispatch_result(ZerofidoApp *app, const ZfProtocolDispatchRequest *request,
                                       const ZfProtocolDispatchResult *result) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->send_dispatch_result(app, request, result);
    }
}

bool zf_transport_wait_for_interaction(ZerofidoApp *app, ZfTransportSessionId current_session_id,
                                       bool *approved) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (!adapter) {
        return false;
    }

    return adapter->wait_for_interaction(app, current_session_id, approved);
}

void zf_transport_notify_interaction_changed(ZerofidoApp *app) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->notify_interaction_changed(app);
    }
}

uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, ZfTransportSessionId current_session_id) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (!adapter) {
        return ZF_CTAP_SUCCESS;
    }

    return adapter->poll_cbor_control(app, current_session_id);
}
