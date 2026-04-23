#include "adapter.h"

#include "usb_hid_worker.h"
#include "../zerofido_app_i.h"

static const ZfTransportAdapterOps *zf_transport_get_adapter(const ZerofidoApp *app) {
    if (!app) {
        return NULL;
    }

    return app->transport_adapter;
}

const ZfTransportAdapterOps zf_transport_usb_hid_adapter = {
    .worker = zf_transport_usb_hid_worker,
    .stop = zf_transport_usb_hid_stop,
    .send_keepalive = zf_transport_usb_hid_send_keepalive,
    .wait_for_interaction = zf_transport_usb_hid_wait_for_interaction,
    .notify_interaction_changed = zf_transport_usb_hid_notify_interaction_changed,
    .poll_cbor_control = zf_transport_usb_hid_poll_cbor_control,
};

void zf_transport_stop(ZerofidoApp *app) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->stop(app);
    }
}

void zf_transport_send_keepalive(const ZerofidoApp *app, uint32_t cid, uint8_t status) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->send_keepalive(cid, status);
    }
}

bool zf_transport_wait_for_interaction(ZerofidoApp *app, uint32_t current_cid, bool *approved) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (!adapter) {
        return false;
    }

    return adapter->wait_for_interaction(app, current_cid, approved);
}

void zf_transport_notify_interaction_changed(ZerofidoApp *app) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (adapter) {
        adapter->notify_interaction_changed(app);
    }
}

uint8_t zf_transport_poll_cbor_control(ZerofidoApp *app, uint32_t current_cid) {
    const ZfTransportAdapterOps *adapter = zf_transport_get_adapter(app);

    if (!adapter) {
        return ZF_CTAP_SUCCESS;
    }

    return adapter->poll_cbor_control(app, current_cid);
}
