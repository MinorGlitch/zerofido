#include "zerofido_app.h"

#include "app/lifecycle.h"
#include "zerofido_ui.h"
#include "zerofido_ui_i.h"

int32_t zerofido_main(void *p) {
    UNUSED(p);

    ZerofidoApp *app = zf_app_lifecycle_alloc();
    if (!app) {
        return -1;
    }

    if (!zf_app_lifecycle_open(app)) {
        zf_app_lifecycle_free(app);
        return -1;
    }

    zerofido_ui_switch_to_view(app, ZfViewStatus);
    zf_app_lifecycle_startup_async(app);
    view_dispatcher_run(app->view_dispatcher);
    zf_app_lifecycle_shutdown(app);
    zf_app_lifecycle_free(app);
    return 0;
}
