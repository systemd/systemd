/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "qmp-client.h"
#include "set.h"
#include "varlink-io.systemd.MachineInstance.h"
#include "varlink-io.systemd.QemuMachineInstance.h"
#include "varlink-io.systemd.VirtualMachineInstance.h"
#include "varlink-util.h"
#include "vmspawn-varlink.h"

struct VmspawnVarlinkBridge {
        QmpClient *qmp;
};

VmspawnVarlinkBridge *vmspawn_varlink_bridge_free(VmspawnVarlinkBridge *b) {
        if (!b)
                return NULL;

        qmp_client_free(b->qmp);
        return mfree(b);
}

struct VmspawnVarlinkContext {
        /* The dynamic interface must be declared (and thus freed) after the varlink server, because
         * sd_varlink_server_add_interface() stores a bare pointer. Struct fields are freed in the order
         * specified in vmspawn_varlink_context_free(), where we explicitly free the server first. */
        sd_varlink_interface *qemu_interface;
        sd_varlink_server *varlink_server;
        VmspawnVarlinkBridge *bridge;
        Set *subscribed;
        Hashmap *qmp_command_names;
};

static int vl_method_terminate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_pause(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_query_status(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_subscribe_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error(link, "io.systemd.MachineInstance.NotSupported", NULL);
}

static int vl_method_acquire_qmp(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_error_errno(link, -EOPNOTSUPP);
}

int vmspawn_varlink_setup(VmspawnVarlinkContext **ret, int _qmp_fd, sd_event *event, const char *runtime_dir, char **ret_varlink_address) {
        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *ctx = NULL;
        _cleanup_close_ int fd = TAKE_FD(_qmp_fd);
        _cleanup_free_ char *listen_address = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);
        assert_return(runtime_dir, -EINVAL);

        ctx = new(VmspawnVarlinkContext, 1);
        if (!ctx)
                return log_oom();

        *ctx = (VmspawnVarlinkContext) {};

        /* Phase 1: blocking QMP handshake */
        r = qmp_client_connect_fd(&ctx->bridge->qmp, TAKE_FD(fd), event);
        if (r < 0)
                return log_error_errno(r, "Failed to perform QMP handshake: %m");

        /* Create varlink server for VM control */
        r = varlink_server_new(&ctx->varlink_server,
                               SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                               ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to create varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        ctx->varlink_server,
                        &vl_interface_io_systemd_MachineInstance,
                        &vl_interface_io_systemd_VirtualMachineInstance,
                        &vl_interface_io_systemd_QemuMachineInstance);
        if (r < 0)
                return log_error_errno(r, "Failed to add varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        ctx->varlink_server,
                        "io.systemd.MachineInstance.Terminate",         vl_method_terminate,
                        "io.systemd.MachineInstance.PowerOff",          vl_method_power_off,
                        "io.systemd.MachineInstance.Reboot",            vl_method_reboot,
                        "io.systemd.MachineInstance.Pause",             vl_method_pause,
                        "io.systemd.MachineInstance.Resume",            vl_method_resume,
                        "io.systemd.MachineInstance.QueryStatus",       vl_method_query_status,
                        "io.systemd.MachineInstance.SubscribeEvents",   vl_method_subscribe_events,
                        "io.systemd.QemuMachineInstance.AcquireQMP",    vl_method_acquire_qmp);
        if (r < 0)
                return log_error_errno(r, "Failed to bind varlink methods: %m");

        listen_address = path_join(runtime_dir, "io.systemd.MachineInstance");
        if (!listen_address)
                return log_oom();

        r = sd_varlink_server_listen_address(ctx->varlink_server, listen_address, 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on %s: %m", listen_address);

        r = sd_varlink_server_attach_event(ctx->varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink server to event loop: %m");

        log_debug("QMP varlink server listening on %s", listen_address);

        if (ret_varlink_address)
                *ret_varlink_address = TAKE_PTR(listen_address);

        *ret = TAKE_PTR(ctx);
        return 0;
}

VmspawnVarlinkContext *vmspawn_varlink_context_free(VmspawnVarlinkContext *ctx) {
        if (!ctx)
                return NULL;

        /* Free the varlink server before the dynamic interface, since the server stores bare pointers to
         * interfaces added via sd_varlink_server_add_interface(). */
        ctx->varlink_server = sd_varlink_server_unref(ctx->varlink_server);
        ctx->qemu_interface = sd_varlink_interface_free(ctx->qemu_interface);
        ctx->bridge = vmspawn_varlink_bridge_free(ctx->bridge);
        set_free(ctx->subscribed);
        hashmap_free(ctx->qmp_command_names);

        return mfree(ctx);
}
