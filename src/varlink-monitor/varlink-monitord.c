/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <signal.h>
#include "sd-event.h"

#include "alloc-util.h"
#include "bpf-util.h"
#include "bus-polkit.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "monitor-varlink-api.bpf.h"
#include "monitor-varlink-skel.h"
#include "socket-util.h"
#include "user-util.h"
#include "varlink-io.systemd.VarlinkMonitor.h"
#include "varlink-util.h"

static struct monitor_varlink_bpf *monitor_varlink_bpf_free(struct monitor_varlink_bpf *obj) {
        if (obj)
                monitor_varlink_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct monitor_varlink_bpf *, monitor_varlink_bpf_free);

typedef struct BpfMonitor {
        struct monitor_varlink_bpf *obj;
        bool attached;
} BpfMonitor;

static void bpf_monitor_detach(BpfMonitor *m);

static BpfMonitor *bpf_monitor_free(BpfMonitor *m) {
        if (!m)
                return NULL;

        bpf_monitor_detach(m);

        m->obj = monitor_varlink_bpf_free(m->obj);

        free(m);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BpfMonitor *, bpf_monitor_free);

static int bpf_monitor_new(BpfMonitor **ret) {
        _cleanup_(monitor_varlink_bpf_freep) struct monitor_varlink_bpf *obj = NULL;
        _cleanup_(bpf_monitor_freep) BpfMonitor *m = NULL;
        int r;

        assert(ret);

        r = socket_xattr_supported();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether socket xattr is supported: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Kernel does not support extended attributes on socket inodes.");

        obj = monitor_varlink_bpf__open();
        if (!obj)
                return log_error_errno(errno, "Failed to open BPF object: %m");

        r = monitor_varlink_bpf__load(obj);
        if (r != 0)
                return log_error_errno(r, "Failed to load BPF object: %m");

        m = new(BpfMonitor, 1);
        if (!m)
                return log_oom_debug();

        *m = (BpfMonitor) {
                .obj = TAKE_PTR(obj),
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int bpf_monitor_set_filters(BpfMonitor *m, sd_json_variant *filters) {
        int r;

        assert(m);

        int filter_map_fd = sym_bpf_map__fd(m->obj->maps.monitor_varlink_filters);
        if (filter_map_fd < 0)
                return log_error_errno(filter_map_fd, "Failed to get fd of filter map: %m");

        if (!filters || sd_json_variant_is_null(filters)) {
                m->obj->bss->n_filters = 0;
                return 0;
        }

        if (!sd_json_variant_is_array(filters))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Filters must be an array.");

        size_t n = sd_json_variant_elements(filters);
        if (n > MONITOR_VARLINK_MAX_FILTERS)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Too many filters (%zu, max %u).", n, MONITOR_VARLINK_MAX_FILTERS);

        uint32_t i = 0;
        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, filters) {
                struct {
                        uid_t uid;
                        uint32_t pid;
                        uint64_t pidfd_ino;
                        char *path;
                } p = {
                        .uid = UID_INVALID,
                        .pid = UINT32_MAX,
                        .pidfd_ino = UINT64_MAX,
                        .path = NULL,
                };

                static const sd_json_dispatch_field filter_dispatch[] = {
                        { "uid",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, offsetof(typeof(p), uid),       SD_JSON_NULLABLE },
                        { "pid",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32,  offsetof(typeof(p), pid),       SD_JSON_NULLABLE },
                        { "pidfdInode", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,  offsetof(typeof(p), pidfd_ino), SD_JSON_NULLABLE },
                        { "path",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,  offsetof(typeof(p), path),      SD_JSON_NULLABLE },
                        {}
                };

                r = sd_json_dispatch_full(e, filter_dispatch, /* bad= */ NULL, /* flags= */ 0, &p, /* reterr_bad_field= */ NULL);
                if (r < 0)
                        return r;

                _cleanup_free_ char *path = TAKE_PTR(p.path);

                struct monitor_varlink_filter filter = {
                        .uid = p.uid,
                        .pid = p.pid,
                        .pidfd_ino = p.pidfd_ino,
                };

                if (path) {
                        size_t path_len = strlen(path);
                        if (path_len > MONITOR_VARLINK_MAX_PATH)
                                return log_error_errno(SYNTHETIC_ERRNO(ENAMETOOLONG), "Filter path too long.");

                        filter.has_path = true;
                        filter.path_len = path_len;
                        memcpy(filter.path, path, path_len);
                }

                r = sym_bpf_map_update_elem(filter_map_fd, &i, &filter, BPF_ANY);
                if (r < 0)
                        return log_error_errno(r, "Failed to update filter map: %m");

                i++;
        }

        m->obj->bss->n_filters = i;
        return 0;
}

static int bpf_monitor_attach(BpfMonitor *m) {
        int r;

        assert(m);

        r = monitor_varlink_bpf__attach(m->obj);
        m->attached = (r == 0);

        return r;
}

static void bpf_monitor_detach(BpfMonitor *m) {
        assert(m);

        if (!m->attached)
                return;

        monitor_varlink_bpf__detach(m->obj);
        m->attached = false;
}

static int bpf_monitor_get_ringbuf_fd(BpfMonitor *m) {
        int fd;

        assert(m);

        fd = sym_bpf_map__fd(m->obj->maps.monitor_varlink_ringbuf);
        if (fd < 0)
                return log_error_errno(fd, "Failed to get fd of ring buffer map: %m");

        return fd;
}

typedef struct Context {
        sd_event *event;

        sd_varlink *link;
        BpfMonitor *monitor;
        Hashmap *polkit_registry;
} Context;

static void context_done(Context *c) {
        assert(c);

        c->event = sd_event_unref(c->event);

        c->link = sd_varlink_unref(c->link);
        c->monitor = bpf_monitor_free(c->monitor);
        c->polkit_registry = hashmap_free(c->polkit_registry);
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        if (c->event)
                sd_event_exit(c->event, 0);
}

static bool filters_are_self_only(sd_json_variant *filters, uid_t peer_uid) {
        if (!filters || sd_json_variant_is_null(filters) || sd_json_variant_elements(filters) == 0)
                return false;

        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, filters) {
                sd_json_variant *uid_v = sd_json_variant_by_key(e, "uid");
                if (!uid_v || sd_json_variant_is_null(uid_v))
                        return false;
                if ((uid_t) sd_json_variant_unsigned(uid_v) != peer_uid)
                        return false;
        }

        return true;
}

static int vl_method_monitor(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_POLKIT_FIELD,
                { "filters", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant, 0, SD_JSON_NULLABLE },
                {}
        };

        _cleanup_(bpf_monitor_freep) BpfMonitor *m = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *filters = NULL;
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        if (!(flags & SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        assert(!c->monitor);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &filters);
        if (r != 0)
                return r;

        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return log_error_errno(r, "Failed to get peer UID: %m");

        bool self_only = filters_are_self_only(filters, peer_uid);

        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        self_only ? "io.systemd.varlink-monitor.monitor-self"
                                 : "io.systemd.varlink-monitor.monitor",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        /* flags= */ 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL);
        if (r == 0)
                return 0;
        if (r < 0)
                return r;

        r = bpf_monitor_new(&m);
        if (r < 0)
                return r;

        r = bpf_monitor_set_filters(m, filters);
        if (r < 0)
                return r;

        r = bpf_monitor_attach(m);
        if (r != 0)
                return log_error_errno(r, "Failed to attach BPF probes: %m");

        int ringbuf_fd = bpf_monitor_get_ringbuf_fd(m);
        if (ringbuf_fd < 0)
                return ringbuf_fd;

        int ringbuf_fd_idx = sd_varlink_push_dup_fd(link, ringbuf_fd);
        if (ringbuf_fd_idx < 0)
                return ringbuf_fd_idx;

        r = sd_varlink_notifybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("ringbufFileDescriptor", ringbuf_fd_idx));
        if (r < 0)
                return r;

        c->link = sd_varlink_ref(link);
        c->monitor = TAKE_PTR(m);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(context_done) Context c = {};
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        log_setup();

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        LIBBPF_NOTE(recommended);
        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return log_debug_errno(r, "dlopen_bpf failed: %m");

        r = sd_event_new(&c.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_VarlinkMonitor);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.VarlinkMonitor.Monitor", vl_method_monitor);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_bind_disconnect(varlink_server, on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind disconnect: %m");

        r = sd_varlink_server_set_exit_on_idle(varlink_server, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set exit on idle: %m");

        r = sd_event_add_signal(c.event, /* ret= */ NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set SIGINT handler: %m");

        r = sd_event_add_signal(c.event, /* ret= */ NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set SIGTERM handler: %m");

        r = sd_varlink_server_attach_event(varlink_server, c.event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        r = sd_varlink_server_listen_name(varlink_server, "varlink");
        if (r < 0)
                return log_error_errno(r, "Failed to get Varlink listen fd: %m");

        r = sd_event_loop(c.event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
