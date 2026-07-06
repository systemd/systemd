/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/eventfd.h>

#include "sd-event.h"
#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "user-util.h"
#include "memfd-util.h"
#include "main-func.h"
#include "log.h"
#include "varlink-io.systemd.VarlinkMonitor.h"
#include "varlink-util.h"

#include "bus-polkit.h"
#include "bpf-util.h"
#include "bpf-link.h"
#include "monitor-varlink-api.bpf.h"
#include "monitor-varlink-skel.h"

#include "ringbuf.h"


static struct monitor_varlink_bpf *monitor_varlink_bpf_free(struct monitor_varlink_bpf *obj) {
        if (obj)
                monitor_varlink_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct monitor_varlink_bpf *, monitor_varlink_bpf_free);

static struct ring_buffer *ring_buffer_free(struct ring_buffer *rb) {
        if (rb)
                bpf_ring_buffer_free(rb);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct ring_buffer *, ring_buffer_free);

typedef struct BpfMonitor {
        struct monitor_varlink_bpf *obj;
        struct ring_buffer *ring_buffer;
        sd_event_source *event_source_ring_buffer_io;
        bool attached;
} BpfMonitor;

static void bpf_monitor_detach(BpfMonitor *m);

static BpfMonitor *bpf_monitor_free(BpfMonitor *m) {
        if (!m)
                return NULL;

        bpf_monitor_detach(m);

        m->event_source_ring_buffer_io = sd_event_source_unref(m->event_source_ring_buffer_io);
        m->ring_buffer = ring_buffer_free (m->ring_buffer);
        m->obj = monitor_varlink_bpf_free(m->obj);

        free (m);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BpfMonitor *, bpf_monitor_free);

static void bpf_monitor_detach(BpfMonitor *m) {
        if (!m->attached)
                return;

        monitor_varlink_bpf__detach(m->obj);
        m->attached = false;
}

static int bpf_monitor_attach(BpfMonitor *m) {
        int r;

        r = monitor_varlink_bpf__attach(m->obj);
        m->attached = r == 0;

        return r;
}

static int on_bpf_ringbuf_io(sd_event_source *s, int fd, uint32_t events, void *userdata) {
        BpfMonitor *m = ASSERT_PTR(userdata);
        int r;

        //r = sym_ring_buffer__consume(m->ring_buffer);
        r = sym_ring_buffer__poll(m->ring_buffer, /* timeout_msec= */ 0);
        if (r < 0)
                return log_error_errno(r, "Got failure reading from BPF ring buffer: %m");

        return 0;
}

static int bpf_monitor_new(BpfMonitor **ret, sd_event *event, ring_buffer_sample_fn fn, void *userdata) {
        _cleanup_(bpf_monitor_freep) BpfMonitor *m = NULL;
        int r;

        m = new(BpfMonitor, 1);
        if (!m)
                return log_oom_debug();

        m->obj = monitor_varlink_bpf__open();
        if (!m->obj)
                return log_debug_errno(errno, "Failed to open BPF object: %m");

        r = sym_bpf_map__set_pin_path(m->obj->maps.unix_socket_protocol_ino_map,
                                      "/sys/fs/bpf/systemd/unix-socket-protocol/maps/unix_socket_protocol_ino_map");
        if (r < 0)
                return log_error_errno(r, "Failed to set pin path for inode storage map: %m");

        r = monitor_varlink_bpf__load(m->obj);
        if (r != 0)
                return log_debug_errno(r, "Failed to load BPF object: %m");

        int rb_fd = -EBADF, poll_fd = -EBADF;
        rb_fd = sym_bpf_map__fd(m->obj->maps.monitor_varlink_ringbuf);
        if (rb_fd < 0)
                return log_error_errno(rb_fd, "Failed to get fd of ring buffer: %m");

        m->ring_buffer = sym_ring_buffer__new(rb_fd, fn, userdata, NULL);
        if (!m->ring_buffer)
                return log_error_errno(errno, "Failed to allocate BPF ring buffer object: %m");

        poll_fd = sym_ring_buffer__epoll_fd(m->ring_buffer);
        if (poll_fd < 0)
                return log_error_errno(poll_fd, "Failed to get poll fd of ring buffer: %m");

        r = sd_event_add_io(
                        event,
                        &m->event_source_ring_buffer_io,
                        poll_fd,
                        EPOLLIN,
                        on_bpf_ringbuf_io,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event source for BPF ring buffer: %m");

        (void) sd_event_source_set_description(m->event_source_ring_buffer_io, "varlink-monitor-ring-buffer");

        *ret = TAKE_PTR(m);
        return 0;
}

typedef enum ContextState {
        CONTEXT_STATE_INIT,
        CONTEXT_STATE_SETUP,
        CONTEXT_STATE_STARTED,
        CONTEXT_STATE_STOPPED,
        CONTEXT_STATE_EXITED,
} ContextState;

typedef struct Context {
        ContextState state;
        sd_event *event;

        uid_t uid;
        Ringbuf *rb;
        BpfMonitor *monitor;
        Hashmap *polkit_registry;
} Context;

static void context_done(Context *c) {
        assert(c);

        c->event = sd_event_unref(c->event);

        c->rb = ringbuf_unref(c->rb);
        c->monitor = bpf_monitor_free(c->monitor);
        c->polkit_registry = hashmap_free(c->polkit_registry);
}

static void context_shutdown(Context *c) {
        if (c->state != CONTEXT_STATE_EXITED && c->event)
                sd_event_exit(c->event, 0);

        c->state = CONTEXT_STATE_EXITED;
}

static void on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        context_shutdown(c);
}

static int on_bpf_monitor_data(void *userdata, void *data, size_t size) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        if (size < sizeof(struct monitor_varlink_packet))
                return 0;

        struct monitor_varlink_packet *p = data;

        if (uid_is_valid(c->uid) && p->uid != c->uid && p->peer_uid != c->uid)
                return 0;

        r = ringbuf_write(c->rb, data, size);
        if (r < 0)
                return log_error_errno(r, "Failed to write to ring buffer: %m");

        r = ringbuf_flush(c->rb);
        if (r < 0)
                return log_error_errno(r, "Failed to flush ring buffer: %m");

        return 0;
}

static void on_ringbuf_shutdown(Ringbuf *rb, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        context_shutdown(c);
}

typedef struct SetupParameters {
        unsigned ringbuf_memfd_idx;
        uid_t uid;
} SetupParameters;

static int vl_method_setup(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "ringbufFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,    offsetof(SetupParameters, ringbuf_memfd_idx), SD_JSON_MANDATORY },
                { "uid",                   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, offsetof(SetupParameters, uid),           0                 },
                {}
        };

        _cleanup_close_ int ringbuf_memfd = -EBADF;
        _cleanup_(ringbuf_unrefp) Ringbuf *rb = NULL;
        _cleanup_(bpf_monitor_freep) BpfMonitor *m = NULL;
        Context *c = ASSERT_PTR(userdata);
        SetupParameters p = {
                .ringbuf_memfd_idx = UINT_MAX,
                .uid = UID_INVALID,
        };
        int r;

        assert(link);
        assert(parameters);

        if (c->state != CONTEXT_STATE_INIT)
                return sd_varlink_error(link, "io.systemd.VarlinkMonitor.BadState", NULL);

        assert (c->uid == UID_INVALID);
        assert (c->rb == NULL);
        assert (c->monitor == NULL);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        ringbuf_memfd = sd_varlink_peek_dup_fd(link, p.ringbuf_memfd_idx);
        if (ringbuf_memfd < 0)
                return log_debug_errno(ringbuf_memfd, "Failed to take ring buffer fd from Varlink connection: %m");

        r = varlink_verify_polkit_async_full(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.varlink-monitor.monitor",
                        /* details= */ NULL,
                        /* good_user= */ p.uid,
                        /* flags= */ 0,
                        &c->polkit_registry,
                        /* ret_admin= */ NULL);
        if (r <= 0)
                return r;

        r = bpf_monitor_new(&m, c->event, on_bpf_monitor_data, c);
        if (r < 0)
                return log_error_errno(r, "Failed to create the BPF varlink monitor: %m");

        r = ringbuf_new(&rb, RINGBUF_SIDE_WRITER);
        if (r < 0)
                return log_error_errno(r, "Failed to create ring buffer: %m");

        ringbuf_set_userdata(rb, c);

        r = ringbuf_set_memfd(rb, TAKE_FD(ringbuf_memfd));
        if (r < 0)
                return log_error_errno(r, "Failed to set ring buffer memfd: %m");

        r = ringbuf_bind_shutdown(rb, on_ringbuf_shutdown);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to ring buffer shutdown: %m");

        r = ringbuf_attach_event(rb, c->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach ring buffer to event loop: %m");

        r = ringbuf_create_eventfds(rb);
        if (r < 0)
                return log_error_errno(r, "Failed to create ring buffer eventfds: %m");

        int reader_eventfd, writer_eventfd;
        r = ringbuf_get_eventfds(rb, &reader_eventfd, &writer_eventfd);

        int read_eventfd_idx = sd_varlink_push_dup_fd(link, reader_eventfd);
        if (read_eventfd_idx < 0)
                return read_eventfd_idx;

        int write_eventfd_idx = sd_varlink_push_dup_fd(link, writer_eventfd);
        if (write_eventfd_idx < 0)
                return write_eventfd_idx;

         r = sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_INTEGER("eventfdReadFileDescriptor", read_eventfd_idx),
                        SD_JSON_BUILD_PAIR_INTEGER("eventfdWriteFileDescriptor", write_eventfd_idx));
        if (r < 0)
                return r;

        c->state = CONTEXT_STATE_SETUP;
        c->uid = p.uid;
        c->rb = TAKE_PTR(rb);
        c->monitor = TAKE_PTR(m);

        return r;
}

static int vl_method_start(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(link);

        if (!IN_SET(c->state, CONTEXT_STATE_SETUP, CONTEXT_STATE_STOPPED))
                return sd_varlink_error(link, "io.systemd.VarlinkMonitor.BadState", NULL);

        r = bpf_monitor_attach(c->monitor);
        if (r != 0)
                return log_debug_errno(r, "Failed to attach BPF object: %m");

        c->state = CONTEXT_STATE_STARTED;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_stop(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        assert(link);

        if (c->state != CONTEXT_STATE_STARTED)
                return sd_varlink_error(link, "io.systemd.VarlinkMonitor.BadState", NULL);

        bpf_monitor_detach(c->monitor);

        c->state = CONTEXT_STATE_STOPPED;

        return sd_varlink_reply(link, NULL);
}

// FIXME: doesn't seem so stop; should not start when activated without connection
static int run(int argc, char *argv[]) {
        _cleanup_(context_done) Context c = {
                .state = CONTEXT_STATE_INIT,
                .event = NULL,

                .uid = UID_INVALID,
        };
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        log_setup();

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = dlopen_bpf(LOG_WARNING);
        if (r < 0)
                return log_debug_errno(r, "dlopen_bpf failed: %m");

        r = sd_event_new(&c.event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = varlink_server_new(
                        &varlink_server,
                        SD_VARLINK_SERVER_INHERIT_USERDATA |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT | SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_VarlinkMonitor);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.VarlinkMonitor.Setup", vl_method_setup,
                        "io.systemd.VarlinkMonitor.Start", vl_method_start,
                        "io.systemd.VarlinkMonitor.Stop", vl_method_stop);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

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
