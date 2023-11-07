/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"

#include "af-list.h"
#include "alloc-util.h"
#include "bus-container.h"
#include "bus-control.h"
#include "bus-internal.h"
#include "bus-kernel.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-objects.h"
#include "bus-protocol.h"
#include "bus-slot.h"
#include "bus-socket.h"
#include "bus-track.h"
#include "bus-type.h"
#include "cgroup-util.h"
#include "constants.h"
#include "errno-util.h"
#include "fd-util.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "io-util.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "missing_threads.h"
#include "origin-id.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

#define log_debug_bus_message(m)                                         \
        do {                                                             \
                sd_bus_message *_mm = (m);                               \
                log_debug("Got message type=%s sender=%s destination=%s path=%s interface=%s member=%s " \
                          " cookie=%" PRIu64 " reply_cookie=%" PRIu64   \
                          " signature=%s error-name=%s error-message=%s", \
                          strna(bus_message_type_to_string(_mm->header->type)), \
                          strna(sd_bus_message_get_sender(_mm)),         \
                          strna(sd_bus_message_get_destination(_mm)),    \
                          strna(sd_bus_message_get_path(_mm)),           \
                          strna(sd_bus_message_get_interface(_mm)),      \
                          strna(sd_bus_message_get_member(_mm)),         \
                          BUS_MESSAGE_COOKIE(_mm),                       \
                          _mm->reply_cookie,                             \
                          strna(_mm->root_container.signature),          \
                          strna(_mm->error.name),                        \
                          strna(_mm->error.message));                    \
        } while (false)

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec);
static void bus_detach_io_events(sd_bus *b);

static thread_local sd_bus *default_system_bus = NULL;
static thread_local sd_bus *default_user_bus = NULL;
static thread_local sd_bus *default_starter_bus = NULL;

static sd_bus **bus_choose_default(int (**bus_open)(sd_bus **)) {
        const char *e;

        /* Let's try our best to reuse another cached connection. If
         * the starter bus type is set, connect via our normal
         * connection logic, ignoring $DBUS_STARTER_ADDRESS, so that
         * we can share the connection with the user/system default
         * bus. */

        e = secure_getenv("DBUS_STARTER_BUS_TYPE");
        if (e) {
                if (streq(e, "system")) {
                        if (bus_open)
                                *bus_open = sd_bus_open_system;
                        return &default_system_bus;
                } else if (STR_IN_SET(e, "user", "session")) {
                        if (bus_open)
                                *bus_open = sd_bus_open_user;
                        return &default_user_bus;
                }
        }

        /* No type is specified, so we have not other option than to
         * use the starter address if it is set. */
        e = secure_getenv("DBUS_STARTER_ADDRESS");
        if (e) {
                if (bus_open)
                        *bus_open = sd_bus_open;
                return &default_starter_bus;
        }

        /* Finally, if nothing is set use the cached connection for
         * the right scope */

        if (cg_pid_get_owner_uid(0, NULL) >= 0) {
                if (bus_open)
                        *bus_open = sd_bus_open_user;
                return &default_user_bus;
        } else {
                if (bus_open)
                        *bus_open = sd_bus_open_system;
                return &default_system_bus;
        }
}

sd_bus *bus_resolve(sd_bus *bus) {
        switch ((uintptr_t) bus) {
        case (uintptr_t) SD_BUS_DEFAULT:
                return *(bus_choose_default(NULL));
        case (uintptr_t) SD_BUS_DEFAULT_USER:
                return default_user_bus;
        case (uintptr_t) SD_BUS_DEFAULT_SYSTEM:
                return default_system_bus;
        default:
                return bus;
        }
}

void bus_close_io_fds(sd_bus *b) {
        assert(b);

        bus_detach_io_events(b);

        if (b->input_fd != b->output_fd)
                safe_close(b->output_fd);
        b->output_fd = b->input_fd = safe_close(b->input_fd);
}

void bus_close_inotify_fd(sd_bus *b) {
        assert(b);

        b->inotify_event_source = sd_event_source_disable_unref(b->inotify_event_source);

        b->inotify_fd = safe_close(b->inotify_fd);
        b->inotify_watches = mfree(b->inotify_watches);
        b->n_inotify_watches = 0;
}

static void bus_reset_queues(sd_bus *b) {
        assert(b);

        while (b->rqueue_size > 0)
                bus_message_unref_queued(b->rqueue[--b->rqueue_size], b);

        b->rqueue = mfree(b->rqueue);

        while (b->wqueue_size > 0)
                bus_message_unref_queued(b->wqueue[--b->wqueue_size], b);

        b->wqueue = mfree(b->wqueue);
}

static sd_bus* bus_free(sd_bus *b) {
        sd_bus_slot *s;

        assert(b);
        assert(!b->track_queue);
        assert(!b->tracks);

        b->state = BUS_CLOSED;

        sd_bus_detach_event(b);

        while ((s = b->slots)) {
                /* At this point only floating slots can still be
                 * around, because the non-floating ones keep a
                 * reference to the bus, and we thus couldn't be
                 * destructing right now... We forcibly disconnect the
                 * slots here, so that they still can be referenced by
                 * apps, but are dead. */

                assert(s->floating);
                bus_slot_disconnect(s, true);
        }

        if (b->default_bus_ptr)
                *b->default_bus_ptr = NULL;

        bus_close_io_fds(b);
        bus_close_inotify_fd(b);

        free(b->label);
        free(b->groups);
        free(b->rbuffer);
        free(b->unique_name);
        free(b->auth_buffer);
        free(b->address);
        free(b->machine);
        free(b->description);
        free(b->patch_sender);

        free(b->exec_path);
        strv_free(b->exec_argv);

        close_many(b->fds, b->n_fds);
        free(b->fds);

        bus_reset_queues(b);

        ordered_hashmap_free_free(b->reply_callbacks);
        prioq_free(b->reply_callbacks_prioq);

        assert(b->match_callbacks.type == BUS_MATCH_ROOT);
        bus_match_free(&b->match_callbacks);

        hashmap_free_free(b->vtable_methods);
        hashmap_free_free(b->vtable_properties);

        assert(hashmap_isempty(b->nodes));
        hashmap_free(b->nodes);

        bus_flush_memfd(b);

        assert_se(pthread_mutex_destroy(&b->memfd_cache_mutex) == 0);

        return mfree(b);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus*, bus_free);

DEFINE_ORIGIN_ID_HELPERS(sd_bus, bus);

_public_ int sd_bus_new(sd_bus **ret) {
        _cleanup_free_ sd_bus *b = NULL;

        assert_return(ret, -EINVAL);

        b = new(sd_bus, 1);
        if (!b)
                return -ENOMEM;

        *b = (sd_bus) {
                .n_ref = 1,
                .input_fd = -EBADF,
                .output_fd = -EBADF,
                .inotify_fd = -EBADF,
                .message_version = 1,
                .creds_mask = SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME,
                .accept_fd = true,
                .origin_id = origin_id_query(),
                .n_groups = SIZE_MAX,
                .close_on_exit = true,
                .ucred = UCRED_INVALID,
                .runtime_scope = _RUNTIME_SCOPE_INVALID,
                .connect_as_uid = UID_INVALID,
                .connect_as_gid = GID_INVALID,
        };

        /* We guarantee that wqueue always has space for at least one entry */
        if (!GREEDY_REALLOC(b->wqueue, 1))
                return -ENOMEM;

        assert_se(pthread_mutex_init(&b->memfd_cache_mutex, NULL) == 0);

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ int sd_bus_set_address(sd_bus *bus, const char *address) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(address, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return free_and_strdup(&bus->address, address);
}

_public_ int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(input_fd >= 0, -EBADF);
        assert_return(output_fd >= 0, -EBADF);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->input_fd = input_fd;
        bus->output_fd = output_fd;
        return 0;
}

_public_ int sd_bus_set_exec(sd_bus *bus, const char *path, char *const *argv) {
        _cleanup_strv_free_ char **a = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(path, -EINVAL);
        assert_return(!strv_isempty(argv), -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        a = strv_copy(argv);
        if (!a)
                return -ENOMEM;

        r = free_and_strdup(&bus->exec_path, path);
        if (r < 0)
                return r;

        return strv_free_and_replace(bus->exec_argv, a);
}

_public_ int sd_bus_set_bus_client(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus->patch_sender, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->bus_client = b;
        return 0;
}

_public_ int sd_bus_set_monitor(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->is_monitor = b;
        return 0;
}

_public_ int sd_bus_negotiate_fds(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->accept_fd = b;
        return 0;
}

_public_ int sd_bus_negotiate_timestamp(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!IN_SET(bus->state, BUS_CLOSING, BUS_CLOSED), -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        /* This is not actually supported by any of our transports these days, but we do honour it for synthetic
         * replies, and maybe one day classic D-Bus learns this too */
        bus->attach_timestamp = b;

        return 0;
}

_public_ int sd_bus_negotiate_creds(sd_bus *bus, int b, uint64_t mask) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(mask <= _SD_BUS_CREDS_ALL, -EINVAL);
        assert_return(!IN_SET(bus->state, BUS_CLOSING, BUS_CLOSED), -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        SET_FLAG(bus->creds_mask, mask, b);

        /* The well knowns we need unconditionally, so that matches can work */
        bus->creds_mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME;

        return 0;
}

_public_ int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(b || sd_id128_equal(server_id, SD_ID128_NULL), -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->is_server = b;
        bus->server_id = server_id;
        return 0;
}

_public_ int sd_bus_set_anonymous(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->anonymous_auth = b;
        return 0;
}

_public_ int sd_bus_set_trusted(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->trusted = b;
        return 0;
}

_public_ int sd_bus_set_description(sd_bus *bus, const char *description) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return free_and_strdup(&bus->description, description);
}

_public_ int sd_bus_set_allow_interactive_authorization(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->allow_interactive_authorization = b;
        return 0;
}

_public_ int sd_bus_get_allow_interactive_authorization(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->allow_interactive_authorization;
}

_public_ int sd_bus_set_watch_bind(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->watch_bind = b;
        return 0;
}

_public_ int sd_bus_get_watch_bind(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->watch_bind;
}

_public_ int sd_bus_set_connected_signal(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus->connected_signal = b;
        return 0;
}

_public_ int sd_bus_get_connected_signal(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->connected_signal;
}

static int synthesize_connected_signal(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        /* If enabled, synthesizes a local "Connected" signal mirroring the local "Disconnected" signal. This is called
         * whenever we fully established a connection, i.e. after the authorization phase, and after receiving the
         * Hello() reply. Or in other words, whenever we enter BUS_RUNNING state.
         *
         * This is useful so that clients can start doing stuff whenever the connection is fully established in a way
         * that works independently from whether we connected to a full bus or just a direct connection. */

        if (!bus->connected_signal)
                return 0;

        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/DBus/Local",
                        "org.freedesktop.DBus.Local",
                        "Connected");
        if (r < 0)
                return r;

        bus_message_set_sender_local(bus, m);
        m->read_counter = ++bus->read_counter;

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        /* Insert at the very front */
        memmove(bus->rqueue + 1, bus->rqueue, sizeof(sd_bus_message*) * bus->rqueue_size);
        bus->rqueue[0] = bus_message_ref_queued(m, bus);
        bus->rqueue_size++;

        return 0;
}

void bus_set_state(sd_bus *bus, enum bus_state state) {
        static const char* const table[_BUS_STATE_MAX] = {
                [BUS_UNSET]          = "UNSET",
                [BUS_WATCH_BIND]     = "WATCH_BIND",
                [BUS_OPENING]        = "OPENING",
                [BUS_AUTHENTICATING] = "AUTHENTICATING",
                [BUS_HELLO]          = "HELLO",
                [BUS_RUNNING]        = "RUNNING",
                [BUS_CLOSING]        = "CLOSING",
                [BUS_CLOSED]         = "CLOSED",
        };

        assert(bus);
        assert(state < _BUS_STATE_MAX);

        if (state == bus->state)
                return;

        log_debug("Bus %s: changing state %s %s %s", strna(bus->description),
                  table[bus->state], special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), table[state]);
        bus->state = state;
}

static int hello_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        const char *s;
        sd_bus *bus;
        int r;

        assert(reply);
        bus = reply->bus;
        assert(bus);
        assert(IN_SET(bus->state, BUS_HELLO, BUS_CLOSING));

        r = sd_bus_message_get_errno(reply);
        if (r > 0) {
                r = -r;
                goto fail;
        }

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                goto fail;

        if (!service_name_is_valid(s) || s[0] != ':') {
                r = -EBADMSG;
                goto fail;
        }

        r = free_and_strdup(&bus->unique_name, s);
        if (r < 0)
                goto fail;

        if (bus->state == BUS_HELLO) {
                bus_set_state(bus, BUS_RUNNING);

                r = synthesize_connected_signal(bus);
                if (r < 0)
                        goto fail;
        }

        return 1;

fail:
        /* When Hello() failed, let's propagate this in two ways: first we return the error immediately here,
         * which is the propagated up towards the event loop. Let's also invalidate the connection, so that
         * if the user then calls back into us again we won't wait any longer. */

        bus_set_state(bus, BUS_CLOSING);
        return r;
}

static int bus_send_hello(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);

        if (!bus->bus_client)
                return 0;

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        "Hello");
        if (r < 0)
                return r;

        return sd_bus_call_async(bus, NULL, m, hello_callback, NULL, 0);
}

int bus_start_running(sd_bus *bus) {
        struct reply_callback *c;
        usec_t n;
        int r;

        assert(bus);
        assert(bus->state < BUS_HELLO);

        /* We start all method call timeouts when we enter BUS_HELLO or BUS_RUNNING mode. At this point let's convert
         * all relative to absolute timestamps. Note that we do not reshuffle the reply callback priority queue since
         * adding a fixed value to all entries should not alter the internal order. */

        n = now(CLOCK_MONOTONIC);
        ORDERED_HASHMAP_FOREACH(c, bus->reply_callbacks) {
                if (c->timeout_usec == 0)
                        continue;

                c->timeout_usec = usec_add(n, c->timeout_usec);
        }

        if (bus->bus_client) {
                bus_set_state(bus, BUS_HELLO);
                return 1;
        }

        bus_set_state(bus, BUS_RUNNING);

        r = synthesize_connected_signal(bus);
        if (r < 0)
                return r;

        return 1;
}

static int parse_address_key(const char **p, const char *key, char **value) {
        _cleanup_free_ char *r = NULL;
        size_t l, n = 0;
        const char *a;

        assert(p);
        assert(*p);
        assert(value);

        if (key) {
                l = strlen(key);
                if (strncmp(*p, key, l) != 0)
                        return 0;

                if ((*p)[l] != '=')
                        return 0;

                if (*value)
                        return -EINVAL;

                a = *p + l + 1;
        } else
                a = *p;

        while (!IN_SET(*a, ';', ',', 0)) {
                char c;

                if (*a == '%') {
                        int x, y;

                        x = unhexchar(a[1]);
                        if (x < 0)
                                return x;

                        y = unhexchar(a[2]);
                        if (y < 0)
                                return y;

                        c = (char) ((x << 4) | y);
                        a += 3;
                } else {
                        c = *a;
                        a++;
                }

                if (!GREEDY_REALLOC(r, n + 2))
                        return -ENOMEM;

                r[n++] = c;
        }

        if (!r) {
                r = strdup("");
                if (!r)
                        return -ENOMEM;
        } else
                r[n] = 0;

        if (*a == ',')
                a++;

        *p = a;

        free_and_replace(*value, r);

        return 1;
}

static void skip_address_key(const char **p) {
        assert(p);
        assert(*p);

        *p += strcspn(*p, ",");

        if (**p == ',')
                (*p)++;
}

static int parse_unix_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *path = NULL, *abstract = NULL, *uids = NULL, *gids = NULL;
        size_t l;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (!IN_SET(**p, 0, ';')) {
                r = parse_address_key(p, "guid", guid);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "path", &path);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "abstract", &abstract);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "uid", &uids);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "gid", &gids);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                skip_address_key(p);
        }

        if (!path && !abstract)
                return -EINVAL;

        if (path && abstract)
                return -EINVAL;

        if (path) {
                l = strlen(path);
                if (l >= sizeof(b->sockaddr.un.sun_path)) /* We insist on NUL termination */
                        return -E2BIG;

                b->sockaddr.un = (struct sockaddr_un) {
                        .sun_family = AF_UNIX,
                };

                memcpy(b->sockaddr.un.sun_path, path, l);
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l + 1;

        } else {
                assert(abstract);

                l = strlen(abstract);
                if (l >= sizeof(b->sockaddr.un.sun_path) - 1) /* We insist on NUL termination */
                        return -E2BIG;

                b->sockaddr.un = (struct sockaddr_un) {
                        .sun_family = AF_UNIX,
                };

                memcpy(b->sockaddr.un.sun_path+1, abstract, l);
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + 1 + l;
        }

        if (uids) {
                r = parse_uid(uids, &b->connect_as_uid);
                if (r < 0)
                        return r;
        }
        if (gids) {
                r = parse_gid(gids, &b->connect_as_gid);
                if (r < 0)
                        return r;
        }

        b->is_local = true;

        return 0;
}

static int parse_tcp_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *host = NULL, *port = NULL, *family = NULL;
        int r;
        struct addrinfo *result, hints = {
                .ai_socktype = SOCK_STREAM,
        };

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (!IN_SET(**p, 0, ';')) {
                r = parse_address_key(p, "guid", guid);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "host", &host);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "port", &port);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "family", &family);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                skip_address_key(p);
        }

        if (!host || !port)
                return -EINVAL;

        if (family) {
                hints.ai_family = af_from_ipv4_ipv6(family);
                if (hints.ai_family == AF_UNSPEC)
                        return -EINVAL;
        }

        r = getaddrinfo(host, port, &hints, &result);
        if (r == EAI_SYSTEM)
                return -errno;
        else if (r != 0)
                return -EADDRNOTAVAIL;

        memcpy(&b->sockaddr, result->ai_addr, result->ai_addrlen);
        b->sockaddr_size = result->ai_addrlen;

        freeaddrinfo(result);

        b->is_local = false;

        return 0;
}

static int parse_exec_address(sd_bus *b, const char **p, char **guid) {
        char *path = NULL;
        unsigned n_argv = 0, j;
        char **argv = NULL;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (!IN_SET(**p, 0, ';')) {
                r = parse_address_key(p, "guid", guid);
                if (r < 0)
                        goto fail;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "path", &path);
                if (r < 0)
                        goto fail;
                else if (r > 0)
                        continue;

                if (startswith(*p, "argv")) {
                        unsigned ul;

                        errno = 0;
                        ul = strtoul(*p + 4, (char**) p, 10);
                        if (errno > 0 || **p != '=' || ul > 256) {
                                r = -EINVAL;
                                goto fail;
                        }

                        (*p)++;

                        if (ul >= n_argv) {
                                if (!GREEDY_REALLOC0(argv, ul + 2)) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                n_argv = ul + 1;
                        }

                        r = parse_address_key(p, NULL, argv + ul);
                        if (r < 0)
                                goto fail;

                        continue;
                }

                skip_address_key(p);
        }

        if (!path) {
                r = -EINVAL;
                goto fail;
        }

        /* Make sure there are no holes in the array, with the
         * exception of argv[0] */
        for (j = 1; j < n_argv; j++)
                if (!argv[j]) {
                        r = -EINVAL;
                        goto fail;
                }

        if (argv && argv[0] == NULL) {
                argv[0] = strdup(path);
                if (!argv[0]) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        b->exec_path = path;
        b->exec_argv = argv;

        b->is_local = false;

        return 0;

fail:
        for (j = 0; j < n_argv; j++)
                free(argv[j]);

        free(argv);
        free(path);
        return r;
}

static int parse_container_unix_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *machine = NULL, *pid = NULL;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (!IN_SET(**p, 0, ';')) {
                r = parse_address_key(p, "guid", guid);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "machine", &machine);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                r = parse_address_key(p, "pid", &pid);
                if (r < 0)
                        return r;
                else if (r > 0)
                        continue;

                skip_address_key(p);
        }

        if (!machine == !pid)
                return -EINVAL;

        if (machine) {
                if (!hostname_is_valid(machine, VALID_HOSTNAME_DOT_HOST))
                        return -EINVAL;

                free_and_replace(b->machine, machine);
        } else
                b->machine = mfree(b->machine);

        if (pid) {
                r = parse_pid(pid, &b->nspid);
                if (r < 0)
                        return r;
        } else
                b->nspid = 0;

        b->sockaddr.un = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
                /* Note that we use the old /var/run prefix here, to increase compatibility with really old containers */
                .sun_path = "/var/run/dbus/system_bus_socket",
        };
        b->sockaddr_size = SOCKADDR_UN_LEN(b->sockaddr.un);
        b->is_local = false;

        return 0;
}

static void bus_reset_parsed_address(sd_bus *b) {
        assert(b);

        zero(b->sockaddr);
        b->sockaddr_size = 0;
        b->exec_argv = strv_free(b->exec_argv);
        b->exec_path = mfree(b->exec_path);
        b->server_id = SD_ID128_NULL;
        b->machine = mfree(b->machine);
        b->nspid = 0;
}

static int bus_parse_next_address(sd_bus *b) {
        _cleanup_free_ char *guid = NULL;
        const char *a;
        int r;

        assert(b);

        if (!b->address)
                return 0;
        if (b->address[b->address_index] == 0)
                return 0;

        bus_reset_parsed_address(b);

        a = b->address + b->address_index;

        while (*a != 0) {

                if (*a == ';') {
                        a++;
                        continue;
                }

                if (startswith(a, "unix:")) {
                        a += 5;

                        r = parse_unix_address(b, &a, &guid);
                        if (r < 0)
                                return r;
                        break;

                } else if (startswith(a, "tcp:")) {

                        a += 4;
                        r = parse_tcp_address(b, &a, &guid);
                        if (r < 0)
                                return r;

                        break;

                } else if (startswith(a, "unixexec:")) {

                        a += 9;
                        r = parse_exec_address(b, &a, &guid);
                        if (r < 0)
                                return r;

                        break;

                } else if (startswith(a, "x-machine-unix:")) {

                        a += 15;
                        r = parse_container_unix_address(b, &a, &guid);
                        if (r < 0)
                                return r;

                        break;
                }

                a = strchr(a, ';');
                if (!a)
                        return 0;
        }

        if (guid) {
                r = sd_id128_from_string(guid, &b->server_id);
                if (r < 0)
                        return r;
        }

        b->address_index = a - b->address;
        return 1;
}

static void bus_kill_exec(sd_bus *bus) {
        if (!pid_is_valid(bus->busexec_pid))
                return;

        sigterm_wait(TAKE_PID(bus->busexec_pid));
}

static int bus_start_address(sd_bus *b) {
        int r;

        assert(b);

        for (;;) {
                bus_close_io_fds(b);
                bus_close_inotify_fd(b);

                bus_kill_exec(b);

                /* If you provide multiple different bus-addresses, we
                 * try all of them in order and use the first one that
                 * succeeds. */

                if (b->exec_path)
                        r = bus_socket_exec(b);
                else if ((b->nspid > 0 || b->machine) && b->sockaddr.sa.sa_family != AF_UNSPEC)
                        r = bus_container_connect_socket(b);
                else if (b->sockaddr.sa.sa_family != AF_UNSPEC)
                        r = bus_socket_connect(b);
                else
                        goto next;

                if (r >= 0) {
                        int q;

                        q = bus_attach_io_events(b);
                        if (q < 0)
                                return q;

                        q = bus_attach_inotify_event(b);
                        if (q < 0)
                                return q;

                        return r;
                }

                b->last_connect_error = -r;

        next:
                r = bus_parse_next_address(b);
                if (r < 0)
                        return r;
                if (r == 0)
                        return b->last_connect_error > 0 ? -b->last_connect_error : -ECONNREFUSED;
        }
}

int bus_next_address(sd_bus *b) {
        assert(b);

        bus_reset_parsed_address(b);
        return bus_start_address(b);
}

static int bus_start_fd(sd_bus *b) {
        struct stat st;
        int r;

        assert(b);
        assert(b->input_fd >= 0);
        assert(b->output_fd >= 0);

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *pi = NULL, *po = NULL;
                (void) fd_get_path(b->input_fd, &pi);
                (void) fd_get_path(b->output_fd, &po);
                log_debug("sd-bus: starting bus%s%s on fds %d/%d (%s, %s)...",
                          b->description ? " " : "", strempty(b->description),
                          b->input_fd, b->output_fd,
                          pi ?: "???", po ?: "???");
        }

        r = fd_nonblock(b->input_fd, true);
        if (r < 0)
                return r;

        r = fd_cloexec(b->input_fd, true);
        if (r < 0)
                return r;

        if (b->input_fd != b->output_fd) {
                r = fd_nonblock(b->output_fd, true);
                if (r < 0)
                        return r;

                r = fd_cloexec(b->output_fd, true);
                if (r < 0)
                        return r;
        }

        if (fstat(b->input_fd, &st) < 0)
                return -errno;

        return bus_socket_take_fd(b);
}

_public_ int sd_bus_start(sd_bus *bus) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        bus_set_state(bus, BUS_OPENING);

        if (bus->is_server && bus->bus_client)
                return -EINVAL;

        if (bus->input_fd >= 0)
                r = bus_start_fd(bus);
        else if (bus->address || bus->sockaddr.sa.sa_family != AF_UNSPEC || bus->exec_path || bus->machine)
                r = bus_start_address(bus);
        else
                return -EINVAL;

        if (r < 0) {
                sd_bus_close(bus);
                return r;
        }

        return bus_send_hello(bus);
}

_public_ int sd_bus_open_with_description(sd_bus **ret, const char *description) {
        const char *e;
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(ret, -EINVAL);

        /* Let's connect to the starter bus if it is set, and
         * otherwise to the bus that is appropriate for the scope
         * we are running in */

        e = secure_getenv("DBUS_STARTER_BUS_TYPE");
        if (e) {
                if (streq(e, "system"))
                        return sd_bus_open_system_with_description(ret, description);
                else if (STR_IN_SET(e, "session", "user"))
                        return sd_bus_open_user_with_description(ret, description);
        }

        e = secure_getenv("DBUS_STARTER_ADDRESS");
        if (!e) {
                if (cg_pid_get_owner_uid(0, NULL) >= 0)
                        return sd_bus_open_user_with_description(ret, description);
                else
                        return sd_bus_open_system_with_description(ret, description);
        }

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = sd_bus_set_address(b, e);
        if (r < 0)
                return r;

        b->bus_client = true;

        /* We don't know whether the bus is trusted or not, so better
         * be safe, and authenticate everything */
        b->trusted = false;
        b->is_local = false;
        b->creds_mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_EFFECTIVE_CAPS;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ int sd_bus_open(sd_bus **ret) {
        return sd_bus_open_with_description(ret, NULL);
}

int bus_set_address_system(sd_bus *b) {
        const char *e;
        int r;

        assert(b);

        e = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");

        r = sd_bus_set_address(b, e ?: DEFAULT_SYSTEM_BUS_ADDRESS);
        if (r < 0)
                return r;

        b->runtime_scope = RUNTIME_SCOPE_SYSTEM;
        return r;
}

_public_ int sd_bus_open_system_with_description(sd_bus **ret, const char *description) {
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        if (description) {
                r = sd_bus_set_description(b, description);
                if (r < 0)
                        return r;
        }

        r = bus_set_address_system(b);
        if (r < 0)
                return r;

        b->bus_client = true;

        /* Let's do per-method access control on the system bus. We
         * need the caller's UID and capability set for that. */
        b->trusted = false;
        b->creds_mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_EFFECTIVE_CAPS;
        b->is_local = true;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ int sd_bus_open_system(sd_bus **ret) {
        return sd_bus_open_system_with_description(ret, NULL);
}

int bus_set_address_user(sd_bus *b) {
        const char *a;
        _cleanup_free_ char *_a = NULL;
        int r;

        assert(b);

        a = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
        if (!a) {
                const char *e;
                _cleanup_free_ char *ee = NULL;

                e = secure_getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                               "sd-bus: $XDG_RUNTIME_DIR not set, cannot connect to user bus.");

                ee = bus_address_escape(e);
                if (!ee)
                        return -ENOMEM;

                if (asprintf(&_a, DEFAULT_USER_BUS_ADDRESS_FMT, ee) < 0)
                        return -ENOMEM;
                a = _a;
        }

        r = sd_bus_set_address(b, a);
        if (r < 0)
                return r;

        b->runtime_scope = RUNTIME_SCOPE_USER;
        return r;
}

_public_ int sd_bus_open_user_with_description(sd_bus **ret, const char *description) {
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        if (description) {
                r = sd_bus_set_description(b, description);
                if (r < 0)
                        return r;
        }

        r = bus_set_address_user(b);
        if (r < 0)
                return r;

        b->bus_client = true;

        /* We don't do any per-method access control on the user bus. */
        b->trusted = true;
        b->is_local = true;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ int sd_bus_open_user(sd_bus **ret) {
        return sd_bus_open_user_with_description(ret, NULL);
}

int bus_set_address_system_remote(sd_bus *b, const char *host) {
        _cleanup_free_ char *e = NULL;
        char *m = NULL, *c = NULL, *a, *rbracket = NULL, *p = NULL;

        assert(b);
        assert(host);

        /* Skip ":"s in ipv6 addresses */
        if (*host == '[') {
                char *t;

                rbracket = strchr(host, ']');
                if (!rbracket)
                        return -EINVAL;
                t = strndupa_safe(host + 1, rbracket - host - 1);
                e = bus_address_escape(t);
                if (!e)
                        return -ENOMEM;
        } else if ((a = strchr(host, '@'))) {
                if (*(a + 1) == '[') {
                        _cleanup_free_ char *t = NULL;

                        rbracket = strchr(a + 1, ']');
                        if (!rbracket)
                                return -EINVAL;
                        t = new0(char, strlen(host));
                        if (!t)
                                return -ENOMEM;
                        strncat(t, host, a - host + 1);
                        strncat(t, a + 2, rbracket - a - 2);
                        e = bus_address_escape(t);
                        if (!e)
                                return -ENOMEM;
                } else if (*(a + 1) == '\0' || strchr(a + 1, '@'))
                        return -EINVAL;
        }

        /* Let's see if a port was given */
        m = strchr(rbracket ? rbracket + 1 : host, ':');
        if (m) {
                char *t;
                bool got_forward_slash = false;

                p = m + 1;

                t = strchr(p, '/');
                if (t) {
                        p = strndupa_safe(p, t - p);
                        got_forward_slash = true;
                }

                if (!in_charset(p, "0123456789") || *p == '\0') {
                        if (!hostname_is_valid(p, 0) || got_forward_slash)
                                return -EINVAL;

                        m = TAKE_PTR(p);
                        goto interpret_port_as_machine_old_syntax;
                }
        }

        /* Let's see if a machine was given */
        m = strchr(rbracket ? rbracket + 1 : host, '/');
        if (m) {
                m++;
interpret_port_as_machine_old_syntax:
                /* Let's make sure this is not a port of some kind,
                 * and is a valid machine name. */
                if (!in_charset(m, "0123456789") && hostname_is_valid(m, 0))
                        c = strjoina(",argv", p ? "7" : "5", "=--machine=", m);
        }

        if (!e) {
                char *t;

                t = strndupa_safe(host, strcspn(host, ":/"));

                e = bus_address_escape(t);
                if (!e)
                        return -ENOMEM;
        }

        a = strjoin("unixexec:path=ssh,argv1=-xT", p ? ",argv2=-p,argv3=" : "", strempty(p),
                                ",argv", p ? "4" : "2", "=--,argv", p ? "5" : "3", "=", e,
                                ",argv", p ? "6" : "4", "=systemd-stdio-bridge", c);
        if (!a)
                return -ENOMEM;

        return free_and_replace(b->address, a);
}

_public_ int sd_bus_open_system_remote(sd_bus **ret, const char *host) {
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(host, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = bus_set_address_system_remote(b, host);
        if (r < 0)
                return r;

        b->bus_client = true;
        b->trusted = false;
        b->runtime_scope = RUNTIME_SCOPE_SYSTEM;
        b->is_local = false;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

int bus_set_address_machine(sd_bus *b, RuntimeScope runtime_scope, const char *machine) {
        _cleanup_free_ char *a = NULL;
        const char *rhs;

        assert(b);
        assert(machine);

        rhs = strchr(machine, '@');
        if (rhs || runtime_scope == RUNTIME_SCOPE_USER) {
                _cleanup_free_ char *u = NULL, *eu = NULL, *erhs = NULL;

                /* If there's an "@" in the container specification, we'll connect as a user specified at its
                 * left hand side, which is useful in combination with user=true. This isn't as trivial as it
                 * might sound: it's not sufficient to enter the container and connect to some socket there,
                 * since the --user socket path depends on $XDG_RUNTIME_DIR which is set via PAM. Thus, to be
                 * able to connect, we need to have a PAM session. Our way out?  We use systemd-run to get
                 * into the container and acquire a PAM session there, and then invoke systemd-stdio-bridge
                 * in it, which propagates the bus transport to us. */

                if (rhs) {
                        if (rhs > machine)
                                u = strndup(machine, rhs - machine);
                        else
                                u = getusername_malloc(); /* Empty user name, let's use the local one */
                        if (!u)
                                return -ENOMEM;

                        eu = bus_address_escape(u);
                        if (!eu)
                                return -ENOMEM;

                        rhs++;
                } else {
                        /* No "@" specified but we shall connect to the user instance? Then assume root (and
                         * not a user named identically to the calling one). This means:
                         *
                         *     --machine=foobar --user    → connect to user bus of root user in container "foobar"
                         *     --machine=@foobar --user   → connect to user bus of user named like the calling user in container "foobar"
                         *
                         * Why? so that behaviour for "--machine=foobar --system" is roughly similar to
                         * "--machine=foobar --user": both times we unconditionally connect as root user
                         * regardless what the calling user is. */

                        rhs = machine;
                }

                if (!isempty(rhs)) {
                        erhs = bus_address_escape(rhs);
                        if (!erhs)
                                return -ENOMEM;
                }

                /* systemd-run -M… -PGq --wait -pUser=… -pPAMName=login systemd-stdio-bridge */

                a = strjoin("unixexec:path=systemd-run,"
                            "argv1=-M", erhs ?: ".host", ","
                            "argv2=-PGq,"
                            "argv3=--wait,"
                            "argv4=-pUser%3d", eu ?: "root", ",",
                            "argv5=-pPAMName%3dlogin,"
                            "argv6=systemd-stdio-bridge");
                if (!a)
                        return -ENOMEM;

                if (runtime_scope == RUNTIME_SCOPE_USER) {
                        /* Ideally we'd use the "--user" switch to systemd-stdio-bridge here, but it's only
                         * available in recent systemd versions. Using the "-p" switch with the explicit path
                         * is a working alternative, and is compatible with older versions, hence that's what
                         * we use here. */
                        if (!strextend(&a, ",argv7=-punix:path%3d%24%7bXDG_RUNTIME_DIR%7d/bus"))
                                return -ENOMEM;
                }
        } else {
                _cleanup_free_ char *e = NULL;

                /* Just a container name, we can go the simple way, and just join the container, and connect
                 * to the well-known path of the system bus there. */

                e = bus_address_escape(machine);
                if (!e)
                        return -ENOMEM;

                a = strjoin("x-machine-unix:machine=", e);
                if (!a)
                        return -ENOMEM;
        }

        return free_and_replace(b->address, a);
}

static int user_and_machine_valid(const char *user_and_machine) {
        const char *h;

        /* Checks if a container specification in the form "user@container" or just "container" is valid.
         *
         * If the "@" syntax is used we'll allow either the "user" or the "container" part to be omitted, but
         * not both. */

        h = strchr(user_and_machine, '@');
        if (!h)
                h = user_and_machine;
        else {
                _cleanup_free_ char *user = NULL;

                user = strndup(user_and_machine, h - user_and_machine);
                if (!user)
                        return -ENOMEM;

                if (!isempty(user) && !valid_user_group_name(user, VALID_USER_RELAX | VALID_USER_ALLOW_NUMERIC))
                        return false;

                h++;

                if (isempty(h))
                        return !isempty(user);
        }

        return hostname_is_valid(h, VALID_HOSTNAME_DOT_HOST);
}

static int user_and_machine_equivalent(const char *user_and_machine) {
        _cleanup_free_ char *un = NULL;
        const char *f;

        /* Returns true if the specified user+machine name are actually equivalent to our own identity and
         * our own host. If so we can shortcut things.  Why bother? Because that way we don't have to fork
         * off short-lived worker processes that are then unavailable for authentication and logging in the
         * peer. Moreover joining a namespace requires privileges. If we are in the right namespace anyway,
         * we can avoid permission problems thus. */

        assert(user_and_machine);

        /* Omitting the user name means that we shall use the same user name as we run as locally, which
         * means we'll end up on the same host, let's shortcut */
        if (streq(user_and_machine, "@.host"))
                return true;

        /* Otherwise, if we are root, then we can also allow the ".host" syntax, as that's the user this
         * would connect to. */
        uid_t uid = geteuid();

        if (uid == 0 && STR_IN_SET(user_and_machine, ".host", "root@.host", "0@.host"))
                return true;

        /* Otherwise, we have to figure out our user id and name, and compare things with that. */
        char buf[DECIMAL_STR_MAX(uid_t)];
        xsprintf(buf, UID_FMT, uid);

        f = startswith(user_and_machine, buf);
        if (!f) {
                un = getusername_malloc();
                if (!un)
                        return -ENOMEM;

                f = startswith(user_and_machine, un);
                if (!f)
                        return false;
        }

        return STR_IN_SET(f, "@", "@.host");
}

_public_ int sd_bus_open_system_machine(sd_bus **ret, const char *user_and_machine) {
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(user_and_machine, -EINVAL);
        assert_return(ret, -EINVAL);

        if (user_and_machine_equivalent(user_and_machine))
                return sd_bus_open_system(ret);

        r = user_and_machine_valid(user_and_machine);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = bus_set_address_machine(b, RUNTIME_SCOPE_SYSTEM, user_and_machine);
        if (r < 0)
                return r;

        b->bus_client = true;
        b->runtime_scope = RUNTIME_SCOPE_SYSTEM;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ int sd_bus_open_user_machine(sd_bus **ret, const char *user_and_machine) {
        _cleanup_(bus_freep) sd_bus *b = NULL;
        int r;

        assert_return(user_and_machine, -EINVAL);
        assert_return(ret, -EINVAL);

        /* Shortcut things if we'd end up on this host and as the same user.  */
        if (user_and_machine_equivalent(user_and_machine))
                return sd_bus_open_user(ret);

        r = user_and_machine_valid(user_and_machine);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = bus_set_address_machine(b, RUNTIME_SCOPE_USER, user_and_machine);
        if (r < 0)
                return r;

        b->bus_client = true;
        b->trusted = true;

        r = sd_bus_start(b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(b);
        return 0;
}

_public_ void sd_bus_close(sd_bus *bus) {
        if (!bus)
                return;
        if (bus->state == BUS_CLOSED)
                return;
        if (bus_origin_changed(bus))
                return;

        /* Don't leave ssh hanging around */
        bus_kill_exec(bus);

        bus_set_state(bus, BUS_CLOSED);

        sd_bus_detach_event(bus);

        /* Drop all queued messages so that they drop references to
         * the bus object and the bus may be freed */
        bus_reset_queues(bus);

        bus_close_io_fds(bus);
        bus_close_inotify_fd(bus);
}

_public_ sd_bus *sd_bus_close_unref(sd_bus *bus) {
        if (!bus)
                return NULL;
        if (bus_origin_changed(bus))
                return NULL;

        sd_bus_close(bus);

        return sd_bus_unref(bus);
}

_public_ sd_bus* sd_bus_flush_close_unref(sd_bus *bus) {
        if (!bus)
                return NULL;
        if (bus_origin_changed(bus))
                return NULL;

        /* Have to do this before flush() to prevent hang */
        bus_kill_exec(bus);
        sd_bus_flush(bus);

        return sd_bus_close_unref(bus);
}

void bus_enter_closing(sd_bus *bus) {
        assert(bus);

        if (!IN_SET(bus->state, BUS_WATCH_BIND, BUS_OPENING, BUS_AUTHENTICATING, BUS_HELLO, BUS_RUNNING))
                return;

        bus_set_state(bus, BUS_CLOSING);
}

/* Define manually so we can add the PID check */
_public_ sd_bus *sd_bus_ref(sd_bus *bus) {
        if (!bus)
                return NULL;
        if (bus_origin_changed(bus))
                return NULL;

        bus->n_ref++;

        return bus;
}

_public_ sd_bus* sd_bus_unref(sd_bus *bus) {
        if (!bus)
                return NULL;
        if (bus_origin_changed(bus))
                return NULL;

        assert(bus->n_ref > 0);
        if (--bus->n_ref > 0)
                return NULL;

        return bus_free(bus);
}

_public_ int sd_bus_is_open(sd_bus *bus) {
        if (!bus)
                return 0;

        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return BUS_IS_OPEN(bus->state);
}

_public_ int sd_bus_is_ready(sd_bus *bus) {
        if (!bus)
                return 0;

        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->state == BUS_RUNNING;
}

_public_ int sd_bus_can_send(sd_bus *bus, char type) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->is_monitor)
                return 0;

        if (type == SD_BUS_TYPE_UNIX_FD) {
                if (!bus->accept_fd)
                        return 0;

                r = bus_ensure_running(bus);
                if (r < 0)
                        return r;

                return bus->can_fds;
        }

        return bus_type_is_valid(type);
}

_public_ int sd_bus_get_bus_id(sd_bus *bus, sd_id128_t *id) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(id, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *id = bus->server_id;
        return 0;
}

#define COOKIE_CYCLED (UINT32_C(1) << 31)

static uint64_t cookie_inc(uint64_t cookie) {

        /* Stay within the 32-bit range, since classic D-Bus can't deal with more */
        if (cookie >= UINT32_MAX)
                return COOKIE_CYCLED; /* Don't go back to zero, but use the highest bit for checking
                                       * whether we are looping. */

        return cookie + 1;
}

static int next_cookie(sd_bus *b) {
        uint64_t new_cookie;

        assert(b);

        new_cookie = cookie_inc(b->cookie);

        /* Small optimization: don't bother with checking for cookie reuse until we overran cookiespace at
         * least once, but then do it thorougly. */
        if (FLAGS_SET(new_cookie, COOKIE_CYCLED)) {
                uint32_t i;

                /* Check if the cookie is currently in use. If so, pick the next one */
                for (i = 0; i < COOKIE_CYCLED; i++) {
                        if (!ordered_hashmap_contains(b->reply_callbacks, &new_cookie))
                                goto good;

                        new_cookie = cookie_inc(new_cookie);
                }

                /* Can't fulfill request */
                return -EBUSY;
        }

good:
        b->cookie = new_cookie;
        return 0;
}

static int bus_seal_message(sd_bus *b, sd_bus_message *m, usec_t timeout) {
        int r;

        assert(b);
        assert(m);

        if (m->sealed) {
                /* If we copy the same message to multiple
                 * destinations, avoid using the same cookie
                 * numbers. */
                b->cookie = MAX(b->cookie, BUS_MESSAGE_COOKIE(m));
                return 0;
        }

        if (timeout == 0) {
                r = sd_bus_get_method_call_timeout(b, &timeout);
                if (r < 0)
                        return r;
        }

        if (!m->sender && b->patch_sender) {
                r = sd_bus_message_set_sender(m, b->patch_sender);
                if (r < 0)
                        return r;
        }

        r = next_cookie(b);
        if (r < 0)
                return r;

        return sd_bus_message_seal(m, b->cookie, timeout);
}

static int bus_remarshal_message(sd_bus *b, sd_bus_message **m) {
        bool remarshal = false;

        assert(b);

        /* wrong packet version */
        if (b->message_version != 0 && b->message_version != (*m)->header->version)
                remarshal = true;

        /* wrong packet endianness */
        if (b->message_endian != 0 && b->message_endian != (*m)->header->endian)
                remarshal = true;

        return remarshal ? bus_message_remarshal(b, m) : 0;
}

int bus_seal_synthetic_message(sd_bus *b, sd_bus_message *m) {
        assert(b);
        assert(m);

        /* Fake some timestamps, if they were requested, and not
         * already initialized */
        if (b->attach_timestamp) {
                if (m->realtime <= 0)
                        m->realtime = now(CLOCK_REALTIME);

                if (m->monotonic <= 0)
                        m->monotonic = now(CLOCK_MONOTONIC);
        }

        /* The bus specification says the serial number cannot be 0,
         * hence let's fill something in for synthetic messages. Since
         * synthetic messages might have a fake sender and we don't
         * want to interfere with the real sender's serial numbers we
         * pick a fixed, artificial one. */
        return sd_bus_message_seal(m, UINT32_MAX, 0);
}

static int bus_write_message(sd_bus *bus, sd_bus_message *m, size_t *idx) {
        int r;

        assert(bus);
        assert(m);

        r = bus_socket_write_message(bus, m, idx);
        if (r <= 0)
                return r;

        if (*idx >= BUS_MESSAGE_SIZE(m))
                log_debug("Sent message type=%s sender=%s destination=%s path=%s interface=%s member=%s"
                          " cookie=%" PRIu64 " reply_cookie=%" PRIu64
                          " signature=%s error-name=%s error-message=%s",
                          bus_message_type_to_string(m->header->type),
                          strna(sd_bus_message_get_sender(m)),
                          strna(sd_bus_message_get_destination(m)),
                          strna(sd_bus_message_get_path(m)),
                          strna(sd_bus_message_get_interface(m)),
                          strna(sd_bus_message_get_member(m)),
                          BUS_MESSAGE_COOKIE(m),
                          m->reply_cookie,
                          strna(m->root_container.signature),
                          strna(m->error.name),
                          strna(m->error.message));

        return r;
}

static int dispatch_wqueue(sd_bus *bus) {
        int r, ret = 0;

        assert(bus);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        while (bus->wqueue_size > 0) {

                r = bus_write_message(bus, bus->wqueue[0], &bus->windex);
                if (r < 0)
                        return r;
                else if (r == 0)
                        /* Didn't do anything this time */
                        return ret;
                else if (bus->windex >= BUS_MESSAGE_SIZE(bus->wqueue[0])) {
                        /* Fully written. Let's drop the entry from
                         * the queue.
                         *
                         * This isn't particularly optimized, but
                         * well, this is supposed to be our worst-case
                         * buffer only, and the socket buffer is
                         * supposed to be our primary buffer, and if
                         * it got full, then all bets are off
                         * anyway. */

                        bus->wqueue_size--;
                        bus_message_unref_queued(bus->wqueue[0], bus);
                        memmove(bus->wqueue, bus->wqueue + 1, sizeof(sd_bus_message*) * bus->wqueue_size);
                        bus->windex = 0;

                        ret = 1;
                }
        }

        return ret;
}

static int bus_read_message(sd_bus *bus) {
        assert(bus);

        return bus_socket_read_message(bus);
}

int bus_rqueue_make_room(sd_bus *bus) {
        assert(bus);

        if (bus->rqueue_size >= BUS_RQUEUE_MAX)
                return -ENOBUFS;

        if (!GREEDY_REALLOC(bus->rqueue, bus->rqueue_size + 1))
                return -ENOMEM;

        return 0;
}

static void rqueue_drop_one(sd_bus *bus, size_t i) {
        assert(bus);
        assert(i < bus->rqueue_size);

        bus_message_unref_queued(bus->rqueue[i], bus);
        memmove(bus->rqueue + i, bus->rqueue + i + 1, sizeof(sd_bus_message*) * (bus->rqueue_size - i - 1));
        bus->rqueue_size--;
}

static int dispatch_rqueue(sd_bus *bus, sd_bus_message **m) {
        int r, ret = 0;

        assert(bus);
        assert(m);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        for (;;) {
                if (bus->rqueue_size > 0) {
                        /* Dispatch a queued message */
                        *m = sd_bus_message_ref(bus->rqueue[0]);
                        rqueue_drop_one(bus, 0);
                        return 1;
                }

                /* Try to read a new message */
                r = bus_read_message(bus);
                if (r < 0)
                        return r;
                if (r == 0) {
                        *m = NULL;
                        return ret;
                }

                ret = 1;
        }
}

_public_ int sd_bus_send(sd_bus *bus, sd_bus_message *_m, uint64_t *cookie) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = sd_bus_message_ref(_m);
        int r;

        assert_return(m, -EINVAL);

        if (bus)
                assert_return(bus = bus_resolve(bus), -ENOPKG);
        else
                assert_return(bus = m->bus, -ENOTCONN);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (m->n_fds > 0) {
                r = sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EOPNOTSUPP;
        }

        /* If the cookie number isn't kept, then we know that no reply
         * is expected */
        if (!cookie && !m->sealed)
                m->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;

        r = bus_seal_message(bus, m, 0);
        if (r < 0)
                return r;

        /* Remarshall if we have to. This will possibly unref the
         * message and place a replacement in m */
        r = bus_remarshal_message(bus, &m);
        if (r < 0)
                return r;

        /* If this is a reply and no reply was requested, then let's
         * suppress this, if we can */
        if (m->dont_send)
                goto finish;

        if (IN_SET(bus->state, BUS_RUNNING, BUS_HELLO) && bus->wqueue_size <= 0) {
                size_t idx = 0;

                r = bus_write_message(bus, m, &idx);
                if (ERRNO_IS_NEG_DISCONNECT(r)) {
                        bus_enter_closing(bus);
                        return -ECONNRESET;
                } else if (r < 0)
                        return r;

                if (idx < BUS_MESSAGE_SIZE(m))  {
                        /* Wasn't fully written. So let's remember how
                         * much was written. Note that the first entry
                         * of the wqueue array is always allocated so
                         * that we always can remember how much was
                         * written. */
                        bus->wqueue[0] = bus_message_ref_queued(m, bus);
                        bus->wqueue_size = 1;
                        bus->windex = idx;
                }

        } else {
                /* Just append it to the queue. */

                if (bus->wqueue_size >= BUS_WQUEUE_MAX)
                        return -ENOBUFS;

                if (!GREEDY_REALLOC(bus->wqueue, bus->wqueue_size + 1))
                        return -ENOMEM;

                bus->wqueue[bus->wqueue_size++] = bus_message_ref_queued(m, bus);
        }

finish:
        if (cookie)
                *cookie = BUS_MESSAGE_COOKIE(m);

        return 1;
}

_public_ int sd_bus_send_to(sd_bus *bus, sd_bus_message *m, const char *destination, uint64_t *cookie) {
        int r;

        assert_return(m, -EINVAL);

        if (bus)
                assert_return(bus = bus_resolve(bus), -ENOPKG);
        else
                assert_return(bus = m->bus, -ENOTCONN);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (!streq_ptr(m->destination, destination)) {

                if (!destination)
                        return -EEXIST;

                r = sd_bus_message_set_destination(m, destination);
                if (r < 0)
                        return r;
        }

        return sd_bus_send(bus, m, cookie);
}

static usec_t calc_elapse(sd_bus *bus, uint64_t usec) {
        assert(bus);

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        if (usec == USEC_INFINITY)
                return 0;

        /* We start all timeouts the instant we enter BUS_HELLO/BUS_RUNNING state, so that the don't run in parallel
         * with any connection setup states. Hence, if a method callback is started earlier than that we just store the
         * relative timestamp, and afterwards the absolute one. */

        if (IN_SET(bus->state, BUS_WATCH_BIND, BUS_OPENING, BUS_AUTHENTICATING))
                return usec;
        else
                return usec_add(now(CLOCK_MONOTONIC), usec);
}

static int timeout_compare(const void *a, const void *b) {
        const struct reply_callback *x = a, *y = b;

        if (x->timeout_usec != 0 && y->timeout_usec == 0)
                return -1;

        if (x->timeout_usec == 0 && y->timeout_usec != 0)
                return 1;

        return CMP(x->timeout_usec, y->timeout_usec);
}

_public_ int sd_bus_call_async(
                sd_bus *bus,
                sd_bus_slot **slot,
                sd_bus_message *_m,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t usec) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = sd_bus_message_ref(_m);
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *s = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(!m->sealed || (!!callback == !(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)), -EINVAL);

        if (bus)
                assert_return(bus = bus_resolve(bus), -ENOPKG);
        else
                assert_return(bus = m->bus, -ENOTCONN);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* If no callback is specified and there's no interest in a slot, then there's no reason to ask for a reply */
        if (!callback && !slot && !m->sealed)
                m->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;

        r = ordered_hashmap_ensure_allocated(&bus->reply_callbacks, &uint64_hash_ops);
        if (r < 0)
                return r;

        r = prioq_ensure_allocated(&bus->reply_callbacks_prioq, timeout_compare);
        if (r < 0)
                return r;

        r = bus_seal_message(bus, m, usec);
        if (r < 0)
                return r;

        r = bus_remarshal_message(bus, &m);
        if (r < 0)
                return r;

        if (slot || callback) {
                s = bus_slot_allocate(bus, !slot, BUS_REPLY_CALLBACK, sizeof(struct reply_callback), userdata);
                if (!s)
                        return -ENOMEM;

                s->reply_callback.callback = callback;

                s->reply_callback.cookie = BUS_MESSAGE_COOKIE(m);
                r = ordered_hashmap_put(bus->reply_callbacks, &s->reply_callback.cookie, &s->reply_callback);
                if (r < 0) {
                        s->reply_callback.cookie = 0;
                        return r;
                }

                s->reply_callback.timeout_usec = calc_elapse(bus, m->timeout);
                if (s->reply_callback.timeout_usec != 0) {
                        r = prioq_put(bus->reply_callbacks_prioq, &s->reply_callback, &s->reply_callback.prioq_idx);
                        if (r < 0) {
                                s->reply_callback.timeout_usec = 0;
                                return r;
                        }
                }
        }

        r = sd_bus_send(bus, m, s ? &s->reply_callback.cookie : NULL);
        if (r < 0)
                return r;

        if (slot)
                *slot = s;
        s = NULL;

        return r;
}

int bus_ensure_running(sd_bus *bus) {
        int r;

        assert(bus);

        if (bus->state == BUS_RUNNING)
                return 1;

        for (;;) {
                if (IN_SET(bus->state, BUS_UNSET, BUS_CLOSED, BUS_CLOSING))
                        return -ENOTCONN;

                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (bus->state == BUS_RUNNING)
                        return 1;
                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, UINT64_MAX);
                if (r < 0)
                        return r;
        }
}

_public_ int sd_bus_call(
                sd_bus *bus,
                sd_bus_message *_m,
                uint64_t usec,
                sd_bus_error *error,
                sd_bus_message **reply) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = sd_bus_message_ref(_m);
        usec_t timeout;
        uint64_t cookie;
        size_t i;
        int r;

        bus_assert_return(m, -EINVAL, error);
        bus_assert_return(m->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL, error);
        bus_assert_return(!(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED), -EINVAL, error);
        bus_assert_return(!bus_error_is_dirty(error), -EINVAL, error);

        if (bus)
                assert_return(bus = bus_resolve(bus), -ENOPKG);
        else
                assert_return(bus = m->bus, -ENOTCONN);
        bus_assert_return(!bus_origin_changed(bus), -ECHILD, error);

        if (!BUS_IS_OPEN(bus->state)) {
                r = -ENOTCONN;
                goto fail;
        }

        r = bus_ensure_running(bus);
        if (r < 0)
                goto fail;

        i = bus->rqueue_size;

        r = bus_seal_message(bus, m, usec);
        if (r < 0)
                goto fail;

        r = bus_remarshal_message(bus, &m);
        if (r < 0)
                goto fail;

        r = sd_bus_send(bus, m, &cookie);
        if (r < 0)
                goto fail;

        timeout = calc_elapse(bus, m->timeout);

        for (;;) {
                usec_t left;

                while (i < bus->rqueue_size) {
                        _cleanup_(sd_bus_message_unrefp) sd_bus_message *incoming = NULL;

                        incoming = sd_bus_message_ref(bus->rqueue[i]);

                        if (incoming->reply_cookie == cookie) {
                                /* Found a match! */

                                rqueue_drop_one(bus, i);
                                log_debug_bus_message(incoming);

                                if (incoming->header->type == SD_BUS_MESSAGE_METHOD_RETURN) {

                                        if (incoming->n_fds <= 0 || bus->accept_fd) {
                                                if (reply)
                                                        *reply = TAKE_PTR(incoming);

                                                return 1;
                                        }

                                        return sd_bus_error_set(error, SD_BUS_ERROR_INCONSISTENT_MESSAGE,
                                                                "Reply message contained file descriptors which I couldn't accept. Sorry.");

                                } else if (incoming->header->type == SD_BUS_MESSAGE_METHOD_ERROR)
                                        return sd_bus_error_copy(error, &incoming->error);
                                else {
                                        r = -EIO;
                                        goto fail;
                                }

                        } else if (BUS_MESSAGE_COOKIE(incoming) == cookie &&
                                   bus->unique_name &&
                                   incoming->sender &&
                                   streq(bus->unique_name, incoming->sender)) {

                                rqueue_drop_one(bus, i);

                                /* Our own message? Somebody is trying to send its own client a message,
                                 * let's not dead-lock, let's fail immediately. */

                                r = -ELOOP;
                                goto fail;
                        }

                        /* Try to read more, right-away */
                        i++;
                }

                r = bus_read_message(bus);
                if (r < 0) {
                        if (ERRNO_IS_DISCONNECT(r)) {
                                bus_enter_closing(bus);
                                r = -ECONNRESET;
                        }

                        goto fail;
                }
                if (r > 0)
                        continue;

                if (timeout > 0) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout) {
                                r = -ETIMEDOUT;
                                goto fail;
                        }

                        left = timeout - n;
                } else
                        left = UINT64_MAX;

                r = bus_poll(bus, true, left);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        goto fail;
                if (r == 0) {
                        r = -ETIMEDOUT;
                        goto fail;
                }

                r = dispatch_wqueue(bus);
                if (r < 0) {
                        if (ERRNO_IS_DISCONNECT(r)) {
                                bus_enter_closing(bus);
                                r = -ECONNRESET;
                        }

                        goto fail;
                }
        }

fail:
        return sd_bus_error_set_errno(error, r);
}

_public_ int sd_bus_get_fd(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(bus->input_fd == bus->output_fd, -EPERM);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->state == BUS_CLOSED)
                return -ENOTCONN;

        if (bus->inotify_fd >= 0)
                return bus->inotify_fd;

        if (bus->input_fd >= 0)
                return bus->input_fd;

        return -ENOTCONN;
}

_public_ int sd_bus_get_events(sd_bus *bus) {
        int flags = 0;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        switch (bus->state) {

        case BUS_UNSET:
        case BUS_CLOSED:
                return -ENOTCONN;

        case BUS_WATCH_BIND:
                flags |= POLLIN;
                break;

        case BUS_OPENING:
                flags |= POLLOUT;
                break;

        case BUS_AUTHENTICATING:
                if (bus_socket_auth_needs_write(bus))
                        flags |= POLLOUT;

                flags |= POLLIN;
                break;

        case BUS_RUNNING:
        case BUS_HELLO:
                if (bus->rqueue_size <= 0)
                        flags |= POLLIN;
                if (bus->wqueue_size > 0)
                        flags |= POLLOUT;
                break;

        case BUS_CLOSING:
                break;

        default:
                assert_not_reached();
        }

        return flags;
}

_public_ int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec) {
        struct reply_callback *c;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(timeout_usec, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state) && bus->state != BUS_CLOSING)
                return -ENOTCONN;

        if (bus->track_queue) {
                *timeout_usec = 0;
                return 1;
        }

        switch (bus->state) {

        case BUS_AUTHENTICATING:
                *timeout_usec = bus->auth_timeout;
                return 1;

        case BUS_RUNNING:
        case BUS_HELLO:
                if (bus->rqueue_size > 0) {
                        *timeout_usec = 0;
                        return 1;
                }

                c = prioq_peek(bus->reply_callbacks_prioq);
                if (!c) {
                        *timeout_usec = UINT64_MAX;
                        return 0;
                }

                if (c->timeout_usec == 0) {
                        *timeout_usec = UINT64_MAX;
                        return 0;
                }

                *timeout_usec = c->timeout_usec;
                return 1;

        case BUS_CLOSING:
                *timeout_usec = 0;
                return 1;

        case BUS_WATCH_BIND:
        case BUS_OPENING:
                *timeout_usec = UINT64_MAX;
                return 0;

        default:
                assert_not_reached();
        }
}

static int process_timeout(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
        struct reply_callback *c;
        sd_bus_slot *slot;
        bool is_hello;
        usec_t n;
        int r;

        assert(bus);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c)
                return 0;

        n = now(CLOCK_MONOTONIC);
        if (c->timeout_usec > n)
                return 0;

        r = bus_message_new_synthetic_error(
                        bus,
                        c->cookie,
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call timed out"),
                        &m);
        if (r < 0)
                return r;

        m->read_counter = ++bus->read_counter;

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        assert_se(prioq_pop(bus->reply_callbacks_prioq) == c);
        c->timeout_usec = 0;

        ordered_hashmap_remove(bus->reply_callbacks, &c->cookie);
        c->cookie = 0;

        slot = container_of(c, sd_bus_slot, reply_callback);

        bus->iteration_counter++;

        is_hello = bus->state == BUS_HELLO && c->callback == hello_callback;

        bus->current_message = m;
        bus->current_slot = sd_bus_slot_ref(slot);
        bus->current_handler = c->callback;
        bus->current_userdata = slot->userdata;
        r = c->callback(m, slot->userdata, &error_buffer);
        bus->current_userdata = NULL;
        bus->current_handler = NULL;
        bus->current_slot = NULL;
        bus->current_message = NULL;

        if (slot->floating)
                bus_slot_disconnect(slot, true);

        sd_bus_slot_unref(slot);

        /* When this is the hello message and it timed out, then make sure to propagate the error up, don't just log
         * and ignore the callback handler's return value. */
        if (is_hello)
                return r;

        return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_hello(sd_bus *bus, sd_bus_message *m) {
        assert(bus);
        assert(m);

        if (bus->state != BUS_HELLO)
                return 0;

        /* Let's make sure the first message on the bus is the HELLO
         * reply. But note that we don't actually parse the message
         * here (we leave that to the usual handling), we just verify
         * we don't let any earlier msg through. */

        if (!IN_SET(m->header->type, SD_BUS_MESSAGE_METHOD_RETURN, SD_BUS_MESSAGE_METHOD_ERROR))
                return -EIO;

        if (m->reply_cookie != 1)
                return -EIO;

        return 0;
}

static int process_reply(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *synthetic_reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        struct reply_callback *c;
        sd_bus_slot *slot;
        bool is_hello;
        int r;

        assert(bus);
        assert(m);

        if (!IN_SET(m->header->type, SD_BUS_MESSAGE_METHOD_RETURN, SD_BUS_MESSAGE_METHOD_ERROR))
                return 0;

        if (m->destination && bus->unique_name && !streq_ptr(m->destination, bus->unique_name))
                return 0;

        c = ordered_hashmap_remove(bus->reply_callbacks, &m->reply_cookie);
        if (!c)
                return 0;

        c->cookie = 0;

        slot = container_of(c, sd_bus_slot, reply_callback);

        if (m->n_fds > 0 && !bus->accept_fd) {

                /* If the reply contained a file descriptor which we
                 * didn't want we pass an error instead. */

                r = bus_message_new_synthetic_error(
                                bus,
                                m->reply_cookie,
                                &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Reply message contained file descriptor"),
                                &synthetic_reply);
                if (r < 0)
                        return r;

                /* Copy over original timestamp */
                synthetic_reply->realtime = m->realtime;
                synthetic_reply->monotonic = m->monotonic;
                synthetic_reply->seqnum = m->seqnum;
                synthetic_reply->read_counter = m->read_counter;

                r = bus_seal_synthetic_message(bus, synthetic_reply);
                if (r < 0)
                        return r;

                m = synthetic_reply;
        } else {
                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;
        }

        if (c->timeout_usec != 0) {
                prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
                c->timeout_usec = 0;
        }

        is_hello = bus->state == BUS_HELLO && c->callback == hello_callback;

        bus->current_slot = sd_bus_slot_ref(slot);
        bus->current_handler = c->callback;
        bus->current_userdata = slot->userdata;
        r = c->callback(m, slot->userdata, &error_buffer);
        bus->current_userdata = NULL;
        bus->current_handler = NULL;
        bus->current_slot = NULL;

        if (slot->floating)
                bus_slot_disconnect(slot, true);

        sd_bus_slot_unref(slot);

        /* When this is the hello message and it failed, then make sure to propagate the error up, don't just log and
         * ignore the callback handler's return value. */
        if (is_hello)
                return r;

        return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_filter(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(m);

        do {
                bus->filter_callbacks_modified = false;

                LIST_FOREACH(callbacks, l, bus->filter_callbacks) {
                        sd_bus_slot *slot;

                        if (bus->filter_callbacks_modified)
                                break;

                        /* Don't run this more than once per iteration */
                        if (l->last_iteration == bus->iteration_counter)
                                continue;

                        l->last_iteration = bus->iteration_counter;

                        r = sd_bus_message_rewind(m, true);
                        if (r < 0)
                                return r;

                        slot = container_of(l, sd_bus_slot, filter_callback);

                        bus->current_slot = sd_bus_slot_ref(slot);
                        bus->current_handler = l->callback;
                        bus->current_userdata = slot->userdata;
                        r = l->callback(m, slot->userdata, &error_buffer);
                        bus->current_userdata = NULL;
                        bus->current_handler = NULL;
                        bus->current_slot = sd_bus_slot_unref(slot);

                        r = bus_maybe_reply_error(m, r, &error_buffer);
                        if (r != 0)
                                return r;

                }

        } while (bus->filter_callbacks_modified);

        return 0;
}

static int process_match(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert(bus);
        assert(m);

        do {
                bus->match_callbacks_modified = false;

                r = bus_match_run(bus, &bus->match_callbacks, m);
                if (r != 0)
                        return r;

        } while (bus->match_callbacks_modified);

        return 0;
}

static int process_builtin(sd_bus *bus, sd_bus_message *m) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(m);

        if (bus->is_monitor)
                return 0;

        if (bus->manual_peer_interface)
                return 0;

        if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
                return 0;

        if (!streq_ptr(m->interface, "org.freedesktop.DBus.Peer"))
                return 0;

        if (m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 1;

        if (streq_ptr(m->member, "Ping"))
                r = sd_bus_message_new_method_return(m, &reply);
        else if (streq_ptr(m->member, "GetMachineId")) {
                sd_id128_t id;

                r = sd_id128_get_machine(&id);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_return(m, &reply);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "s", SD_ID128_TO_STRING(id));
        } else {
                r = sd_bus_message_new_method_errorf(
                                m, &reply,
                                SD_BUS_ERROR_UNKNOWN_METHOD,
                                 "Unknown method '%s' on interface '%s'.", m->member, m->interface);
        }
        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int process_fd_check(sd_bus *bus, sd_bus_message *m) {
        assert(bus);
        assert(m);

        /* If we got a message with a file descriptor which we didn't
         * want to accept, then let's drop it. How can this even
         * happen? For example, when the kernel queues a message into
         * an activatable names's queue which allows fds, and then is
         * delivered to us later even though we ourselves did not
         * negotiate it. */

        if (bus->is_monitor)
                return 0;

        if (m->n_fds <= 0)
                return 0;

        if (bus->accept_fd)
                return 0;

        if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
                return 1; /* just eat it up */

        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INCONSISTENT_MESSAGE,
                                          "Message contains file descriptors, which I cannot accept. Sorry.");
}

static int process_message(sd_bus *bus, sd_bus_message *m) {
        _unused_ _cleanup_(log_context_unrefp) LogContext *c = NULL;
        int r;

        assert(bus);
        assert(m);

        bus->current_message = m;
        bus->iteration_counter++;

        if (log_context_enabled())
                c = log_context_new_strv_consume(bus_message_make_log_fields(m));

        log_debug_bus_message(m);

        r = process_hello(bus, m);
        if (r != 0)
                goto finish;

        r = process_reply(bus, m);
        if (r != 0)
                goto finish;

        r = process_fd_check(bus, m);
        if (r != 0)
                goto finish;

        r = process_filter(bus, m);
        if (r != 0)
                goto finish;

        r = process_match(bus, m);
        if (r != 0)
                goto finish;

        r = process_builtin(bus, m);
        if (r != 0)
                goto finish;

        r = bus_process_object(bus, m);

finish:
        bus->current_message = NULL;
        return r;
}

static int dispatch_track(sd_bus *bus) {
        assert(bus);

        if (!bus->track_queue)
                return 0;

        bus_track_dispatch(bus->track_queue);
        return 1;
}

static int process_running(sd_bus *bus, sd_bus_message **ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));

        r = process_timeout(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_wqueue(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_track(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(bus, &m);
        if (r < 0)
                return r;
        if (!m)
                goto null_message;

        r = process_message(bus, m);
        if (r != 0)
                goto null_message;

        if (ret) {
                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;

                *ret = TAKE_PTR(m);
                return 1;
        }

        if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL) {

                log_debug("Unprocessed message call sender=%s object=%s interface=%s member=%s",
                          strna(sd_bus_message_get_sender(m)),
                          strna(sd_bus_message_get_path(m)),
                          strna(sd_bus_message_get_interface(m)),
                          strna(sd_bus_message_get_member(m)));

                r = sd_bus_reply_method_errorf(
                                m,
                                SD_BUS_ERROR_UNKNOWN_OBJECT,
                                "Unknown object '%s'.", m->path);
                if (r < 0)
                        return r;
        }

        return 1;

null_message:
        if (r >= 0 && ret)
                *ret = NULL;

        return r;
}

static int bus_exit_now(sd_bus *bus) {
        assert(bus);

        /* Exit due to close, if this is requested. If this is bus object is attached to an event source, invokes
         * sd_event_exit(), otherwise invokes libc exit(). */

        if (bus->exited) /* did we already exit? */
                return 0;
        if (!bus->exit_triggered) /* was the exit condition triggered? */
                return 0;
        if (!bus->exit_on_disconnect) /* Shall we actually exit on disconnection? */
                return 0;

        bus->exited = true; /* never exit more than once */

        log_debug("Bus connection disconnected, exiting.");

        if (bus->event)
                return sd_event_exit(bus->event, EXIT_FAILURE);
        else
                exit(EXIT_FAILURE);

        assert_not_reached();
}

static int process_closing_reply_callback(sd_bus *bus, struct reply_callback *c) {
        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        sd_bus_slot *slot;
        int r;

        assert(bus);
        assert(c);

        r = bus_message_new_synthetic_error(
                        bus,
                        c->cookie,
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Connection terminated"),
                        &m);
        if (r < 0)
                return r;

        m->read_counter = ++bus->read_counter;

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        if (c->timeout_usec != 0) {
                prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
                c->timeout_usec = 0;
        }

        ordered_hashmap_remove(bus->reply_callbacks, &c->cookie);
        c->cookie = 0;

        slot = container_of(c, sd_bus_slot, reply_callback);

        bus->iteration_counter++;

        bus->current_message = m;
        bus->current_slot = sd_bus_slot_ref(slot);
        bus->current_handler = c->callback;
        bus->current_userdata = slot->userdata;
        r = c->callback(m, slot->userdata, &error_buffer);
        bus->current_userdata = NULL;
        bus->current_handler = NULL;
        bus->current_slot = NULL;
        bus->current_message = NULL;

        if (slot->floating)
                bus_slot_disconnect(slot, true);

        sd_bus_slot_unref(slot);

        return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_closing(sd_bus *bus, sd_bus_message **ret) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        struct reply_callback *c;
        int r;

        assert(bus);
        assert(bus->state == BUS_CLOSING);

        /* First, fail all outstanding method calls */
        c = ordered_hashmap_first(bus->reply_callbacks);
        if (c)
                return process_closing_reply_callback(bus, c);

        /* Then, fake-drop all remaining bus tracking references */
        if (bus->tracks) {
                bus_track_close(bus->tracks);
                return 1;
        }

        /* Then, synthesize a Disconnected message */
        r = sd_bus_message_new_signal(
                        bus,
                        &m,
                        "/org/freedesktop/DBus/Local",
                        "org.freedesktop.DBus.Local",
                        "Disconnected");
        if (r < 0)
                return r;

        bus_message_set_sender_local(bus, m);
        m->read_counter = ++bus->read_counter;

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        sd_bus_close(bus);

        bus->current_message = m;
        bus->iteration_counter++;

        r = process_filter(bus, m);
        if (r != 0)
                goto finish;

        r = process_match(bus, m);
        if (r != 0)
                goto finish;

        /* Nothing else to do, exit now, if the condition holds */
        bus->exit_triggered = true;
        (void) bus_exit_now(bus);

        if (ret)
                *ret = TAKE_PTR(m);

        r = 1;

finish:
        bus->current_message = NULL;

        return r;
}

static int bus_process_internal(sd_bus *bus, sd_bus_message **ret) {
        int r;

        /* Returns 0 when we didn't do anything. This should cause the
         * caller to invoke sd_bus_wait() before returning the next
         * time. Returns > 0 when we did something, which possibly
         * means *ret is filled in with an unprocessed message. */

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        /* We don't allow recursively invoking sd_bus_process(). */
        assert_return(!bus->current_message, -EBUSY);
        assert(!bus->current_slot); /* This should be NULL whenever bus->current_message is */

        BUS_DONT_DESTROY(bus);

        switch (bus->state) {

        case BUS_UNSET:
                return -ENOTCONN;

        case BUS_CLOSED:
                return -ECONNRESET;

        case BUS_WATCH_BIND:
                r = bus_socket_process_watch_bind(bus);
                break;

        case BUS_OPENING:
                r = bus_socket_process_opening(bus);
                break;

        case BUS_AUTHENTICATING:
                r = bus_socket_process_authenticating(bus);
                break;

        case BUS_RUNNING:
        case BUS_HELLO:
                r = process_running(bus, ret);
                if (r >= 0)
                        return r;

                /* This branch initializes *ret, hence we don't use the generic error checking below */
                break;

        case BUS_CLOSING:
                return process_closing(bus, ret);

        default:
                assert_not_reached();
        }

        if (ERRNO_IS_NEG_DISCONNECT(r)) {
                bus_enter_closing(bus);
                r = 1;
        } else if (r < 0)
                return r;

        if (ret)
                *ret = NULL;

        return r;
}

_public_ int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
        return bus_process_internal(bus, ret);
}

_public_ int sd_bus_process_priority(sd_bus *bus, int64_t priority, sd_bus_message **ret) {
        return bus_process_internal(bus, ret);
}

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec) {
        struct pollfd p[2] = {};
        usec_t m = USEC_INFINITY;
        int r, n;

        assert(bus);

        if (bus->state == BUS_CLOSING)
                return 1;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->state == BUS_WATCH_BIND) {
                assert(bus->inotify_fd >= 0);

                p[0].events = POLLIN;
                p[0].fd = bus->inotify_fd;
                n = 1;
        } else {
                int e;

                e = sd_bus_get_events(bus);
                if (e < 0)
                        return e;

                if (need_more)
                        /* The caller really needs some more data, they don't
                         * care about what's already read, or any timeouts
                         * except its own. */
                        e |= POLLIN;
                else {
                        usec_t until;
                        /* The caller wants to process if there's something to
                         * process, but doesn't care otherwise */

                        r = sd_bus_get_timeout(bus, &until);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                m = usec_sub_unsigned(until, now(CLOCK_MONOTONIC));
                }

                p[0].fd = bus->input_fd;
                if (bus->output_fd == bus->input_fd) {
                        p[0].events = e;
                        n = 1;
                } else {
                        p[0].events = e & POLLIN;
                        p[1].fd = bus->output_fd;
                        p[1].events = e & POLLOUT;
                        n = 2;
                }
        }

        if (timeout_usec != UINT64_MAX && (m == USEC_INFINITY || timeout_usec < m))
                m = timeout_usec;

        r = ppoll_usec(p, n, m);
        if (r <= 0)
                return r;

        return 1;
}

_public_ int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->state == BUS_CLOSING)
                return 0;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->rqueue_size > 0)
                return 0;

        r = bus_poll(bus, false, timeout_usec);
        if (ERRNO_IS_NEG_TRANSIENT(r))
                return 1; /* treat EINTR as success, but let's exit, so that the caller will call back into us soon. */

        return r;
}

_public_ int sd_bus_flush(sd_bus *bus) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->state == BUS_CLOSING)
                return 0;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* We never were connected? Don't hang in inotify for good, as there's no timeout set for it */
        if (bus->state == BUS_WATCH_BIND)
                return -EUNATCH;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        if (bus->wqueue_size <= 0)
                return 0;

        for (;;) {
                r = dispatch_wqueue(bus);
                if (ERRNO_IS_NEG_DISCONNECT(r)) {
                        bus_enter_closing(bus);
                        return -ECONNRESET;
                } else if (r < 0)
                        return r;

                if (bus->wqueue_size <= 0)
                        return 0;

                r = bus_poll(bus, false, UINT64_MAX);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return r;
        }
}

_public_ int sd_bus_add_filter(
                sd_bus *bus,
                sd_bus_slot **slot,
                sd_bus_message_handler_t callback,
                void *userdata) {

        sd_bus_slot *s;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(callback, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        s = bus_slot_allocate(bus, !slot, BUS_FILTER_CALLBACK, sizeof(struct filter_callback), userdata);
        if (!s)
                return -ENOMEM;

        s->filter_callback.callback = callback;

        bus->filter_callbacks_modified = true;
        LIST_PREPEND(callbacks, bus->filter_callbacks, &s->filter_callback);

        if (slot)
                *slot = s;

        return 0;
}

static int add_match_callback(
                sd_bus_message *m,
                void *userdata,
                sd_bus_error *ret_error) {

        sd_bus_slot *match_slot = ASSERT_PTR(userdata);
        bool failed = false;
        int r;

        assert(m);

        sd_bus_slot_ref(match_slot);

        if (sd_bus_message_is_method_error(m, NULL)) {
                log_debug_errno(sd_bus_message_get_errno(m),
                                "Unable to add match %s, failing connection: %s",
                                match_slot->match_callback.match_string,
                                sd_bus_message_get_error(m)->message);

                failed = true;
        } else
                log_debug("Match %s successfully installed.", match_slot->match_callback.match_string);

        if (match_slot->match_callback.install_callback) {
                sd_bus *bus;

                bus = sd_bus_message_get_bus(m);

                /* This function has been called as slot handler, and we want to call another slot handler. Let's
                 * update the slot callback metadata temporarily with our own data, and then revert back to the old
                 * values. */

                assert(bus->current_slot == match_slot->match_callback.install_slot);
                assert(bus->current_handler == add_match_callback);
                assert(bus->current_userdata == userdata);

                bus->current_slot = match_slot;
                bus->current_handler = match_slot->match_callback.install_callback;
                bus->current_userdata = match_slot->userdata;

                r = match_slot->match_callback.install_callback(m, match_slot->userdata, ret_error);

                bus->current_slot = match_slot->match_callback.install_slot;
                bus->current_handler = add_match_callback;
                bus->current_userdata = userdata;
        } else {
                if (failed) /* Generic failure handling: destroy the connection */
                        bus_enter_closing(sd_bus_message_get_bus(m));

                r = 1;
        }

        /* We don't need the install method reply slot anymore, let's free it */
        match_slot->match_callback.install_slot = sd_bus_slot_unref(match_slot->match_callback.install_slot);

        if (failed && match_slot->floating)
                bus_slot_disconnect(match_slot, true);

        sd_bus_slot_unref(match_slot);

        return r;
}

int bus_add_match_full(
                sd_bus *bus,
                sd_bus_slot **slot,
                bool asynchronous,
                const char *match,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata,
                uint64_t timeout_usec) {

        struct bus_match_component *components = NULL;
        size_t n_components = 0;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *s = NULL;
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(match, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        CLEANUP_ARRAY(components, n_components, bus_match_parse_free);

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                return r;

        s = bus_slot_allocate(bus, !slot, BUS_MATCH_CALLBACK, sizeof(struct match_callback), userdata);
        if (!s)
                return -ENOMEM;

        s->match_callback.callback = callback;
        s->match_callback.install_callback = install_callback;

        if (bus->bus_client) {
                enum bus_match_scope scope;

                scope = bus_match_get_scope(components, n_components);

                /* Do not install server-side matches for matches against the local service, interface or bus path. */
                if (scope != BUS_MATCH_LOCAL) {

                        /* We store the original match string, so that we can use it to remove the match again. */

                        s->match_callback.match_string = strdup(match);
                        if (!s->match_callback.match_string)
                                return -ENOMEM;

                        if (asynchronous) {
                                r = bus_add_match_internal_async(bus,
                                                                 &s->match_callback.install_slot,
                                                                 s->match_callback.match_string,
                                                                 add_match_callback,
                                                                 s,
                                                                 timeout_usec);

                                if (r < 0)
                                        return r;

                                /* Make the slot of the match call floating now. We need the reference, but we don't
                                 * want that this match pins the bus object, hence we first create it non-floating, but
                                 * then make it floating. */
                                r = sd_bus_slot_set_floating(s->match_callback.install_slot, true);
                        } else
                                r = bus_add_match_internal(bus,
                                                s->match_callback.match_string,
                                                timeout_usec,
                                                &s->match_callback.after);
                        if (r < 0)
                                return r;

                        s->match_added = true;
                }
        }

        bus->match_callbacks_modified = true;
        r = bus_match_add(&bus->match_callbacks, components, n_components, &s->match_callback);
        if (r < 0)
                return r;

        if (slot)
                *slot = s;
        s = NULL;

        return 0;
}

_public_ int sd_bus_add_match(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *match,
                sd_bus_message_handler_t callback,
                void *userdata) {

        return bus_add_match_full(bus, slot, false, match, callback, NULL, userdata, 0);
}

_public_ int sd_bus_add_match_async(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *match,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata) {

        return bus_add_match_full(bus, slot, true, match, callback, install_callback, userdata, 0);
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        /* Note that this is called both on input_fd, output_fd as well as inotify_fd events */

        r = sd_bus_process(bus, NULL);
        if (r < 0) {
                log_debug_errno(r, "Processing of bus failed, closing down: %m");
                bus_enter_closing(bus);
        }

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r;

        r = sd_bus_process(bus, NULL);
        if (r < 0) {
                log_debug_errno(r, "Processing of bus failed, closing down: %m");
                bus_enter_closing(bus);
        }

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_bus *bus = ASSERT_PTR(userdata);
        int r, e;
        usec_t until;

        assert(s);

        e = sd_bus_get_events(bus);
        if (e < 0) {
                r = e;
                goto fail;
        }

        if (bus->output_fd != bus->input_fd) {

                r = sd_event_source_set_io_events(bus->input_io_event_source, e & POLLIN);
                if (r < 0)
                        goto fail;

                r = sd_event_source_set_io_events(bus->output_io_event_source, e & POLLOUT);
        } else
                r = sd_event_source_set_io_events(bus->input_io_event_source, e);
        if (r < 0)
                goto fail;

        r = sd_bus_get_timeout(bus, &until);
        if (r < 0)
                goto fail;
        if (r > 0) {
                int j;

                j = sd_event_source_set_time(bus->time_event_source, until);
                if (j < 0) {
                        r = j;
                        goto fail;
                }
        }

        r = sd_event_source_set_enabled(bus->time_event_source, r > 0 ? SD_EVENT_ONESHOT : SD_EVENT_OFF);
        if (r < 0)
                goto fail;

        return 1;

fail:
        log_debug_errno(r, "Preparing of bus events failed, closing down: %m");
        bus_enter_closing(bus);

        return 1;
}

static int quit_callback(sd_event_source *event, void *userdata) {
        sd_bus *bus = userdata;

        assert(event);

        if (bus->close_on_exit) {
                sd_bus_flush(bus);
                sd_bus_close(bus);
        }

        return 1;
}

int bus_attach_io_events(sd_bus *bus) {
        int r;

        assert(bus);

        if (bus->input_fd < 0)
                return 0;

        if (!bus->event)
                return 0;

        if (!bus->input_io_event_source) {
                r = sd_event_add_io(bus->event, &bus->input_io_event_source, bus->input_fd, 0, io_callback, bus);
                if (r < 0)
                        return r;

                r = sd_event_source_set_prepare(bus->input_io_event_source, prepare_callback);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(bus->input_io_event_source, bus->event_priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_description(bus->input_io_event_source, "bus-input");
        } else
                r = sd_event_source_set_io_fd(bus->input_io_event_source, bus->input_fd);

        if (r < 0)
                return r;

        if (bus->output_fd != bus->input_fd) {
                assert(bus->output_fd >= 0);

                if (!bus->output_io_event_source) {
                        r = sd_event_add_io(bus->event, &bus->output_io_event_source, bus->output_fd, 0, io_callback, bus);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_priority(bus->output_io_event_source, bus->event_priority);
                        if (r < 0)
                                return r;

                        r = sd_event_source_set_description(bus->input_io_event_source, "bus-output");
                } else
                        r = sd_event_source_set_io_fd(bus->output_io_event_source, bus->output_fd);

                if (r < 0)
                        return r;
        }

        return 0;
}

static void bus_detach_io_events(sd_bus *bus) {
        assert(bus);

        bus->input_io_event_source = sd_event_source_disable_unref(bus->input_io_event_source);
        bus->output_io_event_source = sd_event_source_disable_unref(bus->output_io_event_source);
}

int bus_attach_inotify_event(sd_bus *bus) {
        int r;

        assert(bus);

        if (bus->inotify_fd < 0)
                return 0;

        if (!bus->event)
                return 0;

        if (!bus->inotify_event_source) {
                r = sd_event_add_io(bus->event, &bus->inotify_event_source, bus->inotify_fd, EPOLLIN, io_callback, bus);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(bus->inotify_event_source, bus->event_priority);
                if (r < 0)
                        return r;

                r = sd_event_source_set_description(bus->inotify_event_source, "bus-inotify");
        } else
                r = sd_event_source_set_io_fd(bus->inotify_event_source, bus->inotify_fd);
        if (r < 0)
                return r;

        return 0;
}

_public_ int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus->event, -EBUSY);

        assert(!bus->input_io_event_source);
        assert(!bus->output_io_event_source);
        assert(!bus->time_event_source);

        if (event)
                bus->event = sd_event_ref(event);
        else  {
                r = sd_event_default(&bus->event);
                if (r < 0)
                        return r;
        }

        bus->event_priority = priority;

        r = sd_event_add_time(bus->event, &bus->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, bus);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(bus->time_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(bus->time_event_source, "bus-time");
        if (r < 0)
                goto fail;

        r = sd_event_add_exit(bus->event, &bus->quit_event_source, quit_callback, bus);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_description(bus->quit_event_source, "bus-exit");
        if (r < 0)
                goto fail;

        r = bus_attach_io_events(bus);
        if (r < 0)
                goto fail;

        r = bus_attach_inotify_event(bus);
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_bus_detach_event(bus);
        return r;
}

_public_ int sd_bus_detach_event(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        if (!bus->event)
                return 0;

        bus_detach_io_events(bus);
        bus->inotify_event_source = sd_event_source_disable_unref(bus->inotify_event_source);
        bus->time_event_source = sd_event_source_disable_unref(bus->time_event_source);
        bus->quit_event_source = sd_event_source_disable_unref(bus->quit_event_source);

        bus->event = sd_event_unref(bus->event);
        return 1;
}

_public_ sd_event* sd_bus_get_event(sd_bus *bus) {
        assert_return(bus = bus_resolve(bus), NULL);

        return bus->event;
}

_public_ sd_bus_message* sd_bus_get_current_message(sd_bus *bus) {
        assert_return(bus = bus_resolve(bus), NULL);

        return bus->current_message;
}

_public_ sd_bus_slot* sd_bus_get_current_slot(sd_bus *bus) {
        assert_return(bus = bus_resolve(bus), NULL);

        return bus->current_slot;
}

_public_ sd_bus_message_handler_t sd_bus_get_current_handler(sd_bus *bus) {
        assert_return(bus = bus_resolve(bus), NULL);

        return bus->current_handler;
}

_public_ void* sd_bus_get_current_userdata(sd_bus *bus) {
        assert_return(bus = bus_resolve(bus), NULL);

        return bus->current_userdata;
}

static int bus_default(int (*bus_open)(sd_bus **), sd_bus **default_bus, sd_bus **ret) {
        sd_bus *b = NULL;
        int r;

        assert(bus_open);
        assert(default_bus);

        if (!ret)
                return !!*default_bus;

        if (*default_bus) {
                *ret = sd_bus_ref(*default_bus);
                return 0;
        }

        r = bus_open(&b);
        if (r < 0)
                return r;

        b->default_bus_ptr = default_bus;
        b->tid = gettid();
        *default_bus = b;

        *ret = b;
        return 1;
}

_public_ int sd_bus_default_system(sd_bus **ret) {
        return bus_default(sd_bus_open_system, &default_system_bus, ret);
}

_public_ int sd_bus_default_user(sd_bus **ret) {
        return bus_default(sd_bus_open_user, &default_user_bus, ret);
}

_public_ int sd_bus_default(sd_bus **ret) {
        int (*bus_open)(sd_bus **) = NULL;
        sd_bus **busp;

        busp = bus_choose_default(&bus_open);
        return bus_default(bus_open, busp, ret);
}

_public_ int sd_bus_get_tid(sd_bus *b, pid_t *tid) {
        assert_return(b, -EINVAL);
        assert_return(tid, -EINVAL);
        assert_return(!bus_origin_changed(b), -ECHILD);

        if (b->tid != 0) {
                *tid = b->tid;
                return 0;
        }

        if (b->event)
                return sd_event_get_tid(b->event, tid);

        return -ENXIO;
}

_public_ int sd_bus_path_encode(const char *prefix, const char *external_id, char **ret_path) {
        _cleanup_free_ char *e = NULL;
        char *ret;

        assert_return(object_path_is_valid(prefix), -EINVAL);
        assert_return(external_id, -EINVAL);
        assert_return(ret_path, -EINVAL);

        e = bus_label_escape(external_id);
        if (!e)
                return -ENOMEM;

        ret = path_join(prefix, e);
        if (!ret)
                return -ENOMEM;

        *ret_path = ret;
        return 0;
}

_public_ int sd_bus_path_decode(const char *path, const char *prefix, char **external_id) {
        const char *e;
        char *ret;

        assert_return(object_path_is_valid(path), -EINVAL);
        assert_return(object_path_is_valid(prefix), -EINVAL);
        assert_return(external_id, -EINVAL);

        e = object_path_startswith(path, prefix);
        if (!e) {
                *external_id = NULL;
                return 0;
        }

        /* Note that 'e' might be an empty string here. That's expected. E.g. a case where the subtree
         * corresponds to a subtree on a disk, and we want to return something that represents the root
         * of the filesystem. */

        ret = bus_label_unescape(e);
        if (!ret)
                return -ENOMEM;

        *external_id = ret;
        return 1;
}

_public_ int sd_bus_path_encode_many(char **out, const char *path_template, ...) {
        _cleanup_strv_free_ char **labels = NULL;
        char *path, *path_pos, **label_pos;
        const char *sep, *template_pos;
        size_t path_length;
        va_list list;
        int r;

        assert_return(out, -EINVAL);
        assert_return(path_template, -EINVAL);

        path_length = strlen(path_template);

        va_start(list, path_template);
        for (sep = strchr(path_template, '%'); sep; sep = strchr(sep + 1, '%')) {
                const char *arg;
                char *label;

                arg = va_arg(list, const char *);
                if (!arg) {
                        va_end(list);
                        return -EINVAL;
                }

                label = bus_label_escape(arg);
                if (!label) {
                        va_end(list);
                        return -ENOMEM;
                }

                r = strv_consume(&labels, label);
                if (r < 0) {
                        va_end(list);
                        return r;
                }

                /* add label length, but account for the format character */
                path_length += strlen(label) - 1;
        }
        va_end(list);

        path = malloc(path_length + 1);
        if (!path)
                return -ENOMEM;

        path_pos = path;
        label_pos = labels;

        for (template_pos = path_template; *template_pos; ) {
                sep = strchrnul(template_pos, '%');
                path_pos = mempcpy(path_pos, template_pos, sep - template_pos);
                if (!*sep)
                        break;

                path_pos = stpcpy(path_pos, *label_pos++);
                template_pos = sep + 1;
        }

        *path_pos = 0;
        *out = path;
        return 0;
}

_public_ int sd_bus_path_decode_many(const char *path, const char *path_template, ...) {
        _cleanup_strv_free_ char **labels = NULL;
        const char *template_pos, *path_pos;
        char **label_pos;
        va_list list;
        int r;

        /*
         * This decodes an object-path based on a template argument. The
         * template consists of a verbatim path, optionally including special
         * directives:
         *
         *   - Each occurrence of '%' in the template matches an arbitrary
         *     substring of a label in the given path. At most one such
         *     directive is allowed per label. For each such directive, the
         *     caller must provide an output parameter (char **) via va_arg. If
         *     NULL is passed, the given label is verified, but not returned.
         *     For each matched label, the *decoded* label is stored in the
         *     passed output argument, and the caller is responsible to free
         *     it. Note that the output arguments are only modified if the
         *     actually path matched the template. Otherwise, they're left
         *     untouched.
         *
         * This function returns <0 on error, 0 if the path does not match the
         * template, 1 if it matched.
         */

        assert_return(path, -EINVAL);
        assert_return(path_template, -EINVAL);

        path_pos = path;

        for (template_pos = path_template; *template_pos; ) {
                const char *sep;
                size_t length;
                char *label;

                /* verify everything until the next '%' matches verbatim */
                sep = strchrnul(template_pos, '%');
                length = sep - template_pos;
                if (strncmp(path_pos, template_pos, length))
                        return 0;

                path_pos += length;
                template_pos += length;

                if (!*template_pos)
                        break;

                /* We found the next '%' character. Everything up until here
                 * matched. We now skip ahead to the end of this label and make
                 * sure it matches the tail of the label in the path. Then we
                 * decode the string in-between and save it for later use. */

                ++template_pos; /* skip over '%' */

                sep = strchrnul(template_pos, '/');
                length = sep - template_pos; /* length of suffix to match verbatim */

                /* verify the suffixes match */
                sep = strchrnul(path_pos, '/');
                if (sep - path_pos < (ssize_t)length ||
                    strncmp(sep - length, template_pos, length))
                        return 0;

                template_pos += length; /* skip over matched label */
                length = sep - path_pos - length; /* length of sub-label to decode */

                /* store unescaped label for later use */
                label = bus_label_unescape_n(path_pos, length);
                if (!label)
                        return -ENOMEM;

                r = strv_consume(&labels, label);
                if (r < 0)
                        return r;

                path_pos = sep; /* skip decoded label and suffix */
        }

        /* end of template must match end of path */
        if (*path_pos)
                return 0;

        /* copy the labels over to the caller */
        va_start(list, path_template);
        for (label_pos = labels; label_pos && *label_pos; ++label_pos) {
                char **arg;

                arg = va_arg(list, char **);
                if (arg)
                        *arg = *label_pos;
                else
                        free(*label_pos);
        }
        va_end(list);

        labels = mfree(labels);
        return 1;
}

_public_ int sd_bus_try_close(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return -EOPNOTSUPP;
}

_public_ int sd_bus_get_description(sd_bus *bus, const char **description) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(description, -EINVAL);

        const char *d = bus->description;
        if (!d)
                d = runtime_scope_to_string(bus->runtime_scope);
        if (!d)
                return -ENXIO;

        *description = d;
        return 0;
}

_public_ int sd_bus_get_scope(sd_bus *bus, const char **scope) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(scope, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->runtime_scope < 0)
                return -ENODATA;

        *scope = runtime_scope_to_string(bus->runtime_scope);
        return 0;
}

_public_ int sd_bus_get_address(sd_bus *bus, const char **address) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(address, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (bus->address) {
                *address = bus->address;
                return 0;
        }

        return -ENODATA;
}

_public_ int sd_bus_get_creds_mask(sd_bus *bus, uint64_t *mask) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(mask, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        *mask = bus->creds_mask;
        return 0;
}

_public_ int sd_bus_is_bus_client(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->bus_client;
}

_public_ int sd_bus_is_server(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->is_server;
}

_public_ int sd_bus_is_anonymous(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->anonymous_auth;
}

_public_ int sd_bus_is_trusted(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->trusted;
}

_public_ int sd_bus_is_monitor(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        return bus->is_monitor;
}

static void flush_close(sd_bus *bus) {
        if (!bus)
                return;

        /* Flushes and closes the specified bus. We take a ref before,
         * to ensure the flushing does not cause the bus to be
         * unreferenced. */

        sd_bus_flush_close_unref(sd_bus_ref(bus));
}

_public_ void sd_bus_default_flush_close(void) {
        flush_close(default_starter_bus);
        flush_close(default_user_bus);
        flush_close(default_system_bus);
}

_public_ int sd_bus_set_exit_on_disconnect(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        /* Turns on exit-on-disconnect, and triggers it immediately if the bus connection was already
         * disconnected. Note that this is triggered exclusively on disconnections triggered by the server side, never
         * from the client side. */
        bus->exit_on_disconnect = b;

        /* If the exit condition was triggered already, exit immediately. */
        return bus_exit_now(bus);
}

_public_ int sd_bus_get_exit_on_disconnect(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        return bus->exit_on_disconnect;
}

_public_ int sd_bus_set_sender(sd_bus *bus, const char *sender) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus->bus_client, -EPERM);
        assert_return(!sender || service_name_is_valid(sender), -EINVAL);

        return free_and_strdup(&bus->patch_sender, sender);
}

_public_ int sd_bus_get_sender(sd_bus *bus, const char **ret) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(ret, -EINVAL);

        if (!bus->patch_sender)
                return -ENODATA;

        *ret = bus->patch_sender;
        return 0;
}

_public_ int sd_bus_get_n_queued_read(sd_bus *bus, uint64_t *ret) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);
        assert_return(ret, -EINVAL);

        *ret = bus->rqueue_size;
        return 0;
}

_public_ int sd_bus_get_n_queued_write(sd_bus *bus, uint64_t *ret) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(!bus_origin_changed(bus), -ECHILD);
        assert_return(ret, -EINVAL);

        *ret = bus->wqueue_size;
        return 0;
}

_public_ int sd_bus_set_method_call_timeout(sd_bus *bus, uint64_t usec) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        bus->method_call_timeout = usec;
        return 0;
}

_public_ int sd_bus_get_method_call_timeout(sd_bus *bus, uint64_t *ret) {
        const char *e;
        usec_t usec;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(ret, -EINVAL);

        if (bus->method_call_timeout != 0) {
                *ret = bus->method_call_timeout;
                return 0;
        }

        e = secure_getenv("SYSTEMD_BUS_TIMEOUT");
        if (e && parse_sec(e, &usec) >= 0 && usec != 0) {
                /* Save the parsed value to avoid multiple parsing. To change the timeout value,
                 * use sd_bus_set_method_call_timeout() instead of setenv(). */
                *ret = bus->method_call_timeout = usec;
                return 0;
        }

        *ret = bus->method_call_timeout = BUS_DEFAULT_TIMEOUT;
        return 0;
}

_public_ int sd_bus_set_close_on_exit(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        bus->close_on_exit = b;
        return 0;
}

_public_ int sd_bus_get_close_on_exit(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);

        return bus->close_on_exit;
}

_public_ int sd_bus_enqueue_for_read(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus = bus_resolve(bus), -ENOPKG);
        assert_return(m, -EINVAL);
        assert_return(m->sealed, -EINVAL);
        assert_return(!bus_origin_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        /* Re-enqueue a message for reading. This is primarily useful for PolicyKit-style authentication,
         * where we accept a message, then determine we need to interactively authenticate the user, and then
         * we want to process the message again. */

        r = bus_rqueue_make_room(bus);
        if (r < 0)
                return r;

        bus->rqueue[bus->rqueue_size++] = bus_message_ref_queued(m, bus);
        return 0;
}
