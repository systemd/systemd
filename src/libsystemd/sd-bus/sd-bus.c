/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <endian.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <poll.h>
#include <sys/mman.h>
#include <pthread.h>

#include "util.h"
#include "macro.h"
#include "strv.h"
#include "missing.h"
#include "def.h"
#include "cgroup-util.h"
#include "hostname-util.h"
#include "bus-label.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-type.h"
#include "bus-socket.h"
#include "bus-kernel.h"
#include "bus-control.h"
#include "bus-objects.h"
#include "bus-util.h"
#include "bus-container.h"
#include "bus-protocol.h"
#include "bus-track.h"
#include "bus-slot.h"

#define log_debug_bus_message(m)                                         \
        do {                                                             \
                sd_bus_message *_mm = (m);                               \
                log_debug("Got message type=%s sender=%s destination=%s object=%s interface=%s member=%s cookie=%" PRIu64 " reply_cookie=%" PRIu64 " error=%s", \
                          bus_message_type_to_string(_mm->header->type), \
                          strna(sd_bus_message_get_sender(_mm)),         \
                          strna(sd_bus_message_get_destination(_mm)),    \
                          strna(sd_bus_message_get_path(_mm)),           \
                          strna(sd_bus_message_get_interface(_mm)),      \
                          strna(sd_bus_message_get_member(_mm)),         \
                          BUS_MESSAGE_COOKIE(_mm),                       \
                          _mm->reply_cookie,                             \
                          strna(_mm->error.message));                    \
        } while (false)

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec);
static int attach_io_events(sd_bus *b);
static void detach_io_events(sd_bus *b);

static void bus_close_fds(sd_bus *b) {
        assert(b);

        detach_io_events(b);

        if (b->input_fd != b->output_fd)
                safe_close(b->output_fd);
        b->output_fd = b->input_fd = safe_close(b->input_fd);
}

static void bus_reset_queues(sd_bus *b) {
        assert(b);

        while (b->rqueue_size > 0)
                sd_bus_message_unref(b->rqueue[--b->rqueue_size]);

        b->rqueue = mfree(b->rqueue);
        b->rqueue_allocated = 0;

        while (b->wqueue_size > 0)
                sd_bus_message_unref(b->wqueue[--b->wqueue_size]);

        b->wqueue = mfree(b->wqueue);
        b->wqueue_allocated = 0;
}

static void bus_free(sd_bus *b) {
        sd_bus_slot *s;

        assert(b);
        assert(!b->track_queue);

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
                bus_slot_disconnect(s);
                sd_bus_slot_unref(s);
        }

        if (b->default_bus_ptr)
                *b->default_bus_ptr = NULL;

        bus_close_fds(b);

        if (b->kdbus_buffer)
                munmap(b->kdbus_buffer, KDBUS_POOL_SIZE);

        free(b->label);
        free(b->rbuffer);
        free(b->unique_name);
        free(b->auth_buffer);
        free(b->address);
        free(b->kernel);
        free(b->machine);
        free(b->fake_label);
        free(b->cgroup_root);
        free(b->description);

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

        bus_kernel_flush_memfd(b);

        assert_se(pthread_mutex_destroy(&b->memfd_cache_mutex) == 0);

        free(b);
}

_public_ int sd_bus_new(sd_bus **ret) {
        sd_bus *r;

        assert_return(ret, -EINVAL);

        r = new0(sd_bus, 1);
        if (!r)
                return -ENOMEM;

        r->n_ref = REFCNT_INIT;
        r->input_fd = r->output_fd = -1;
        r->message_version = 1;
        r->creds_mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME;
        r->hello_flags |= KDBUS_HELLO_ACCEPT_FD;
        r->attach_flags |= KDBUS_ATTACH_NAMES;
        r->original_pid = getpid();

        assert_se(pthread_mutex_init(&r->memfd_cache_mutex, NULL) == 0);

        /* We guarantee that wqueue always has space for at least one
         * entry */
        if (!GREEDY_REALLOC(r->wqueue, r->wqueue_allocated, 1)) {
                free(r);
                return -ENOMEM;
        }

        *ret = r;
        return 0;
}

_public_ int sd_bus_set_address(sd_bus *bus, const char *address) {
        char *a;

        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(address, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        a = strdup(address);
        if (!a)
                return -ENOMEM;

        free(bus->address);
        bus->address = a;

        return 0;
}

_public_ int sd_bus_set_fd(sd_bus *bus, int input_fd, int output_fd) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(input_fd >= 0, -EBADF);
        assert_return(output_fd >= 0, -EBADF);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->input_fd = input_fd;
        bus->output_fd = output_fd;
        return 0;
}

_public_ int sd_bus_set_exec(sd_bus *bus, const char *path, char *const argv[]) {
        char *p, **a;

        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(path, -EINVAL);
        assert_return(!strv_isempty(argv), -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        a = strv_copy(argv);
        if (!a) {
                free(p);
                return -ENOMEM;
        }

        free(bus->exec_path);
        strv_free(bus->exec_argv);

        bus->exec_path = p;
        bus->exec_argv = a;

        return 0;
}

_public_ int sd_bus_set_bus_client(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->bus_client = !!b;
        return 0;
}

_public_ int sd_bus_set_monitor(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        SET_FLAG(bus->hello_flags, KDBUS_HELLO_MONITOR, b);
        return 0;
}

_public_ int sd_bus_negotiate_fds(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        SET_FLAG(bus->hello_flags, KDBUS_HELLO_ACCEPT_FD, b);
        return 0;
}

_public_ int sd_bus_negotiate_timestamp(sd_bus *bus, int b) {
        uint64_t new_flags;
        assert_return(bus, -EINVAL);
        assert_return(!IN_SET(bus->state, BUS_CLOSING, BUS_CLOSED), -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        new_flags = bus->attach_flags;
        SET_FLAG(new_flags, KDBUS_ATTACH_TIMESTAMP, b);

        if (bus->attach_flags == new_flags)
                return 0;

        bus->attach_flags = new_flags;
        if (bus->state != BUS_UNSET && bus->is_kernel)
                bus_kernel_realize_attach_flags(bus);

        return 0;
}

_public_ int sd_bus_negotiate_creds(sd_bus *bus, int b, uint64_t mask) {
        uint64_t new_flags;

        assert_return(bus, -EINVAL);
        assert_return(mask <= _SD_BUS_CREDS_ALL, -EINVAL);
        assert_return(!IN_SET(bus->state, BUS_CLOSING, BUS_CLOSED), -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (b)
                bus->creds_mask |= mask;
        else
                bus->creds_mask &= ~mask;

        /* The well knowns we need unconditionally, so that matches can work */
        bus->creds_mask |= SD_BUS_CREDS_WELL_KNOWN_NAMES|SD_BUS_CREDS_UNIQUE_NAME;

        /* Make sure we don't lose the timestamp flag */
        new_flags = (bus->attach_flags & KDBUS_ATTACH_TIMESTAMP) | attach_flags_to_kdbus(bus->creds_mask);
        if (bus->attach_flags == new_flags)
                return 0;

        bus->attach_flags = new_flags;
        if (bus->state != BUS_UNSET && bus->is_kernel)
                bus_kernel_realize_attach_flags(bus);

        return 0;
}

_public_ int sd_bus_set_server(sd_bus *bus, int b, sd_id128_t server_id) {
        assert_return(bus, -EINVAL);
        assert_return(b || sd_id128_equal(server_id, SD_ID128_NULL), -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->is_server = !!b;
        bus->server_id = server_id;
        return 0;
}

_public_ int sd_bus_set_anonymous(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->anonymous_auth = !!b;
        return 0;
}

_public_ int sd_bus_set_trusted(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->trusted = !!b;
        return 0;
}

_public_ int sd_bus_set_description(sd_bus *bus, const char *description) {
        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return free_and_strdup(&bus->description, description);
}

_public_ int sd_bus_set_allow_interactive_authorization(sd_bus *bus, int b) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->allow_interactive_authorization = !!b;
        return 0;
}

_public_ int sd_bus_get_allow_interactive_authorization(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->allow_interactive_authorization;
}

static int hello_callback(sd_bus_message *reply, void *userdata, sd_bus_error *error) {
        const char *s;
        sd_bus *bus;
        int r;

        assert(reply);
        bus = reply->bus;
        assert(bus);
        assert(bus->state == BUS_HELLO || bus->state == BUS_CLOSING);

        r = sd_bus_message_get_errno(reply);
        if (r > 0)
                return -r;

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return r;

        if (!service_name_is_valid(s) || s[0] != ':')
                return -EBADMSG;

        bus->unique_name = strdup(s);
        if (!bus->unique_name)
                return -ENOMEM;

        if (bus->state == BUS_HELLO)
                bus->state = BUS_RUNNING;

        return 1;
}

static int bus_send_hello(sd_bus *bus) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);

        if (!bus->bus_client || bus->is_kernel)
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
        assert(bus);

        if (bus->bus_client && !bus->is_kernel) {
                bus->state = BUS_HELLO;
                return 1;
        }

        bus->state = BUS_RUNNING;
        return 1;
}

static int parse_address_key(const char **p, const char *key, char **value) {
        size_t l, n = 0, allocated = 0;
        const char *a;
        char *r = NULL;

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

        while (*a != ';' && *a != ',' && *a != 0) {
                char c;

                if (*a == '%') {
                        int x, y;

                        x = unhexchar(a[1]);
                        if (x < 0) {
                                free(r);
                                return x;
                        }

                        y = unhexchar(a[2]);
                        if (y < 0) {
                                free(r);
                                return y;
                        }

                        c = (char) ((x << 4) | y);
                        a += 3;
                } else {
                        c = *a;
                        a++;
                }

                if (!GREEDY_REALLOC(r, allocated, n + 2))
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

        free(*value);
        *value = r;

        return 1;
}

static void skip_address_key(const char **p) {
        assert(p);
        assert(*p);

        *p += strcspn(*p, ",");

        if (**p == ',')
                (*p) ++;
}

static int parse_unix_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *path = NULL, *abstract = NULL;
        size_t l;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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

                skip_address_key(p);
        }

        if (!path && !abstract)
                return -EINVAL;

        if (path && abstract)
                return -EINVAL;

        if (path) {
                l = strlen(path);
                if (l > sizeof(b->sockaddr.un.sun_path))
                        return -E2BIG;

                b->sockaddr.un.sun_family = AF_UNIX;
                strncpy(b->sockaddr.un.sun_path, path, sizeof(b->sockaddr.un.sun_path));
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l;
        } else if (abstract) {
                l = strlen(abstract);
                if (l > sizeof(b->sockaddr.un.sun_path) - 1)
                        return -E2BIG;

                b->sockaddr.un.sun_family = AF_UNIX;
                b->sockaddr.un.sun_path[0] = 0;
                strncpy(b->sockaddr.un.sun_path+1, abstract, sizeof(b->sockaddr.un.sun_path)-1);
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + 1 + l;
        }

        return 0;
}

static int parse_tcp_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *host = NULL, *port = NULL, *family = NULL;
        int r;
        struct addrinfo *result, hints = {
                .ai_socktype = SOCK_STREAM,
                .ai_flags = AI_ADDRCONFIG,
        };

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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
                if (streq(family, "ipv4"))
                        hints.ai_family = AF_INET;
                else if (streq(family, "ipv6"))
                        hints.ai_family = AF_INET6;
                else
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

        return 0;
}

static int parse_exec_address(sd_bus *b, const char **p, char **guid) {
        char *path = NULL;
        unsigned n_argv = 0, j;
        char **argv = NULL;
        size_t allocated = 0;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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

                        (*p) ++;

                        if (ul >= n_argv) {
                                if (!GREEDY_REALLOC0(argv, allocated, ul + 2)) {
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
        return 0;

fail:
        for (j = 0; j < n_argv; j++)
                free(argv[j]);

        free(argv);
        free(path);
        return r;
}

static int parse_kernel_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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

                skip_address_key(p);
        }

        if (!path)
                return -EINVAL;

        free(b->kernel);
        b->kernel = path;
        path = NULL;

        return 0;
}

static int parse_container_unix_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *machine = NULL, *pid = NULL;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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
                if (!machine_name_is_valid(machine))
                        return -EINVAL;

                free(b->machine);
                b->machine = machine;
                machine = NULL;
        } else {
                free(b->machine);
                b->machine = NULL;
        }

        if (pid) {
                r = parse_pid(pid, &b->nspid);
                if (r < 0)
                        return r;
        } else
                b->nspid = 0;

        b->sockaddr.un.sun_family = AF_UNIX;
        strncpy(b->sockaddr.un.sun_path, "/var/run/dbus/system_bus_socket", sizeof(b->sockaddr.un.sun_path));
        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + strlen("/var/run/dbus/system_bus_socket");

        return 0;
}

static int parse_container_kernel_address(sd_bus *b, const char **p, char **guid) {
        _cleanup_free_ char *machine = NULL, *pid = NULL;
        int r;

        assert(b);
        assert(p);
        assert(*p);
        assert(guid);

        while (**p != 0 && **p != ';') {
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
                if (!machine_name_is_valid(machine))
                        return -EINVAL;

                free(b->machine);
                b->machine = machine;
                machine = NULL;
        } else {
                free(b->machine);
                b->machine = NULL;
        }

        if (pid) {
                r = parse_pid(pid, &b->nspid);
                if (r < 0)
                        return r;
        } else
                b->nspid = 0;

        r = free_and_strdup(&b->kernel, "/sys/fs/kdbus/0-system/bus");
        if (r < 0)
                return r;

        return 0;
}

static void bus_reset_parsed_address(sd_bus *b) {
        assert(b);

        zero(b->sockaddr);
        b->sockaddr_size = 0;
        b->exec_argv = strv_free(b->exec_argv);
        b->exec_path = mfree(b->exec_path);
        b->server_id = SD_ID128_NULL;
        b->kernel = mfree(b->kernel);
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

                } else if (startswith(a, "kernel:")) {

                        a += 7;
                        r = parse_kernel_address(b, &a, &guid);
                        if (r < 0)
                                return r;

                        break;
                } else if (startswith(a, "x-machine-unix:")) {

                        a += 15;
                        r = parse_container_unix_address(b, &a, &guid);
                        if (r < 0)
                                return r;

                        break;
                } else if (startswith(a, "x-machine-kernel:")) {

                        a += 17;
                        r = parse_container_kernel_address(b, &a, &guid);
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

static int bus_start_address(sd_bus *b) {
        bool container_kdbus_available = false;
        bool kdbus_available = false;
        int r;

        assert(b);

        for (;;) {
                bool skipped = false;

                bus_close_fds(b);

                /*
                 * Usually, if you provide multiple different bus-addresses, we
                 * try all of them in order. We use the first one that
                 * succeeds. However, if you mix kernel and unix addresses, we
                 * never try unix-addresses if a previous kernel address was
                 * tried and kdbus was available. This is required to prevent
                 * clients to fallback to the bus-proxy if kdbus is available
                 * but failed (eg., too many connections).
                 */

                if (b->exec_path)
                        r = bus_socket_exec(b);

                else if ((b->nspid > 0 || b->machine) && b->kernel) {
                        r = bus_container_connect_kernel(b);
                        if (r < 0 && !IN_SET(r, -ENOENT, -ESOCKTNOSUPPORT))
                                container_kdbus_available = true;

                } else if ((b->nspid > 0 || b->machine) && b->sockaddr.sa.sa_family != AF_UNSPEC) {
                        if (!container_kdbus_available)
                                r = bus_container_connect_socket(b);
                        else
                                skipped = true;

                } else if (b->kernel) {
                        r = bus_kernel_connect(b);
                        if (r < 0 && !IN_SET(r, -ENOENT, -ESOCKTNOSUPPORT))
                                kdbus_available = true;

                } else if (b->sockaddr.sa.sa_family != AF_UNSPEC) {
                        if (!kdbus_available)
                                r = bus_socket_connect(b);
                        else
                                skipped = true;

                } else
                        skipped = true;

                if (!skipped) {
                        if (r >= 0) {
                                r = attach_io_events(b);
                                if (r >= 0)
                                        return r;
                        }

                        b->last_connect_error = -r;
                }

                r = bus_parse_next_address(b);
                if (r < 0)
                        return r;
                if (r == 0)
                        return b->last_connect_error ? -b->last_connect_error : -ECONNREFUSED;
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

        if (S_ISCHR(b->input_fd))
                return bus_kernel_take_fd(b);
        else
                return bus_socket_take_fd(b);
}

_public_ int sd_bus_start(sd_bus *bus) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus->state == BUS_UNSET, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        bus->state = BUS_OPENING;

        if (bus->is_server && bus->bus_client)
                return -EINVAL;

        if (bus->input_fd >= 0)
                r = bus_start_fd(bus);
        else if (bus->address || bus->sockaddr.sa.sa_family != AF_UNSPEC || bus->exec_path || bus->kernel || bus->machine)
                r = bus_start_address(bus);
        else
                return -EINVAL;

        if (r < 0) {
                sd_bus_close(bus);
                return r;
        }

        return bus_send_hello(bus);
}

_public_ int sd_bus_open(sd_bus **ret) {
        const char *e;
        sd_bus *b;
        int r;

        assert_return(ret, -EINVAL);

        /* Let's connect to the starter bus if it is set, and
         * otherwise to the bus that is appropropriate for the scope
         * we are running in */

        e = secure_getenv("DBUS_STARTER_BUS_TYPE");
        if (e) {
                if (streq(e, "system"))
                        return sd_bus_open_system(ret);
                else if (STR_IN_SET(e, "session", "user"))
                        return sd_bus_open_user(ret);
        }

        e = secure_getenv("DBUS_STARTER_ADDRESS");
        if (!e) {
                if (cg_pid_get_owner_uid(0, NULL) >= 0)
                        return sd_bus_open_user(ret);
                else
                        return sd_bus_open_system(ret);
        }

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = sd_bus_set_address(b, e);
        if (r < 0)
                goto fail;

        b->bus_client = true;

        /* We don't know whether the bus is trusted or not, so better
         * be safe, and authenticate everything */
        b->trusted = false;
        b->attach_flags |= KDBUS_ATTACH_CAPS | KDBUS_ATTACH_CREDS;
        b->creds_mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_EFFECTIVE_CAPS;

        r = sd_bus_start(b);
        if (r < 0)
                goto fail;

        *ret = b;
        return 0;

fail:
        bus_free(b);
        return r;
}

int bus_set_address_system(sd_bus *b) {
        const char *e;
        assert(b);

        e = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");
        if (e)
                return sd_bus_set_address(b, e);

        return sd_bus_set_address(b, DEFAULT_SYSTEM_BUS_ADDRESS);
}

_public_ int sd_bus_open_system(sd_bus **ret) {
        sd_bus *b;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = bus_set_address_system(b);
        if (r < 0)
                goto fail;

        b->bus_client = true;
        b->is_system = true;

        /* Let's do per-method access control on the system bus. We
         * need the caller's UID and capability set for that. */
        b->trusted = false;
        b->attach_flags |= KDBUS_ATTACH_CAPS | KDBUS_ATTACH_CREDS;
        b->creds_mask |= SD_BUS_CREDS_UID | SD_BUS_CREDS_EUID | SD_BUS_CREDS_EFFECTIVE_CAPS;

        r = sd_bus_start(b);
        if (r < 0)
                goto fail;

        *ret = b;
        return 0;

fail:
        bus_free(b);
        return r;
}

int bus_set_address_user(sd_bus *b) {
        const char *e;
        uid_t uid;
        int r;

        assert(b);

        e = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
        if (e)
                return sd_bus_set_address(b, e);

        r = cg_pid_get_owner_uid(0, &uid);
        if (r < 0)
                uid = getuid();

        e = secure_getenv("XDG_RUNTIME_DIR");
        if (e) {
                _cleanup_free_ char *ee = NULL;

                ee = bus_address_escape(e);
                if (!ee)
                        return -ENOMEM;

                (void) asprintf(&b->address, KERNEL_USER_BUS_ADDRESS_FMT ";" UNIX_USER_BUS_ADDRESS_FMT, uid, ee);
        } else
                (void) asprintf(&b->address, KERNEL_USER_BUS_ADDRESS_FMT, uid);

        if (!b->address)
                return -ENOMEM;

        return 0;
}

_public_ int sd_bus_open_user(sd_bus **ret) {
        sd_bus *b;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        r = bus_set_address_user(b);
        if (r < 0)
                return r;

        b->bus_client = true;
        b->is_user = true;

        /* We don't do any per-method access control on the user
         * bus. */
        b->trusted = true;

        r = sd_bus_start(b);
        if (r < 0)
                goto fail;

        *ret = b;
        return 0;

fail:
        bus_free(b);
        return r;
}

int bus_set_address_system_remote(sd_bus *b, const char *host) {
        _cleanup_free_ char *e = NULL;
        char *m = NULL, *c = NULL;

        assert(b);
        assert(host);

        /* Let's see if we shall enter some container */
        m = strchr(host, ':');
        if (m) {
                m++;

                /* Let's make sure this is not a port of some kind,
                 * and is a valid machine name. */
                if (!in_charset(m, "0123456789") && machine_name_is_valid(m)) {
                        char *t;

                        /* Cut out the host part */
                        t = strndupa(host, m - host - 1);
                        e = bus_address_escape(t);
                        if (!e)
                                return -ENOMEM;

                        c = strjoina(",argv4=--machine=", m);
                }
        }

        if (!e) {
                e = bus_address_escape(host);
                if (!e)
                        return -ENOMEM;
        }

        b->address = strjoin("unixexec:path=ssh,argv1=-xT,argv2=", e, ",argv3=systemd-stdio-bridge", c, NULL);
        if (!b->address)
                return -ENOMEM;

        return 0;
 }

_public_ int sd_bus_open_system_remote(sd_bus **ret, const char *host) {
        sd_bus *bus;
        int r;

        assert_return(host, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = bus_set_address_system_remote(bus, host);
        if (r < 0)
                goto fail;

        bus->bus_client = true;
        bus->trusted = false;
        bus->is_system = true;

        r = sd_bus_start(bus);
        if (r < 0)
                goto fail;

        *ret = bus;
        return 0;

fail:
        bus_free(bus);
        return r;
}

int bus_set_address_system_machine(sd_bus *b, const char *machine) {
        _cleanup_free_ char *e = NULL;

        assert(b);
        assert(machine);

        e = bus_address_escape(machine);
        if (!e)
                return -ENOMEM;

        b->address = strjoin("x-machine-kernel:machine=", e, ";x-machine-unix:machine=", e, NULL);
        if (!b->address)
                return -ENOMEM;

        return 0;
}

_public_ int sd_bus_open_system_machine(sd_bus **ret, const char *machine) {
        sd_bus *bus;
        int r;

        assert_return(machine, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(machine_name_is_valid(machine), -EINVAL);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = bus_set_address_system_machine(bus, machine);
        if (r < 0)
                goto fail;

        bus->bus_client = true;
        bus->trusted = false;
        bus->is_system = true;

        r = sd_bus_start(bus);
        if (r < 0)
                goto fail;

        *ret = bus;
        return 0;

fail:
        bus_free(bus);
        return r;
}

_public_ void sd_bus_close(sd_bus *bus) {

        if (!bus)
                return;
        if (bus->state == BUS_CLOSED)
                return;
        if (bus_pid_changed(bus))
                return;

        bus->state = BUS_CLOSED;

        sd_bus_detach_event(bus);

        /* Drop all queued messages so that they drop references to
         * the bus object and the bus may be freed */
        bus_reset_queues(bus);

        if (!bus->is_kernel)
                bus_close_fds(bus);

        /* We'll leave the fd open in case this is a kernel bus, since
         * there might still be memblocks around that reference this
         * bus, and they might need to invoke the KDBUS_CMD_FREE
         * ioctl on the fd when they are freed. */
}

_public_ sd_bus* sd_bus_flush_close_unref(sd_bus *bus) {

        if (!bus)
                return NULL;

        sd_bus_flush(bus);
        sd_bus_close(bus);

        return sd_bus_unref(bus);
}

static void bus_enter_closing(sd_bus *bus) {
        assert(bus);

        if (bus->state != BUS_OPENING &&
            bus->state != BUS_AUTHENTICATING &&
            bus->state != BUS_HELLO &&
            bus->state != BUS_RUNNING)
                return;

        bus->state = BUS_CLOSING;
}

_public_ sd_bus *sd_bus_ref(sd_bus *bus) {
        assert_return(bus, NULL);

        assert_se(REFCNT_INC(bus->n_ref) >= 2);

        return bus;
}

_public_ sd_bus *sd_bus_unref(sd_bus *bus) {
        unsigned i;

        if (!bus)
                return NULL;

        i = REFCNT_DEC(bus->n_ref);
        if (i > 0)
                return NULL;

        bus_free(bus);
        return NULL;
}

_public_ int sd_bus_is_open(sd_bus *bus) {

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return BUS_IS_OPEN(bus->state);
}

_public_ int sd_bus_can_send(sd_bus *bus, char type) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(bus->state != BUS_UNSET, -ENOTCONN);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
                return 0;

        if (type == SD_BUS_TYPE_UNIX_FD) {
                if (!(bus->hello_flags & KDBUS_HELLO_ACCEPT_FD))
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
        assert_return(id, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *id = bus->server_id;
        return 0;
}

static int bus_seal_message(sd_bus *b, sd_bus_message *m, usec_t timeout) {
        assert(b);
        assert(m);

        if (m->sealed) {
                /* If we copy the same message to multiple
                 * destinations, avoid using the same cookie
                 * numbers. */
                b->cookie = MAX(b->cookie, BUS_MESSAGE_COOKIE(m));
                return 0;
        }

        if (timeout == 0)
                timeout = BUS_DEFAULT_TIMEOUT;

        return bus_message_seal(m, ++b->cookie, timeout);
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

        /* TODO: kdbus-messages received from the kernel contain data which is
         * not allowed to be passed to KDBUS_CMD_SEND. Therefore, we have to
         * force remarshaling of the message. Technically, we could just
         * recreate the kdbus message, but that is non-trivial as other parts of
         * the message refer to m->kdbus already. This should be fixed! */
        if ((*m)->kdbus && (*m)->release_kdbus)
                remarshal = true;

        return remarshal ? bus_message_remarshal(b, m) : 0;
}

int bus_seal_synthetic_message(sd_bus *b, sd_bus_message *m) {
        assert(b);
        assert(m);

        /* Fake some timestamps, if they were requested, and not
         * already initialized */
        if (b->attach_flags & KDBUS_ATTACH_TIMESTAMP) {
                if (m->realtime <= 0)
                        m->realtime = now(CLOCK_REALTIME);

                if (m->monotonic <= 0)
                        m->monotonic = now(CLOCK_MONOTONIC);
        }

        /* The bus specification says the serial number cannot be 0,
         * hence let's fill something in for synthetic messages. Since
         * synthetic messages might have a fake sender and we don't
         * want to interfere with the real sender's serial numbers we
         * pick a fixed, artificial one. We use (uint32_t) -1 rather
         * than (uint64_t) -1 since dbus1 only had 32bit identifiers,
         * even though kdbus can do 64bit. */
        return bus_message_seal(m, 0xFFFFFFFFULL, 0);
}

static int bus_write_message(sd_bus *bus, sd_bus_message *m, bool hint_sync_call, size_t *idx) {
        int r;

        assert(bus);
        assert(m);

        if (bus->is_kernel)
                r = bus_kernel_write_message(bus, m, hint_sync_call);
        else
                r = bus_socket_write_message(bus, m, idx);

        if (r <= 0)
                return r;

        if (bus->is_kernel || *idx >= BUS_MESSAGE_SIZE(m))
                log_debug("Sent message type=%s sender=%s destination=%s object=%s interface=%s member=%s cookie=%" PRIu64 " reply_cookie=%" PRIu64 " error=%s",
                          bus_message_type_to_string(m->header->type),
                          strna(sd_bus_message_get_sender(m)),
                          strna(sd_bus_message_get_destination(m)),
                          strna(sd_bus_message_get_path(m)),
                          strna(sd_bus_message_get_interface(m)),
                          strna(sd_bus_message_get_member(m)),
                          BUS_MESSAGE_COOKIE(m),
                          m->reply_cookie,
                          strna(m->error.message));

        return r;
}

static int dispatch_wqueue(sd_bus *bus) {
        int r, ret = 0;

        assert(bus);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        while (bus->wqueue_size > 0) {

                r = bus_write_message(bus, bus->wqueue[0], false, &bus->windex);
                if (r < 0)
                        return r;
                else if (r == 0)
                        /* Didn't do anything this time */
                        return ret;
                else if (bus->is_kernel || bus->windex >= BUS_MESSAGE_SIZE(bus->wqueue[0])) {
                        /* Fully written. Let's drop the entry from
                         * the queue.
                         *
                         * This isn't particularly optimized, but
                         * well, this is supposed to be our worst-case
                         * buffer only, and the socket buffer is
                         * supposed to be our primary buffer, and if
                         * it got full, then all bets are off
                         * anyway. */

                        bus->wqueue_size --;
                        sd_bus_message_unref(bus->wqueue[0]);
                        memmove(bus->wqueue, bus->wqueue + 1, sizeof(sd_bus_message*) * bus->wqueue_size);
                        bus->windex = 0;

                        ret = 1;
                }
        }

        return ret;
}

static int bus_read_message(sd_bus *bus, bool hint_priority, int64_t priority) {
        assert(bus);

        if (bus->is_kernel)
                return bus_kernel_read_message(bus, hint_priority, priority);
        else
                return bus_socket_read_message(bus);
}

int bus_rqueue_make_room(sd_bus *bus) {
        assert(bus);

        if (bus->rqueue_size >= BUS_RQUEUE_MAX)
                return -ENOBUFS;

        if (!GREEDY_REALLOC(bus->rqueue, bus->rqueue_allocated, bus->rqueue_size + 1))
                return -ENOMEM;

        return 0;
}

static int dispatch_rqueue(sd_bus *bus, bool hint_priority, int64_t priority, sd_bus_message **m) {
        int r, ret = 0;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        /* Note that the priority logic is only available on kdbus,
         * where the rqueue is unused. We check the rqueue here
         * anyway, because it's simple... */

        for (;;) {
                if (bus->rqueue_size > 0) {
                        /* Dispatch a queued message */

                        *m = bus->rqueue[0];
                        bus->rqueue_size --;
                        memmove(bus->rqueue, bus->rqueue + 1, sizeof(sd_bus_message*) * bus->rqueue_size);
                        return 1;
                }

                /* Try to read a new message */
                r = bus_read_message(bus, hint_priority, priority);
                if (r < 0)
                        return r;
                if (r == 0)
                        return ret;

                ret = 1;
        }
}

static int bus_send_internal(sd_bus *bus, sd_bus_message *_m, uint64_t *cookie, bool hint_sync_call) {
        _cleanup_bus_message_unref_ sd_bus_message *m = sd_bus_message_ref(_m);
        int r;

        assert_return(m, -EINVAL);

        if (!bus)
                bus = m->bus;

        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(!bus->is_kernel || !(bus->hello_flags & KDBUS_HELLO_MONITOR), -EROFS);

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

        if ((bus->state == BUS_RUNNING || bus->state == BUS_HELLO) && bus->wqueue_size <= 0) {
                size_t idx = 0;

                r = bus_write_message(bus, m, hint_sync_call, &idx);
                if (r < 0) {
                        if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
                                bus_enter_closing(bus);
                                return -ECONNRESET;
                        }

                        return r;
                }

                if (!bus->is_kernel && idx < BUS_MESSAGE_SIZE(m))  {
                        /* Wasn't fully written. So let's remember how
                         * much was written. Note that the first entry
                         * of the wqueue array is always allocated so
                         * that we always can remember how much was
                         * written. */
                        bus->wqueue[0] = sd_bus_message_ref(m);
                        bus->wqueue_size = 1;
                        bus->windex = idx;
                }

        } else {
                /* Just append it to the queue. */

                if (bus->wqueue_size >= BUS_WQUEUE_MAX)
                        return -ENOBUFS;

                if (!GREEDY_REALLOC(bus->wqueue, bus->wqueue_allocated, bus->wqueue_size + 1))
                        return -ENOMEM;

                bus->wqueue[bus->wqueue_size ++] = sd_bus_message_ref(m);
        }

finish:
        if (cookie)
                *cookie = BUS_MESSAGE_COOKIE(m);

        return 1;
}

_public_ int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *cookie) {
        return bus_send_internal(bus, m, cookie, false);
}

_public_ int sd_bus_send_to(sd_bus *bus, sd_bus_message *m, const char *destination, uint64_t *cookie) {
        int r;

        assert_return(m, -EINVAL);

        if (!bus)
                bus = m->bus;

        assert_return(!bus_pid_changed(bus), -ECHILD);

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

static usec_t calc_elapse(uint64_t usec) {
        if (usec == (uint64_t) -1)
                return 0;

        return now(CLOCK_MONOTONIC) + usec;
}

static int timeout_compare(const void *a, const void *b) {
        const struct reply_callback *x = a, *y = b;

        if (x->timeout != 0 && y->timeout == 0)
                return -1;

        if (x->timeout == 0 && y->timeout != 0)
                return 1;

        if (x->timeout < y->timeout)
                return -1;

        if (x->timeout > y->timeout)
                return 1;

        return 0;
}

_public_ int sd_bus_call_async(
                sd_bus *bus,
                sd_bus_slot **slot,
                sd_bus_message *_m,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t usec) {

        _cleanup_bus_message_unref_ sd_bus_message *m = sd_bus_message_ref(_m);
        _cleanup_bus_slot_unref_ sd_bus_slot *s = NULL;
        int r;

        assert_return(m, -EINVAL);
        assert_return(m->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL);
        assert_return(!(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED), -EINVAL);
        assert_return(callback, -EINVAL);

        if (!bus)
                bus = m->bus;

        assert_return(!bus_pid_changed(bus), -ECHILD);
        assert_return(!bus->is_kernel || !(bus->hello_flags & KDBUS_HELLO_MONITOR), -EROFS);

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

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

        s->reply_callback.timeout = calc_elapse(m->timeout);
        if (s->reply_callback.timeout != 0) {
                r = prioq_put(bus->reply_callbacks_prioq, &s->reply_callback, &s->reply_callback.prioq_idx);
                if (r < 0) {
                        s->reply_callback.timeout = 0;
                        return r;
                }
        }

        r = sd_bus_send(bus, m, &s->reply_callback.cookie);
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

        if (bus->state == BUS_UNSET || bus->state == BUS_CLOSED || bus->state == BUS_CLOSING)
                return -ENOTCONN;
        if (bus->state == BUS_RUNNING)
                return 1;

        for (;;) {
                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return r;
                if (bus->state == BUS_RUNNING)
                        return 1;
                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, (uint64_t) -1);
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

        _cleanup_bus_message_unref_ sd_bus_message *m = sd_bus_message_ref(_m);
        usec_t timeout;
        uint64_t cookie;
        unsigned i;
        int r;

        bus_assert_return(m, -EINVAL, error);
        bus_assert_return(m->header->type == SD_BUS_MESSAGE_METHOD_CALL, -EINVAL, error);
        bus_assert_return(!(m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED), -EINVAL, error);
        bus_assert_return(!bus_error_is_dirty(error), -EINVAL, error);

        if (!bus)
                bus = m->bus;

        bus_assert_return(!bus_pid_changed(bus), -ECHILD, error);
        bus_assert_return(!bus->is_kernel || !(bus->hello_flags & KDBUS_HELLO_MONITOR), -EROFS, error);

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

        r = bus_send_internal(bus, m, &cookie, true);
        if (r < 0)
                goto fail;

        timeout = calc_elapse(m->timeout);

        for (;;) {
                usec_t left;

                while (i < bus->rqueue_size) {
                        sd_bus_message *incoming = NULL;

                        incoming = bus->rqueue[i];

                        if (incoming->reply_cookie == cookie) {
                                /* Found a match! */

                                memmove(bus->rqueue + i, bus->rqueue + i + 1, sizeof(sd_bus_message*) * (bus->rqueue_size - i - 1));
                                bus->rqueue_size--;
                                log_debug_bus_message(incoming);

                                if (incoming->header->type == SD_BUS_MESSAGE_METHOD_RETURN) {

                                        if (incoming->n_fds <= 0 || (bus->hello_flags & KDBUS_HELLO_ACCEPT_FD)) {
                                                if (reply)
                                                        *reply = incoming;
                                                else
                                                        sd_bus_message_unref(incoming);

                                                return 1;
                                        }

                                        r = sd_bus_error_setf(error, SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Reply message contained file descriptors which I couldn't accept. Sorry.");
                                        sd_bus_message_unref(incoming);
                                        return r;

                                } else if (incoming->header->type == SD_BUS_MESSAGE_METHOD_ERROR) {
                                        r = sd_bus_error_copy(error, &incoming->error);
                                        sd_bus_message_unref(incoming);
                                        return r;
                                } else {
                                        r = -EIO;
                                        goto fail;
                                }

                        } else if (BUS_MESSAGE_COOKIE(incoming) == cookie &&
                                   bus->unique_name &&
                                   incoming->sender &&
                                   streq(bus->unique_name, incoming->sender)) {

                                memmove(bus->rqueue + i, bus->rqueue + i + 1, sizeof(sd_bus_message*) * (bus->rqueue_size - i - 1));
                                bus->rqueue_size--;

                                /* Our own message? Somebody is trying
                                 * to send its own client a message,
                                 * let's not dead-lock, let's fail
                                 * immediately. */

                                sd_bus_message_unref(incoming);
                                r = -ELOOP;
                                goto fail;
                        }

                        /* Try to read more, right-away */
                        i++;
                }

                r = bus_read_message(bus, false, 0);
                if (r < 0) {
                        if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
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
                        left = (uint64_t) -1;

                r = bus_poll(bus, true, left);
                if (r < 0)
                        goto fail;
                if (r == 0) {
                        r = -ETIMEDOUT;
                        goto fail;
                }

                r = dispatch_wqueue(bus);
                if (r < 0) {
                        if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
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
        assert_return(bus->input_fd == bus->output_fd, -EPERM);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->input_fd;
}

_public_ int sd_bus_get_events(sd_bus *bus) {
        int flags = 0;

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state) && bus->state != BUS_CLOSING)
                return -ENOTCONN;

        if (bus->state == BUS_OPENING)
                flags |= POLLOUT;
        else if (bus->state == BUS_AUTHENTICATING) {

                if (bus_socket_auth_needs_write(bus))
                        flags |= POLLOUT;

                flags |= POLLIN;

        } else if (bus->state == BUS_RUNNING || bus->state == BUS_HELLO) {
                if (bus->rqueue_size <= 0)
                        flags |= POLLIN;
                if (bus->wqueue_size > 0)
                        flags |= POLLOUT;
        }

        return flags;
}

_public_ int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec) {
        struct reply_callback *c;

        assert_return(bus, -EINVAL);
        assert_return(timeout_usec, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!BUS_IS_OPEN(bus->state) && bus->state != BUS_CLOSING)
                return -ENOTCONN;

        if (bus->track_queue) {
                *timeout_usec = 0;
                return 1;
        }

        if (bus->state == BUS_CLOSING) {
                *timeout_usec = 0;
                return 1;
        }

        if (bus->state == BUS_AUTHENTICATING) {
                *timeout_usec = bus->auth_timeout;
                return 1;
        }

        if (bus->state != BUS_RUNNING && bus->state != BUS_HELLO) {
                *timeout_usec = (uint64_t) -1;
                return 0;
        }

        if (bus->rqueue_size > 0) {
                *timeout_usec = 0;
                return 1;
        }

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c) {
                *timeout_usec = (uint64_t) -1;
                return 0;
        }

        if (c->timeout == 0) {
                *timeout_usec = (uint64_t) -1;
                return 0;
        }

        *timeout_usec = c->timeout;
        return 1;
}

static int process_timeout(sd_bus *bus) {
        _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message* m = NULL;
        struct reply_callback *c;
        sd_bus_slot *slot;
        usec_t n;
        int r;

        assert(bus);

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c)
                return 0;

        n = now(CLOCK_MONOTONIC);
        if (c->timeout > n)
                return 0;

        r = bus_message_new_synthetic_error(
                        bus,
                        c->cookie,
                        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call timed out"),
                        &m);
        if (r < 0)
                return r;

        r = bus_seal_synthetic_message(bus, m);
        if (r < 0)
                return r;

        assert_se(prioq_pop(bus->reply_callbacks_prioq) == c);
        c->timeout = 0;

        ordered_hashmap_remove(bus->reply_callbacks, &c->cookie);
        c->cookie = 0;

        slot = container_of(c, sd_bus_slot, reply_callback);

        bus->iteration_counter ++;

        bus->current_message = m;
        bus->current_slot = sd_bus_slot_ref(slot);
        bus->current_handler = c->callback;
        bus->current_userdata = slot->userdata;
        r = c->callback(m, slot->userdata, &error_buffer);
        bus->current_userdata = NULL;
        bus->current_handler = NULL;
        bus->current_slot = NULL;
        bus->current_message = NULL;

        if (slot->floating) {
                bus_slot_disconnect(slot);
                sd_bus_slot_unref(slot);
        }

        sd_bus_slot_unref(slot);

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

        if (m->header->type != SD_BUS_MESSAGE_METHOD_RETURN &&
            m->header->type != SD_BUS_MESSAGE_METHOD_ERROR)
                return -EIO;

        if (m->reply_cookie != 1)
                return -EIO;

        return 0;
}

static int process_reply(sd_bus *bus, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *synthetic_reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        struct reply_callback *c;
        sd_bus_slot *slot;
        int r;

        assert(bus);
        assert(m);

        if (m->header->type != SD_BUS_MESSAGE_METHOD_RETURN &&
            m->header->type != SD_BUS_MESSAGE_METHOD_ERROR)
                return 0;

        if (bus->is_kernel && (bus->hello_flags & KDBUS_HELLO_MONITOR))
                return 0;

        if (m->destination && bus->unique_name && !streq_ptr(m->destination, bus->unique_name))
                return 0;

        c = ordered_hashmap_remove(bus->reply_callbacks, &m->reply_cookie);
        if (!c)
                return 0;

        c->cookie = 0;

        slot = container_of(c, sd_bus_slot, reply_callback);

        if (m->n_fds > 0 && !(bus->hello_flags & KDBUS_HELLO_ACCEPT_FD)) {

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

                r = bus_seal_synthetic_message(bus, synthetic_reply);
                if (r < 0)
                        return r;

                m = synthetic_reply;
        } else {
                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;
        }

        if (c->timeout != 0) {
                prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
                c->timeout = 0;
        }

        bus->current_slot = sd_bus_slot_ref(slot);
        bus->current_handler = c->callback;
        bus->current_userdata = slot->userdata;
        r = c->callback(m, slot->userdata, &error_buffer);
        bus->current_userdata = NULL;
        bus->current_handler = NULL;
        bus->current_slot = NULL;

        if (slot->floating) {
                bus_slot_disconnect(slot);
                sd_bus_slot_unref(slot);
        }

        sd_bus_slot_unref(slot);

        return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_filter(sd_bus *bus, sd_bus_message *m) {
        _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
        struct filter_callback *l;
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
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(m);

        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
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
                char sid[33];

                r = sd_id128_get_machine(&id);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_return(m, &reply);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "s", sd_id128_to_string(id, sid));
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

        if (bus->hello_flags & KDBUS_HELLO_MONITOR)
                return 0;

        if (m->n_fds <= 0)
                return 0;

        if (bus->hello_flags & KDBUS_HELLO_ACCEPT_FD)
                return 0;

        if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
                return 1; /* just eat it up */

        return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Message contains file descriptors, which I cannot accept. Sorry.");
}

static int process_message(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert(bus);
        assert(m);

        bus->current_message = m;
        bus->iteration_counter++;

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

static int process_running(sd_bus *bus, bool hint_priority, int64_t priority, sd_bus_message **ret) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        r = process_timeout(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_wqueue(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_track(bus);
        if (r != 0)
                goto null_message;

        r = dispatch_rqueue(bus, hint_priority, priority, &m);
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

                *ret = m;
                m = NULL;
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

static int process_closing(sd_bus *bus, sd_bus_message **ret) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        struct reply_callback *c;
        int r;

        assert(bus);
        assert(bus->state == BUS_CLOSING);

        c = ordered_hashmap_first(bus->reply_callbacks);
        if (c) {
                _cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
                sd_bus_slot *slot;

                /* First, fail all outstanding method calls */
                r = bus_message_new_synthetic_error(
                                bus,
                                c->cookie,
                                &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Connection terminated"),
                                &m);
                if (r < 0)
                        return r;

                r = bus_seal_synthetic_message(bus, m);
                if (r < 0)
                        return r;

                if (c->timeout != 0) {
                        prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
                        c->timeout = 0;
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

                if (slot->floating) {
                        bus_slot_disconnect(slot);
                        sd_bus_slot_unref(slot);
                }

                sd_bus_slot_unref(slot);

                return bus_maybe_reply_error(m, r, &error_buffer);
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

        if (ret) {
                *ret = m;
                m = NULL;
        }

        r = 1;

finish:
        bus->current_message = NULL;

        return r;
}

static int bus_process_internal(sd_bus *bus, bool hint_priority, int64_t priority, sd_bus_message **ret) {
        BUS_DONT_DESTROY(bus);
        int r;

        /* Returns 0 when we didn't do anything. This should cause the
         * caller to invoke sd_bus_wait() before returning the next
         * time. Returns > 0 when we did something, which possibly
         * means *ret is filled in with an unprocessed message. */

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        /* We don't allow recursively invoking sd_bus_process(). */
        assert_return(!bus->current_message, -EBUSY);
        assert(!bus->current_slot);

        switch (bus->state) {

        case BUS_UNSET:
                return -ENOTCONN;

        case BUS_CLOSED:
                return -ECONNRESET;

        case BUS_OPENING:
                r = bus_socket_process_opening(bus);
                if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
                        bus_enter_closing(bus);
                        r = 1;
                } else if (r < 0)
                        return r;
                if (ret)
                        *ret = NULL;
                return r;

        case BUS_AUTHENTICATING:
                r = bus_socket_process_authenticating(bus);
                if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
                        bus_enter_closing(bus);
                        r = 1;
                } else if (r < 0)
                        return r;

                if (ret)
                        *ret = NULL;

                return r;

        case BUS_RUNNING:
        case BUS_HELLO:
                r = process_running(bus, hint_priority, priority, ret);
                if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
                        bus_enter_closing(bus);
                        r = 1;

                        if (ret)
                                *ret = NULL;
                }

                return r;

        case BUS_CLOSING:
                return process_closing(bus, ret);
        }

        assert_not_reached("Unknown state");
}

_public_ int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
        return bus_process_internal(bus, false, 0, ret);
}

_public_ int sd_bus_process_priority(sd_bus *bus, int64_t priority, sd_bus_message **ret) {
        return bus_process_internal(bus, true, priority, ret);
}

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec) {
        struct pollfd p[2] = {};
        int r, e, n;
        struct timespec ts;
        usec_t m = USEC_INFINITY;

        assert(bus);

        if (bus->state == BUS_CLOSING)
                return 1;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        e = sd_bus_get_events(bus);
        if (e < 0)
                return e;

        if (need_more)
                /* The caller really needs some more data, he doesn't
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
                if (r > 0) {
                        usec_t nw;
                        nw = now(CLOCK_MONOTONIC);
                        m = until > nw ? until - nw : 0;
                }
        }

        if (timeout_usec != (uint64_t) -1 && (m == (uint64_t) -1 || timeout_usec < m))
                m = timeout_usec;

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

        r = ppoll(p, n, m == (uint64_t) -1 ? NULL : timespec_store(&ts, m), NULL);
        if (r < 0)
                return -errno;

        return r > 0 ? 1 : 0;
}

_public_ int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->state == BUS_CLOSING)
                return 0;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->rqueue_size > 0)
                return 0;

        return bus_poll(bus, false, timeout_usec);
}

_public_ int sd_bus_flush(sd_bus *bus) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->state == BUS_CLOSING)
                return 0;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        if (bus->wqueue_size <= 0)
                return 0;

        for (;;) {
                r = dispatch_wqueue(bus);
                if (r < 0) {
                        if (r == -ENOTCONN || r == -ECONNRESET || r == -EPIPE || r == -ESHUTDOWN) {
                                bus_enter_closing(bus);
                                return -ECONNRESET;
                        }

                        return r;
                }

                if (bus->wqueue_size <= 0)
                        return 0;

                r = bus_poll(bus, false, (uint64_t) -1);
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
        assert_return(callback, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

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

_public_ int sd_bus_add_match(
                sd_bus *bus,
                sd_bus_slot **slot,
                const char *match,
                sd_bus_message_handler_t callback,
                void *userdata) {

        struct bus_match_component *components = NULL;
        unsigned n_components = 0;
        sd_bus_slot *s = NULL;
        int r = 0;

        assert_return(bus, -EINVAL);
        assert_return(match, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                goto finish;

        s = bus_slot_allocate(bus, !slot, BUS_MATCH_CALLBACK, sizeof(struct match_callback), userdata);
        if (!s) {
                r = -ENOMEM;
                goto finish;
        }

        s->match_callback.callback = callback;
        s->match_callback.cookie = ++bus->match_cookie;

        if (bus->bus_client) {
                enum bus_match_scope scope;

                scope = bus_match_get_scope(components, n_components);

                /* Do not install server-side matches for matches
                 * against the local service, interface or bus
                 * path. */
                if (scope != BUS_MATCH_LOCAL) {

                        if (!bus->is_kernel) {
                                /* When this is not a kernel transport, we
                                 * store the original match string, so that we
                                 * can use it to remove the match again */

                                s->match_callback.match_string = strdup(match);
                                if (!s->match_callback.match_string) {
                                        r = -ENOMEM;
                                        goto finish;
                                }
                        }

                        r = bus_add_match_internal(bus, s->match_callback.match_string, components, n_components, s->match_callback.cookie);
                        if (r < 0)
                                goto finish;

                        s->match_added = true;
                }
        }

        bus->match_callbacks_modified = true;
        r = bus_match_add(&bus->match_callbacks, components, n_components, &s->match_callback);
        if (r < 0)
                goto finish;

        if (slot)
                *slot = s;
        s = NULL;

finish:
        bus_match_parse_free(components, n_components);
        sd_bus_slot_unref(s);

        return r;
}

int bus_remove_match_by_string(
                sd_bus *bus,
                const char *match,
                sd_bus_message_handler_t callback,
                void *userdata) {

        struct bus_match_component *components = NULL;
        unsigned n_components = 0;
        struct match_callback *c;
        int r = 0;

        assert_return(bus, -EINVAL);
        assert_return(match, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        r = bus_match_parse(match, &components, &n_components);
        if (r < 0)
                goto finish;

        r = bus_match_find(&bus->match_callbacks, components, n_components, NULL, NULL, &c);
        if (r <= 0)
                goto finish;

        sd_bus_slot_unref(container_of(c, sd_bus_slot, match_callback));

finish:
        bus_match_parse_free(components, n_components);

        return r;
}

bool bus_pid_changed(sd_bus *bus) {
        assert(bus);

        /* We don't support people creating a bus connection and
         * keeping it around over a fork(). Let's complain. */

        return bus->original_pid != getpid();
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = sd_bus_process(bus, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_bus *bus = userdata;
        int r;

        assert(bus);

        r = sd_bus_process(bus, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_bus *bus = userdata;
        int r, e;
        usec_t until;

        assert(s);
        assert(bus);

        e = sd_bus_get_events(bus);
        if (e < 0)
                return e;

        if (bus->output_fd != bus->input_fd) {

                r = sd_event_source_set_io_events(bus->input_io_event_source, e & POLLIN);
                if (r < 0)
                        return r;

                r = sd_event_source_set_io_events(bus->output_io_event_source, e & POLLOUT);
                if (r < 0)
                        return r;
        } else {
                r = sd_event_source_set_io_events(bus->input_io_event_source, e);
                if (r < 0)
                        return r;
        }

        r = sd_bus_get_timeout(bus, &until);
        if (r < 0)
                return r;
        if (r > 0) {
                int j;

                j = sd_event_source_set_time(bus->time_event_source, until);
                if (j < 0)
                        return j;
        }

        r = sd_event_source_set_enabled(bus->time_event_source, r > 0);
        if (r < 0)
                return r;

        return 1;
}

static int quit_callback(sd_event_source *event, void *userdata) {
        sd_bus *bus = userdata;

        assert(event);

        sd_bus_flush(bus);
        sd_bus_close(bus);

        return 1;
}

static int attach_io_events(sd_bus *bus) {
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

static void detach_io_events(sd_bus *bus) {
        assert(bus);

        if (bus->input_io_event_source) {
                sd_event_source_set_enabled(bus->input_io_event_source, SD_EVENT_OFF);
                bus->input_io_event_source = sd_event_source_unref(bus->input_io_event_source);
        }

        if (bus->output_io_event_source) {
                sd_event_source_set_enabled(bus->output_io_event_source, SD_EVENT_OFF);
                bus->output_io_event_source = sd_event_source_unref(bus->output_io_event_source);
        }
}

_public_ int sd_bus_attach_event(sd_bus *bus, sd_event *event, int priority) {
        int r;

        assert_return(bus, -EINVAL);
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

        r = attach_io_events(bus);
        if (r < 0)
                goto fail;

        return 0;

fail:
        sd_bus_detach_event(bus);
        return r;
}

_public_ int sd_bus_detach_event(sd_bus *bus) {
        assert_return(bus, -EINVAL);

        if (!bus->event)
                return 0;

        detach_io_events(bus);

        if (bus->time_event_source) {
                sd_event_source_set_enabled(bus->time_event_source, SD_EVENT_OFF);
                bus->time_event_source = sd_event_source_unref(bus->time_event_source);
        }

        if (bus->quit_event_source) {
                sd_event_source_set_enabled(bus->quit_event_source, SD_EVENT_OFF);
                bus->quit_event_source = sd_event_source_unref(bus->quit_event_source);
        }

        bus->event = sd_event_unref(bus->event);
        return 1;
}

_public_ sd_event* sd_bus_get_event(sd_bus *bus) {
        assert_return(bus, NULL);

        return bus->event;
}

_public_ sd_bus_message* sd_bus_get_current_message(sd_bus *bus) {
        assert_return(bus, NULL);

        return bus->current_message;
}

_public_ sd_bus_slot* sd_bus_get_current_slot(sd_bus *bus) {
        assert_return(bus, NULL);

        return bus->current_slot;
}

_public_ sd_bus_message_handler_t sd_bus_get_current_handler(sd_bus *bus) {
        assert_return(bus, NULL);

        return bus->current_handler;
}

_public_ void* sd_bus_get_current_userdata(sd_bus *bus) {
        assert_return(bus, NULL);

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
        static thread_local sd_bus *default_system_bus = NULL;

        return bus_default(sd_bus_open_system, &default_system_bus, ret);
}

_public_ int sd_bus_default_user(sd_bus **ret) {
        static thread_local sd_bus *default_user_bus = NULL;

        return bus_default(sd_bus_open_user, &default_user_bus, ret);
}

_public_ int sd_bus_default(sd_bus **ret) {

        const char *e;

        /* Let's try our best to reuse another cached connection. If
         * the starter bus type is set, connect via our normal
         * connection logic, ignoring $DBUS_STARTER_ADDRESS, so that
         * we can share the connection with the user/system default
         * bus. */

        e = secure_getenv("DBUS_STARTER_BUS_TYPE");
        if (e) {
                if (streq(e, "system"))
                        return sd_bus_default_system(ret);
                else if (STR_IN_SET(e, "user", "session"))
                        return sd_bus_default_user(ret);
        }

        /* No type is specified, so we have not other option than to
         * use the starter address if it is set. */

        e = secure_getenv("DBUS_STARTER_ADDRESS");
        if (e) {
                static thread_local sd_bus *default_starter_bus = NULL;

                return bus_default(sd_bus_open, &default_starter_bus, ret);
        }

        /* Finally, if nothing is set use the cached connection for
         * the right scope */

        if (cg_pid_get_owner_uid(0, NULL) >= 0)
                return sd_bus_default_user(ret);
        else
                return sd_bus_default_system(ret);
}

_public_ int sd_bus_get_tid(sd_bus *b, pid_t *tid) {
        assert_return(b, -EINVAL);
        assert_return(tid, -EINVAL);
        assert_return(!bus_pid_changed(b), -ECHILD);

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

        ret = strjoin(prefix, "/", e, NULL);
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

        ret = bus_label_unescape(e);
        if (!ret)
                return -ENOMEM;

        *external_id = ret;
        return 1;
}

_public_ int sd_bus_try_close(sd_bus *bus) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (!bus->is_kernel)
                return -EOPNOTSUPP;

        if (!BUS_IS_OPEN(bus->state))
                return -ENOTCONN;

        if (bus->rqueue_size > 0)
                return -EBUSY;

        if (bus->wqueue_size > 0)
                return -EBUSY;

        r = bus_kernel_try_close(bus);
        if (r < 0)
                return r;

        sd_bus_close(bus);
        return 0;
}

_public_ int sd_bus_get_description(sd_bus *bus, const char **description) {
        assert_return(bus, -EINVAL);
        assert_return(description, -EINVAL);
        assert_return(bus->description, -ENXIO);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        *description = bus->description;
        return 0;
}

int bus_get_root_path(sd_bus *bus) {
        int r;

        if (bus->cgroup_root)
                return 0;

        r = cg_get_root_path(&bus->cgroup_root);
        if (r == -ENOENT) {
                bus->cgroup_root = strdup("/");
                if (!bus->cgroup_root)
                        return -ENOMEM;

                r = 0;
        }

        return r;
}

_public_ int sd_bus_get_scope(sd_bus *bus, const char **scope) {
        int r;

        assert_return(bus, -EINVAL);
        assert_return(scope, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->is_kernel) {
                _cleanup_free_ char *n = NULL;
                const char *dash;

                r = bus_kernel_get_bus_name(bus, &n);
                if (r < 0)
                        return r;

                if (streq(n, "0-system")) {
                        *scope = "system";
                        return 0;
                }

                dash = strchr(n, '-');
                if (streq_ptr(dash, "-user")) {
                        *scope = "user";
                        return 0;
                }
        }

        if (bus->is_user) {
                *scope = "user";
                return 0;
        }

        if (bus->is_system) {
                *scope = "system";
                return 0;
        }

        return -ENODATA;
}

_public_ int sd_bus_get_address(sd_bus *bus, const char **address) {

        assert_return(bus, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        if (bus->address) {
                *address = bus->address;
                return 0;
        }

        return -ENODATA;
}

_public_ int sd_bus_get_creds_mask(sd_bus *bus, uint64_t *mask) {
        assert_return(bus, -EINVAL);
        assert_return(mask, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        *mask = bus->creds_mask;
        return 0;
}

_public_ int sd_bus_is_bus_client(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->bus_client;
}

_public_ int sd_bus_is_server(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->is_server;
}

_public_ int sd_bus_is_anonymous(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->anonymous_auth;
}

_public_ int sd_bus_is_trusted(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return bus->trusted;
}

_public_ int sd_bus_is_monitor(sd_bus *bus) {
        assert_return(bus, -EINVAL);
        assert_return(!bus_pid_changed(bus), -ECHILD);

        return !!(bus->hello_flags & KDBUS_HELLO_MONITOR);
}
