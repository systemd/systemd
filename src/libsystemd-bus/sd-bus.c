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
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/poll.h>
#include <byteswap.h>

#include "util.h"
#include "macro.h"
#include "missing.h"
#include "strv.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-type.h"

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec);

static void bus_free(sd_bus *b) {
        struct filter_callback *f;
        struct object_callback *c;
        unsigned i;

        assert(b);

        if (b->fd >= 0)
                close_nointr_nofail(b->fd);

        free(b->rbuffer);
        free(b->unique_name);
        free(b->auth_uid);
        free(b->address);

        free(b->exec_path);
        strv_free(b->exec_argv);

        close_many(b->fds, b->n_fds);
        free(b->fds);

        for (i = 0; i < b->rqueue_size; i++)
                sd_bus_message_unref(b->rqueue[i]);
        free(b->rqueue);

        for (i = 0; i < b->wqueue_size; i++)
                sd_bus_message_unref(b->wqueue[i]);
        free(b->wqueue);

        hashmap_free_free(b->reply_callbacks);
        prioq_free(b->reply_callbacks_prioq);

        while ((f = b->filter_callbacks)) {
                LIST_REMOVE(struct filter_callback, callbacks, b->filter_callbacks, f);
                free(f);
        }

        while ((c = hashmap_steal_first(b->object_callbacks))) {
                free(c->path);
                free(c);
        }

        hashmap_free(b->object_callbacks);

        free(b);
}

int sd_bus_new(sd_bus **ret) {
        sd_bus *r;

        if (!ret)
                return -EINVAL;

        r = new0(sd_bus, 1);
        if (!r)
                return -ENOMEM;

        r->n_ref = 1;
        r->fd = -1;
        r->message_version = 1;
        r->negotiate_fds = true;

        /* We guarantee that wqueue always has space for at least one
         * entry */
        r->wqueue = new(sd_bus_message*, 1);
        if (!r->wqueue) {
                free(r);
                return -ENOMEM;
        }

        *ret = r;
        return 0;
}

int sd_bus_set_address(sd_bus *bus, const char *address) {
        char *a;

        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;
        if (!address)
                return -EINVAL;

        a = strdup(address);
        if (!a)
                return -ENOMEM;

        free(bus->address);
        bus->address = a;

        return 0;
}

int sd_bus_set_fd(sd_bus *bus, int fd) {
        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;
        if (fd < 0)
                return -EINVAL;

        bus->fd = fd;
        return 0;
}

int sd_bus_set_exec(sd_bus *bus, const char *path, char *const argv[]) {
        char *p, **a;

        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;
        if (!path)
                return -EINVAL;
        if (strv_isempty(argv))
                return -EINVAL;

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

int sd_bus_set_hello(sd_bus *bus, int b) {
        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;

        bus->send_hello = !!b;
        return 0;
}

int sd_bus_set_negotiate_fds(sd_bus *bus, int b) {
        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;

        bus->negotiate_fds = !!b;
        return 0;
}

static int hello_callback(sd_bus *bus, int error, sd_bus_message *reply, void *userdata) {
        const char *s;
        int r;

        assert(bus);
        assert(bus->state == BUS_HELLO);

        if (error != 0)
                return -error;

        assert(reply);

        r = sd_bus_message_read(reply, "s", &s);
        if (r < 0)
                return r;

        if (!service_name_is_valid(s) || s[0] != ':')
                return -EBADMSG;

        bus->unique_name = strdup(s);
        if (!bus->unique_name)
                return -ENOMEM;

        bus->state = BUS_RUNNING;

        return 1;
}

static int bus_send_hello(sd_bus *bus) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        int r;

        assert(bus);

        if (!bus->send_hello)
                return 0;

        r = sd_bus_message_new_method_call(
                        bus,
                        "org.freedesktop.DBus",
                        "/",
                        "org.freedesktop.DBus",
                        "Hello",
                        &m);
        if (r < 0)
                return r;

        r = sd_bus_send_with_reply(bus, m, hello_callback, NULL, 0, NULL);
        if (r < 0)
                return r;

        return r;
}

static int bus_start_running(sd_bus *bus) {
        assert(bus);

        if (bus->send_hello) {
                bus->state = BUS_HELLO;
                return 1;
        }

        bus->state = BUS_RUNNING;
        return 1;
}

static int parse_address_key(const char **p, const char *key, char **value) {
        size_t l, n = 0;
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
                char c, *t;

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

                t = realloc(r, n + 2);
                if (!t) {
                        free(r);
                        return -ENOMEM;
                }

                r = t;
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
        struct addrinfo hints, *result;
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

        zero(hints);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ADDRCONFIG;

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
                        if (errno != 0 || **p != '=' || ul > 256) {
                                r = -EINVAL;
                                goto fail;
                        }

                        (*p) ++;

                        if (ul >= n_argv) {
                                char **x;

                                x = realloc(argv, sizeof(char*) * (ul + 2));
                                if (!x) {
                                        r = -ENOMEM;
                                        goto fail;
                                }

                                memset(x + n_argv, 0, sizeof(char*) * (ul - n_argv + 2));

                                argv = x;
                                n_argv = ul + 1;
                        }

                        r = parse_address_key(p, NULL, argv + ul);
                        if (r < 0)
                                goto fail;

                        continue;
                }

                skip_address_key(p);
        }

        if (!path)
                goto fail;

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

static void bus_reset_parsed_address(sd_bus *b) {
        assert(b);

        zero(b->sockaddr);
        b->sockaddr_size = 0;
        strv_free(b->exec_argv);
        free(b->exec_path);
        b->exec_path = NULL;
        b->exec_argv = NULL;
        b->peer = SD_ID128_NULL;
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

                }

                a = strchr(a, ';');
                if (!a)
                        return 0;
        }

        if (guid) {
                r = sd_id128_from_string(guid, &b->peer);
                if (r < 0)
                        return r;
        }

        b->address_index = a - b->address;
        return 1;
}

static void iovec_advance(struct iovec *iov, unsigned *idx, size_t size) {

        while (size > 0) {
                struct iovec *i = iov + *idx;

                if (i->iov_len > size) {
                        i->iov_base = (uint8_t*) i->iov_base + size;
                        i->iov_len -= size;
                        return;
                }

                size -= i->iov_len;

                i->iov_base = NULL;
                i->iov_len = 0;

                (*idx) ++;
        }
}

static int bus_write_auth(sd_bus *b) {
        struct msghdr mh;
        ssize_t k;

        assert(b);
        assert(b->state == BUS_AUTHENTICATING);

        if (b->auth_index >= ELEMENTSOF(b->auth_iovec))
                return 0;

        if (b->auth_timeout == 0)
                b->auth_timeout = now(CLOCK_MONOTONIC) + BUS_DEFAULT_TIMEOUT;

        zero(mh);
        mh.msg_iov = b->auth_iovec + b->auth_index;
        mh.msg_iovlen = ELEMENTSOF(b->auth_iovec) - b->auth_index;

        k = sendmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        iovec_advance(b->auth_iovec, &b->auth_index, (size_t) k);

        return 1;
}

static int bus_auth_verify(sd_bus *b) {
        char *e, *f, *start;
        sd_id128_t peer;
        unsigned i;
        int r;

        /* We expect two response lines: "OK" and possibly
         * "AGREE_UNIX_FD" */

        e = memmem(b->rbuffer, b->rbuffer_size, "\r\n", 2);
        if (!e)
                return 0;

        if (b->negotiate_fds) {
                f = memmem(e + 2, b->rbuffer_size - (e - (char*) b->rbuffer) - 2, "\r\n", 2);
                if (!f)
                        return 0;

                start = f + 2;
        } else {
                f = NULL;
                start = e + 2;
        }

        /* Nice! We got all the lines we need. First check the OK
         * line */

        if (e - (char*) b->rbuffer != 3 + 32)
                return -EPERM;

        if (memcmp(b->rbuffer, "OK ", 3))
                return -EPERM;

        for (i = 0; i < 32; i += 2) {
                int x, y;

                x = unhexchar(((char*) b->rbuffer)[3 + i]);
                y = unhexchar(((char*) b->rbuffer)[3 + i + 1]);

                if (x < 0 || y < 0)
                        return -EINVAL;

                peer.bytes[i/2] = ((uint8_t) x << 4 | (uint8_t) y);
        }

        if (!sd_id128_equal(b->peer, SD_ID128_NULL) &&
            !sd_id128_equal(b->peer, peer))
                return -EPERM;

        b->peer = peer;

        /* And possibly check the second line, too */

        if (f)
                b->can_fds =
                        (f - e == sizeof("\r\nAGREE_UNIX_FD") - 1) &&
                        memcmp(e + 2, "AGREE_UNIX_FD", sizeof("AGREE_UNIX_FD") - 1) == 0;

        b->rbuffer_size -= (start - (char*) b->rbuffer);
        memmove(b->rbuffer, start, b->rbuffer_size);

        r = bus_start_running(b);
        if (r < 0)
                return r;

        return 1;
}

static int bus_read_auth(sd_bus *b) {
        struct msghdr mh;
        struct iovec iov;
        size_t n;
        ssize_t k;
        int r;
        void *p;

        assert(b);

        r = bus_auth_verify(b);
        if (r != 0)
                return r;

        n = MAX(3 + 32 + 2 + sizeof("AGREE_UNIX_FD") - 1 + 2, b->rbuffer_size * 2);

        if (n > BUS_AUTH_SIZE_MAX)
                n = BUS_AUTH_SIZE_MAX;

        if (b->rbuffer_size >= n)
                return -ENOBUFS;

        p = realloc(b->rbuffer, n);
        if (!p)
                return -ENOMEM;

        b->rbuffer = p;

        zero(iov);
        iov.iov_base = (uint8_t*) b->rbuffer + b->rbuffer_size;
        iov.iov_len = n - b->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

        k = recvmsg(b->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        b->rbuffer_size += k;

        r = bus_auth_verify(b);
        if (r != 0)
                return r;

        return 1;
}

static int bus_setup_fd(sd_bus *b) {
        int one;

        assert(b);

        /* Enable SO_PASSCRED + SO_PASSEC. We try this on any socket,
         * just in case. This is actually irrelavant for */
        one = 1;
        setsockopt(b->fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        setsockopt(b->fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));

        /* Increase the buffers to a MB */
        fd_inc_rcvbuf(b->fd, 1024*1024);
        fd_inc_sndbuf(b->fd, 1024*1024);

        return 0;
}

static int bus_start_auth(sd_bus *b) {
        static const char auth_prefix[] = "\0AUTH EXTERNAL ";
        static const char auth_suffix_with_unix_fd[] = "\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
        static const char auth_suffix_without_unix_fd[] = "\r\nBEGIN\r\n";

        char text[20 + 1]; /* enough space for a 64bit integer plus NUL */
        size_t l;
        const char *auth_suffix;
        int domain = 0, r;
        socklen_t sl;

        assert(b);

        b->state = BUS_AUTHENTICATING;

        sl = sizeof(domain);
        r = getsockopt(b->fd, SOL_SOCKET, SO_DOMAIN, &domain, &sl);
        if (r < 0)
                return -errno;

        if (domain != AF_UNIX)
                b->negotiate_fds = false;

        snprintf(text, sizeof(text), "%llu", (unsigned long long) geteuid());
        char_array_0(text);

        l = strlen(text);
        b->auth_uid = hexmem(text, l);
        if (!b->auth_uid)
                return -ENOMEM;

        auth_suffix = b->negotiate_fds ? auth_suffix_with_unix_fd : auth_suffix_without_unix_fd;

        b->auth_iovec[0].iov_base = (void*) auth_prefix;
        b->auth_iovec[0].iov_len = sizeof(auth_prefix) -1;
        b->auth_iovec[1].iov_base = (void*) b->auth_uid;
        b->auth_iovec[1].iov_len = l * 2;
        b->auth_iovec[2].iov_base = (void*) auth_suffix;
        b->auth_iovec[2].iov_len = strlen(auth_suffix);
        b->auth_size = sizeof(auth_prefix) - 1 + l * 2 + sizeof(auth_suffix) - 1;

        return bus_write_auth(b);
}

static int bus_connect(sd_bus *b) {
        int r;

        assert(b);
        assert(b->fd < 0);
        assert(b->sockaddr.sa.sa_family != AF_UNSPEC);

        b->fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->fd < 0)
                return -errno;

        r = bus_setup_fd(b);
        if (r < 0)
                return r;

        r = connect(b->fd, &b->sockaddr.sa, b->sockaddr_size);
        if (r < 0) {
                if (errno == EINPROGRESS)
                        return 1;

                return -errno;
        }

        return bus_start_auth(b);
}

static int bus_exec(sd_bus *b) {
        int s[2];
        pid_t pid;

        assert(b);
        assert(b->fd < 0);
        assert(b->exec_path);

        b->fd = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, s);
        if (b->fd < 0)
                return -errno;

        pid = fork();
        if (pid < 0) {
                close_pipe(s);
                return -errno;
        }
        if (pid == 0) {
                /* Child */

                close_all_fds(s, 2);
                close_nointr_nofail(s[0]);

                assert_se(dup3(s[1], STDIN_FILENO, 0) == STDIN_FILENO);
                assert_se(dup3(s[1], STDOUT_FILENO, 0) == STDOUT_FILENO);

                if (s[1] != STDIN_FILENO && s[1] != STDOUT_FILENO)
                        close_nointr_nofail(s[1]);

                fd_cloexec(STDIN_FILENO, false);
                fd_cloexec(STDOUT_FILENO, false);
                fd_nonblock(STDIN_FILENO, false);
                fd_nonblock(STDOUT_FILENO, false);

                if (b->exec_argv)
                        execvp(b->exec_path, b->exec_argv);
                else {
                        const char *argv[] = { b->exec_path, NULL };
                        execvp(b->exec_path, (char**) argv);
                }

                _exit(EXIT_FAILURE);
        }

        close_nointr_nofail(s[1]);
        b->fd = s[0];

        return bus_start_auth(b);
}

static int bus_start_connect(sd_bus *b) {
        int r;

        assert(b);

        for (;;) {
                if (b->fd >= 0) {
                        close_nointr_nofail(b->fd);
                        b->fd = -1;
                }

                if (b->sockaddr.sa.sa_family != AF_UNSPEC) {
                        r = bus_connect(b);
                        if (r >= 0)
                                return r;

                        b->last_connect_error = -r;

                } else if (b->exec_path) {

                        r = bus_exec(b);
                        if (r >= 0)
                                return r;

                        b->last_connect_error = -r;
                }

                r = bus_parse_next_address(b);
                if (r < 0)
                        return r;
                if (r == 0)
                        return b->last_connect_error ? -b->last_connect_error : -ECONNREFUSED;
        }
}

static int bus_start_fd(sd_bus *b) {
        int r;

        assert(b);

        r = fd_nonblock(b->fd, true);
        if (r < 0)
                return r;

        r = fd_cloexec(b->fd, true);
        if (r < 0)
                return r;

        r = bus_setup_fd(b);
        if (r < 0)
                return r;

        return bus_start_auth(b);
}

int sd_bus_start(sd_bus *bus) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->state != BUS_UNSET)
                return -EPERM;

        bus->state = BUS_OPENING;

        if (bus->fd >= 0)
                r = bus_start_fd(bus);
        else if (bus->address)
                r = bus_start_connect(bus);
        else
                return -EINVAL;

        if (r < 0)
                return r;

        return bus_send_hello(bus);
}

int sd_bus_open_system(sd_bus **ret) {
        const char *e;
        sd_bus *b;
        int r;

        if (!ret)
                return -EINVAL;

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        e = getenv("DBUS_SYSTEM_BUS_ADDRESS");
        if (e) {
                r = sd_bus_set_address(b, e);
                if (r < 0)
                        goto fail;
        } else {
                b->sockaddr.un.sun_family = AF_UNIX;
                strncpy(b->sockaddr.un.sun_path, "/run/dbus/system_bus_socket", sizeof(b->sockaddr.un.sun_path));
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + sizeof("/run/dbus/system_bus_socket") - 1;
        }

        b->send_hello = true;

        r = sd_bus_start(b);
        if (r < 0)
                goto fail;

        *ret = b;
        return 0;

fail:
        bus_free(b);
        return r;
}

int sd_bus_open_user(sd_bus **ret) {
        const char *e;
        sd_bus *b;
        size_t l;
        int r;

        if (!ret)
                return -EINVAL;

        r = sd_bus_new(&b);
        if (r < 0)
                return r;

        e = getenv("DBUS_SESSION_BUS_ADDRESS");
        if (e) {
                r = sd_bus_set_address(b, e);
                if (r < 0)
                        goto fail;
        } else {
                e = getenv("XDG_RUNTIME_DIR");
                if (!e) {
                        r = -ENOENT;
                        goto fail;
                }

                l = strlen(e);
                if (l + 4 > sizeof(b->sockaddr.un.sun_path)) {
                        r = -E2BIG;
                        goto fail;
                }

                b->sockaddr.un.sun_family = AF_UNIX;
                memcpy(mempcpy(b->sockaddr.un.sun_path, e, l), "/bus", 4);
                b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l + 4;
        }

        b->send_hello = true;

        r = sd_bus_start(b);
        if (r < 0)
                goto fail;

        *ret = b;
        return 0;

fail:
        bus_free(b);
        return r;
}

void sd_bus_close(sd_bus *bus) {
        if (!bus)
                return;
        if (bus->fd < 0)
                return;

        close_nointr_nofail(bus->fd);
        bus->fd = -1;
}

sd_bus *sd_bus_ref(sd_bus *bus) {
        if (!bus)
                return NULL;

        assert(bus->n_ref > 0);

        bus->n_ref++;
        return bus;
}

sd_bus *sd_bus_unref(sd_bus *bus) {
        if (!bus)
                return NULL;

        assert(bus->n_ref > 0);
        bus->n_ref--;

        if (bus->n_ref <= 0)
                bus_free(bus);

        return NULL;
}

int sd_bus_is_open(sd_bus *bus) {
        if (!bus)
                return -EINVAL;

        return bus->state != BUS_UNSET && bus->fd >= 0;
}

int sd_bus_can_send(sd_bus *bus, char type) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (type == SD_BUS_TYPE_UNIX_FD) {
                if (!bus->negotiate_fds)
                        return 0;

                r = bus_ensure_running(bus);
                if (r < 0)
                        return r;

                return bus->can_fds;
        }

        return bus_type_is_valid(type);
}

int sd_bus_get_peer(sd_bus *bus, sd_id128_t *peer) {
        int r;

        if (!bus)
                return -EINVAL;
        if (!peer)
                return -EINVAL;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        *peer = bus->peer;
        return 0;
}

static int bus_seal_message(sd_bus *b, sd_bus_message *m) {
        assert(m);

        if (m->header->version > b->message_version)
                return -EPERM;

        if (m->sealed)
                return 0;

        return bus_message_seal(m, ++b->serial);
}

static int message_write(sd_bus *bus, sd_bus_message *m, size_t *idx) {
        struct msghdr mh;
        struct iovec *iov;
        ssize_t k;
        size_t n;
        unsigned j;

        assert(bus);
        assert(m);
        assert(idx);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (*idx >= m->size)
                return 0;
        zero(mh);

        if (m->n_fds > 0) {
                struct cmsghdr *control;
                control = alloca(CMSG_SPACE(sizeof(int) * m->n_fds));

                mh.msg_control = control;
                control->cmsg_level = SOL_SOCKET;
                control->cmsg_type = SCM_RIGHTS;
                mh.msg_controllen = control->cmsg_len = CMSG_LEN(sizeof(int) * m->n_fds);
                memcpy(CMSG_DATA(control), m->fds, sizeof(int) * m->n_fds);
        }

        n = m->n_iovec * sizeof(struct iovec);
        iov = alloca(n);
        memcpy(iov, m->iovec, n);

        j = 0;
        iovec_advance(iov, &j, *idx);

        mh.msg_iov = iov;
        mh.msg_iovlen = m->n_iovec;

        k = sendmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;

        *idx += (size_t) k;
        return 1;
}

static int message_read_need(sd_bus *bus, size_t *need) {
        uint32_t a, b;
        uint8_t e;
        uint64_t sum;

        assert(bus);
        assert(need);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->rbuffer_size < sizeof(struct bus_header)) {
                *need = sizeof(struct bus_header) + 8;

                /* Minimum message size:
                 *
                 * Header +
                 *
                 *  Method Call: +2 string headers
                 *       Signal: +3 string headers
                 * Method Error: +1 string headers
                 *               +1 uint32 headers
                 * Method Reply: +1 uint32 headers
                 *
                 * A string header is at least 9 bytes
                 * A uint32 header is at least 8 bytes
                 *
                 * Hence the minimum message size of a valid message
                 * is header + 8 bytes */

                return 0;
        }

        a = ((const uint32_t*) bus->rbuffer)[1];
        b = ((const uint32_t*) bus->rbuffer)[3];

        e = ((const uint8_t*) bus->rbuffer)[0];
        if (e == SD_BUS_LITTLE_ENDIAN) {
                a = le32toh(a);
                b = le32toh(b);
        } else if (e == SD_BUS_BIG_ENDIAN) {
                a = be32toh(a);
                b = be32toh(b);
        } else
                return -EBADMSG;

        sum = (uint64_t) sizeof(struct bus_header) + (uint64_t) ALIGN_TO(b, 8) + (uint64_t) a;
        if (sum >= BUS_MESSAGE_SIZE_MAX)
                return -ENOBUFS;

        *need = (size_t) sum;
        return 0;
}

static int message_make(sd_bus *bus, size_t size, sd_bus_message **m) {
        sd_bus_message *t;
        void *b;
        int r;

        assert(bus);
        assert(m);
        assert(bus->rbuffer_size >= size);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->rbuffer_size > size) {
                b = memdup((const uint8_t*) bus->rbuffer + size,
                           bus->rbuffer_size - size);
                if (!b)
                        return -ENOMEM;
        } else
                b = NULL;

        r = bus_message_from_malloc(bus->rbuffer, size,
                                    bus->fds, bus->n_fds,
                                    bus->ucred_valid ? &bus->ucred : NULL,
                                    bus->label[0] ? bus->label : NULL,
                                    &t);
        if (r < 0) {
                free(b);
                return r;
        }

        bus->rbuffer = b;
        bus->rbuffer_size -= size;

        bus->fds = NULL;
        bus->n_fds = 0;

        *m = t;
        return 1;
}

static int message_read(sd_bus *bus, sd_bus_message **m) {
        struct msghdr mh;
        struct iovec iov;
        ssize_t k;
        size_t need;
        int r;
        void *b;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int) * BUS_FDS_MAX) +
                            CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(NAME_MAX)]; /*selinux label */
        } control;
        struct cmsghdr *cmsg;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        r = message_read_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return message_make(bus, need, m);

        b = realloc(bus->rbuffer, need);
        if (!b)
                return -ENOMEM;

        bus->rbuffer = b;

        zero(iov);
        iov.iov_base = (uint8_t*) bus->rbuffer + bus->rbuffer_size;
        iov.iov_len = need - bus->rbuffer_size;

        zero(mh);
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = &control;
        mh.msg_controllen = sizeof(control);

        k = recvmsg(bus->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL|MSG_CMSG_CLOEXEC);
        if (k < 0)
                return errno == EAGAIN ? 0 : -errno;
        if (k == 0)
                return -ECONNRESET;

        bus->rbuffer_size += k;

        for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                        int n, *f;

                        n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

                        f = realloc(bus->fds, sizeof(int) + (bus->n_fds + n));
                        if (!f) {
                                close_many((int*) CMSG_DATA(cmsg), n);
                                return -ENOMEM;
                        }

                        memcpy(f + bus->n_fds, CMSG_DATA(cmsg), n * sizeof(int));
                        bus->fds = f;
                        bus->n_fds += n;
                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_CREDENTIALS &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        memcpy(&bus->ucred, CMSG_DATA(cmsg), sizeof(struct ucred));
                        bus->ucred_valid = true;

                } else if (cmsg->cmsg_level == SOL_SOCKET &&
                         cmsg->cmsg_type == SCM_SECURITY) {

                        size_t l;
                        l = cmsg->cmsg_len - CMSG_LEN(0);
                        memcpy(&bus->label, CMSG_DATA(cmsg), l);
                        bus->label[l] = 0;
                }
        }

        r = message_read_need(bus, &need);
        if (r < 0)
                return r;

        if (bus->rbuffer_size >= need)
                return message_make(bus, need, m);

        return 1;
}

static int dispatch_wqueue(sd_bus *bus) {
        int r, ret = 0;

        assert(bus);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->fd < 0)
                return -ENOTCONN;

        while (bus->wqueue_size > 0) {

                r = message_write(bus, bus->wqueue[0], &bus->windex);
                if (r < 0) {
                        sd_bus_close(bus);
                        return r;
                } else if (r == 0)
                        /* Didn't do anything this time */
                        return ret;
                else if (bus->windex >= bus->wqueue[0]->size) {
                        /* Fully written. Let's drop the entry from
                         * the queue.
                         *
                         * This isn't particularly optimized, but
                         * well, this is supposed to be our worst-case
                         * buffer only, and the socket buffer is
                         * supposed to be our primary buffer, and if
                         * it got full, then all bets are off
                         * anyway. */

                        sd_bus_message_unref(bus->wqueue[0]);
                        bus->wqueue_size --;
                        memmove(bus->wqueue, bus->wqueue + 1, sizeof(sd_bus_message*) * bus->wqueue_size);
                        bus->windex = 0;

                        ret = 1;
                }
        }

        return ret;
}

static int dispatch_rqueue(sd_bus *bus, sd_bus_message **m) {
        sd_bus_message *z = NULL;
        int r, ret = 0;

        assert(bus);
        assert(m);
        assert(bus->state == BUS_RUNNING || bus->state == BUS_HELLO);

        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->rqueue_size > 0) {
                /* Dispatch a queued message */

                *m = bus->rqueue[0];
                bus->rqueue_size --;
                memmove(bus->rqueue, bus->rqueue + 1, sizeof(sd_bus_message*) * bus->rqueue_size);
                return 1;
        }

        /* Try to read a new message */
        do {
                r = message_read(bus, &z);
                if (r < 0) {
                        sd_bus_close(bus);
                        return r;
                }
                if (r == 0)
                        return ret;

                r = 1;
        } while (!z);

        *m = z;
        return 1;
}

int sd_bus_send(sd_bus *bus, sd_bus_message *m, uint64_t *serial) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;

        if (m->n_fds > 0) {
                r = sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOTSUP;
        }

        /* If the serial number isn't kept, then we know that no reply
         * is expected */
        if (!serial && !m->sealed)
                m->header->flags |= SD_BUS_MESSAGE_NO_REPLY_EXPECTED;

        r = bus_seal_message(bus, m);
        if (r < 0)
                return r;

        /* If this is a reply and no reply was requested, then let's
         * suppress this, if we can */
        if (m->dont_send && !serial)
                return 0;

        if ((bus->state == BUS_RUNNING || bus->state == BUS_HELLO) && bus->wqueue_size <= 0) {
                size_t idx = 0;

                r = message_write(bus, m, &idx);
                if (r < 0) {
                        sd_bus_close(bus);
                        return r;
                } else if (idx < m->size)  {
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
                sd_bus_message **q;

                /* Just append it to the queue. */

                if (bus->wqueue_size >= BUS_WQUEUE_MAX)
                        return -ENOBUFS;

                q = realloc(bus->wqueue, sizeof(sd_bus_message*) * (bus->wqueue_size + 1));
                if (!q)
                        return -ENOMEM;

                bus->wqueue = q;
                q[bus->wqueue_size ++] = sd_bus_message_ref(m);
        }

        if (serial)
                *serial = BUS_MESSAGE_SERIAL(m);

        return 0;
}

static usec_t calc_elapse(uint64_t usec) {
        if (usec == (uint64_t) -1)
                return 0;

        if (usec == 0)
                usec = BUS_DEFAULT_TIMEOUT;

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

int sd_bus_send_with_reply(
                sd_bus *bus,
                sd_bus_message *m,
                sd_message_handler_t callback,
                void *userdata,
                uint64_t usec,
                uint64_t *serial) {

        struct reply_callback *c;
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;
        if (!callback)
                return -EINVAL;
        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED)
                return -EINVAL;

        r = hashmap_ensure_allocated(&bus->reply_callbacks, uint64_hash_func, uint64_compare_func);
        if (r < 0)
                return r;

        if (usec != (uint64_t) -1) {
                r = prioq_ensure_allocated(&bus->reply_callbacks_prioq, timeout_compare);
                if (r < 0)
                        return r;
        }

        r = bus_seal_message(bus, m);
        if (r < 0)
                return r;

        c = new(struct reply_callback, 1);
        if (!c)
                return -ENOMEM;

        c->callback = callback;
        c->userdata = userdata;
        c->serial = BUS_MESSAGE_SERIAL(m);
        c->timeout = calc_elapse(usec);

        r = hashmap_put(bus->reply_callbacks, &c->serial, c);
        if (r < 0) {
                free(c);
                return r;
        }

        if (c->timeout != 0) {
                r = prioq_put(bus->reply_callbacks_prioq, c, &c->prioq_idx);
                if (r < 0) {
                        c->timeout = 0;
                        sd_bus_send_with_reply_cancel(bus, c->serial);
                        return r;
                }
        }

        r = sd_bus_send(bus, m, serial);
        if (r < 0) {
                sd_bus_send_with_reply_cancel(bus, c->serial);
                return r;
        }

        return r;
}

int sd_bus_send_with_reply_cancel(sd_bus *bus, uint64_t serial) {
        struct reply_callback *c;

        if (!bus)
                return -EINVAL;
        if (serial == 0)
                return -EINVAL;

        c = hashmap_remove(bus->reply_callbacks, &serial);
        if (!c)
                return 0;

        if (c->timeout != 0)
                prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);

        free(c);
        return 1;
}

int bus_ensure_running(sd_bus *bus) {
        int r;

        assert(bus);

        if (bus->fd < 0)
                return -ENOTCONN;
        if (bus->state == BUS_UNSET)
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

int sd_bus_send_with_reply_and_block(
                sd_bus *bus,
                sd_bus_message *m,
                uint64_t usec,
                sd_bus_error *error,
                sd_bus_message **reply) {

        int r;
        usec_t timeout;
        uint64_t serial;
        bool room = false;

        if (!bus)
                return -EINVAL;
        if (bus->fd < 0)
                return -ENOTCONN;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (!m)
                return -EINVAL;
        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return -EINVAL;
        if (m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED)
                return -EINVAL;
        if (bus_error_is_dirty(error))
                return -EINVAL;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, m, &serial);
        if (r < 0)
                return r;

        timeout = calc_elapse(usec);

        for (;;) {
                usec_t left;
                sd_bus_message *incoming = NULL;

                if (!room) {
                        sd_bus_message **q;

                        if (bus->rqueue_size >= BUS_RQUEUE_MAX)
                                return -ENOBUFS;

                        /* Make sure there's room for queuing this
                         * locally, before we read the message */

                        q = realloc(bus->rqueue, (bus->rqueue_size + 1) * sizeof(sd_bus_message*));
                        if (!q)
                                return -ENOMEM;

                        bus->rqueue = q;
                        room = true;
                }

                r = message_read(bus, &incoming);
                if (r < 0)
                        return r;
                if (incoming) {

                        if (incoming->reply_serial == serial) {
                                /* Found a match! */

                                if (incoming->header->type == SD_BUS_MESSAGE_TYPE_METHOD_RETURN) {
                                        *reply = incoming;
                                        return 0;
                                }

                                if (incoming->header->type == SD_BUS_MESSAGE_TYPE_METHOD_ERROR) {
                                        int k;

                                        r = sd_bus_error_copy(error, &incoming->error);
                                        if (r < 0) {
                                                sd_bus_message_unref(incoming);
                                                return r;
                                        }

                                        k = bus_error_to_errno(&incoming->error);
                                        sd_bus_message_unref(incoming);
                                        return k;
                                }

                                sd_bus_message_unref(incoming);
                                return -EIO;
                        }

                        /* There's already guaranteed to be room for
                         * this, so need to resize things here */
                        bus->rqueue[bus->rqueue_size ++] = incoming;
                        room = false;

                        /* Try to read more, right-away */
                        continue;
                }
                if (r != 0)
                        continue;

                if (timeout > 0) {
                        usec_t n;

                        n = now(CLOCK_MONOTONIC);
                        if (n >= timeout)
                                return -ETIMEDOUT;

                        left = timeout - n;
                } else
                        left = (uint64_t) -1;

                r = bus_poll(bus, true, left);
                if (r < 0)
                        return r;

                r = dispatch_wqueue(bus);
                if (r < 0)
                        return r;
        }
}

int sd_bus_get_fd(sd_bus *bus) {
        if (!bus)
                return -EINVAL;

        if (bus->fd < 0)
                return -ENOTCONN;

        return bus->fd;
}

int sd_bus_get_events(sd_bus *bus) {
        int flags = 0;

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->state == BUS_OPENING)
                flags |= POLLOUT;
        else if (bus->state == BUS_AUTHENTICATING) {

                if (bus->auth_index < ELEMENTSOF(bus->auth_iovec))
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

int sd_bus_get_timeout(sd_bus *bus, uint64_t *timeout_usec) {
        struct reply_callback *c;

        if (!bus)
                return -EINVAL;
        if (!timeout_usec)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->state == BUS_AUTHENTICATING) {
                *timeout_usec = bus->auth_timeout;
                return 1;
        }

        if (bus->state != BUS_RUNNING && bus->state != BUS_HELLO)
                return 0;

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c)
                return 0;

        *timeout_usec = c->timeout;
        return 1;
}

static int process_timeout(sd_bus *bus) {
        struct reply_callback *c;
        usec_t n;
        int r;

        assert(bus);

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c)
                return 0;

        n = now(CLOCK_MONOTONIC);
        if (c->timeout > n)
                return 0;

        assert_se(prioq_pop(bus->reply_callbacks_prioq) == c);
        hashmap_remove(bus->reply_callbacks, &c->serial);

        r = c->callback(bus, ETIMEDOUT, NULL, c->userdata);
        free(c);

        return r < 0 ? r : 1;
}

static int process_reply(sd_bus *bus, sd_bus_message *m) {
        struct reply_callback *c;
        int r;

        assert(bus);
        assert(m);

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_RETURN &&
            m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_ERROR)
                return 0;

        c = hashmap_remove(bus->reply_callbacks, &m->reply_serial);
        if (!c)
                return 0;

        if (c->timeout != 0)
                prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);

        r = c->callback(bus, 0, m, c->userdata);
        free(c);

        return r;
}

static int process_filter(sd_bus *bus, sd_bus_message *m) {
        struct filter_callback *l;
        int r;

        LIST_FOREACH(callbacks, l, bus->filter_callbacks) {
                r = l->callback(bus, 0, m, l->userdata);
                if (r != 0)
                        return r;
        }

        return 0;
}

static int process_builtin(sd_bus *bus, sd_bus_message *m) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(m);

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return 0;

        if (!streq_ptr(m->interface, "org.freedesktop.DBus.Peer"))
                return 0;

        if (m->header->flags & SD_BUS_MESSAGE_NO_REPLY_EXPECTED)
                return 1;

        if (streq_ptr(m->member, "Ping"))
                r = sd_bus_message_new_method_return(bus, m, &reply);
        else if (streq_ptr(m->member, "GetMachineId")) {
                sd_id128_t id;
                char sid[33];

                r = sd_id128_get_machine(&id);
                if (r < 0)
                        return r;

                r = sd_bus_message_new_method_return(bus, m, &reply);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(reply, "s", sd_id128_to_string(id, sid));
        } else {
                _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_INIT;

                sd_bus_error_set(&error,
                                 "org.freedesktop.DBus.Error.UnknownMethod",
                                 "Unknown method '%s' on interface '%s'.", m->member, m->interface);

                r = sd_bus_message_new_method_error(bus, m, &error, &reply);
        }

        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int process_object(sd_bus *bus, sd_bus_message *m) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_INIT;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        struct object_callback *c;
        char *p;
        int r;
        bool found = false;

        assert(bus);
        assert(m);

        if (m->header->type != SD_BUS_MESSAGE_TYPE_METHOD_CALL)
                return 0;

        if (hashmap_isempty(bus->object_callbacks))
                return 0;

        c = hashmap_get(bus->object_callbacks, m->path);
        if (c) {
                r = c->callback(bus, 0, m, c->userdata);
                if (r != 0)
                        return r;

                found = true;
        }

        /* Look for fallback prefixes */
        p = strdupa(m->path);
        for (;;) {
                char *e;

                e = strrchr(p, '/');
                if (e == p || !e)
                        break;

                *e = 0;

                c = hashmap_get(bus->object_callbacks, p);
                if (c && c->is_fallback) {
                        r = c->callback(bus, 0, m, c->userdata);
                        if (r != 0)
                                return r;

                        found = true;
                }
        }

        if (!found)
                return 0;

        sd_bus_error_set(&error,
                         "org.freedesktop.DBus.Error.UnknownMethod",
                         "Unknown method '%s' or interface '%s'.", m->member, m->interface);

        r = sd_bus_message_new_method_error(bus, m, &error, &reply);
        if (r < 0)
                return r;

        r = sd_bus_send(bus, reply, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int process_message(sd_bus *bus, sd_bus_message *m) {
        int r;

        assert(bus);
        assert(m);

        r = process_reply(bus, m);
        if (r != 0)
                return r;

        r = process_filter(bus, m);
        if (r != 0)
                return r;

        r = process_builtin(bus, m);
        if (r != 0)
                return r;

        return process_object(bus, m);
}

int sd_bus_process(sd_bus *bus, sd_bus_message **ret) {
        int r;

        /* Returns 0 when we didn't do anything. This should cause the
         * caller to invoke sd_bus_wait() before returning the next
         * time. Returns > 0 when we did something, which possibly
         * means *ret is filled in with an unprocessed message. */

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;

        if (bus->state == BUS_OPENING) {
                struct pollfd p;

                zero(p);
                p.fd = bus->fd;
                p.events = POLLOUT;

                r = poll(&p, 1, 0);
                if (r < 0)
                        return -errno;

                if (p.revents & (POLLOUT|POLLERR|POLLHUP)) {
                        int error = 0;
                        socklen_t slen = sizeof(error);

                        r = getsockopt(bus->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                        if (r < 0)
                                bus->last_connect_error = errno;
                        else if (error != 0)
                                bus->last_connect_error = error;
                        else if (p.revents & (POLLERR|POLLHUP))
                                bus->last_connect_error = ECONNREFUSED;
                        else {
                                r = bus_start_auth(bus);
                                goto null_message;
                        }

                        /* Try next address */
                        bus_reset_parsed_address(bus);
                        r = bus_start_connect(bus);
                        goto null_message;
                }

                r = 0;
                goto null_message;

        } else if (bus->state == BUS_AUTHENTICATING) {

                if (now(CLOCK_MONOTONIC) >= bus->auth_timeout)
                        return -ETIMEDOUT;

                r = bus_write_auth(bus);
                if (r != 0)
                        goto null_message;

                r = bus_read_auth(bus);
                goto null_message;

        } else if (bus->state == BUS_RUNNING || bus->state == BUS_HELLO) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                int k;

                r = process_timeout(bus);
                if (r != 0)
                        goto null_message;

                r = dispatch_wqueue(bus);
                if (r != 0)
                        goto null_message;

                k = r;
                r = dispatch_rqueue(bus, &m);
                if (r < 0)
                        return r;
                if (!m) {
                        if (r == 0)
                                r = k;
                        goto null_message;
                }

                r = process_message(bus, m);
                if (r != 0)
                        goto null_message;

                if (ret) {
                        *ret = m;
                        m = NULL;
                        return 1;
                }

                if (m->header->type == SD_BUS_MESSAGE_TYPE_METHOD_CALL) {
                        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_INIT;

                        sd_bus_error_set(&error, "org.freedesktop.DBus.Error.UnknownObject", "Unknown object '%s'.", m->path);

                        r = sd_bus_message_new_method_error(bus, m, &error, &reply);
                        if (r < 0)
                                return r;

                        r = sd_bus_send(bus, reply, NULL);
                        if (r < 0)
                                return r;
                }

                return 1;
        }

        assert_not_reached("Unknown state");

null_message:
        if (r >= 0 && ret)
                *ret = NULL;

        return r;
}

static int bus_poll(sd_bus *bus, bool need_more, uint64_t timeout_usec) {
        struct pollfd p;
        int r, e;
        struct timespec ts;
        usec_t until, m;

        assert(bus);

        if (bus->fd < 0)
                return -ENOTCONN;

        e = sd_bus_get_events(bus);
        if (e < 0)
                return e;

        if (need_more)
                e |= POLLIN;

        r = sd_bus_get_timeout(bus, &until);
        if (r < 0)
                return r;
        if (r == 0)
                m = (uint64_t) -1;
        else {
                usec_t n;
                n = now(CLOCK_MONOTONIC);
                m = until > n ? until - n : 0;
        }

        if (timeout_usec != (uint64_t) -1 && (m == (uint64_t) -1 || timeout_usec < m))
                m = timeout_usec;

        zero(p);
        p.fd = bus->fd;
        p.events = e;

        r = ppoll(&p, 1, m == (uint64_t) -1 ? NULL : timespec_store(&ts, m), NULL);
        if (r < 0)
                return -errno;

        return r > 0 ? 1 : 0;
}

int sd_bus_wait(sd_bus *bus, uint64_t timeout_usec) {

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;
        if (bus->rqueue_size > 0)
                return 0;

        return bus_poll(bus, false, timeout_usec);
}

int sd_bus_flush(sd_bus *bus) {
        int r;

        if (!bus)
                return -EINVAL;
        if (bus->state == BUS_UNSET)
                return -ENOTCONN;
        if (bus->fd < 0)
                return -ENOTCONN;

        r = bus_ensure_running(bus);
        if (r < 0)
                return r;

        if (bus->wqueue_size <= 0)
                return 0;

        for (;;) {
                r = dispatch_wqueue(bus);
                if (r < 0)
                        return r;

                if (bus->wqueue_size <= 0)
                        return 0;

                r = bus_poll(bus, false, (uint64_t) -1);
                if (r < 0)
                        return r;
        }
}

int sd_bus_add_filter(sd_bus *bus, sd_message_handler_t callback, void *userdata) {
        struct filter_callback *f;

        if (!bus)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        f = new(struct filter_callback, 1);
        if (!f)
                return -ENOMEM;
        f->callback = callback;
        f->userdata = userdata;

        LIST_PREPEND(struct filter_callback, callbacks, bus->filter_callbacks, f);
        return 0;
}

int sd_bus_remove_filter(sd_bus *bus, sd_message_handler_t callback, void *userdata) {
        struct filter_callback *f;

        if (!bus)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        LIST_FOREACH(callbacks, f, bus->filter_callbacks) {
                if (f->callback == callback && f->userdata == userdata) {
                        LIST_REMOVE(struct filter_callback, callbacks, bus->filter_callbacks, f);
                        free(f);
                        return 1;
                }
        }

        return 0;
}

static int bus_add_object(
                sd_bus *bus,
                bool fallback,
                const char *path,
                sd_message_handler_t callback,
                void *userdata) {

        struct object_callback *c;
        int r;

        if (!bus)
                return -EINVAL;
        if (!path)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        r = hashmap_ensure_allocated(&bus->object_callbacks, string_hash_func, string_compare_func);
        if (r < 0)
                return r;

        c = new(struct object_callback, 1);
        if (!c)
                return -ENOMEM;

        c->path = strdup(path);
        if (!path) {
                free(c);
                return -ENOMEM;
        }

        c->callback = callback;
        c->userdata = userdata;
        c->is_fallback = fallback;

        r = hashmap_put(bus->object_callbacks, c->path, c);
        if (r < 0) {
                free(c->path);
                free(c);
                return r;
        }

        return 0;
}

static int bus_remove_object(
                sd_bus *bus,
                bool fallback,
                const char *path,
                sd_message_handler_t callback,
                void *userdata) {

        struct object_callback *c;

        if (!bus)
                return -EINVAL;
        if (!path)
                return -EINVAL;
        if (!callback)
                return -EINVAL;

        c = hashmap_get(bus->object_callbacks, path);
        if (!c)
                return 0;

        if (c->callback != callback || c->userdata != userdata || c->is_fallback != fallback)
                return 0;

        assert_se(c == hashmap_remove(bus->object_callbacks, c->path));

        free(c->path);
        free(c);

        return 1;
}

int sd_bus_add_object(sd_bus *bus, const char *path, sd_message_handler_t callback, void *userdata) {
        return bus_add_object(bus, false, path, callback, userdata);
}

int sd_bus_remove_object(sd_bus *bus, const char *path, sd_message_handler_t callback, void *userdata) {
        return bus_remove_object(bus, false, path, callback, userdata);
}

int sd_bus_add_fallback(sd_bus *bus, const char *prefix, sd_message_handler_t callback, void *userdata) {
        return bus_add_object(bus, true, prefix, callback, userdata);
}

int sd_bus_remove_fallback(sd_bus *bus, const char *prefix, sd_message_handler_t callback, void *userdata) {
        return bus_remove_object(bus, true, prefix, callback, userdata);
}
