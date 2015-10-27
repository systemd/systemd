/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
  Copyright 2014 Tom Gundersen

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

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/inotify.h>

#include "sd-network.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

_public_ int sd_network_get_operational_state(char **state) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(state, -EINVAL);

        r = parse_env_file("/run/systemd/netif/state", NEWLINE, "OPER_STATE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *state = s;
        s = NULL;

        return 0;
}

static int network_get_strv(const char *key, char ***ret) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ret, -EINVAL);

        r = parse_env_file("/run/systemd/netif/state", NEWLINE, key, &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = strv_length(a);

        *ret = a;
        a = NULL;

        return r;
}

_public_ int sd_network_get_dns(char ***ret) {
        return network_get_strv("DNS", ret);
}

_public_ int sd_network_get_ntp(char ***ret) {
        return network_get_strv("NTP", ret);
}

_public_ int sd_network_get_domains(char ***ret) {
        return network_get_strv("DOMAINS", ret);
}

_public_ int sd_network_link_get_setup_state(int ifindex, char **state) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(state, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "ADMIN_STATE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *state = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_link_get_network_file(int ifindex, char **filename) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(filename, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "NETWORK_FILE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *filename = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_link_get_operational_state(int ifindex, char **state) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(state, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "OPER_STATE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *state = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_link_get_llmnr(int ifindex, char **llmnr) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(llmnr, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "LLMNR", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *llmnr = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_link_get_lldp(int ifindex, char **lldp) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        size_t size;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(lldp, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/lldp/%d", ifindex) < 0)
                return -ENOMEM;

        r = read_full_file(p, &s, &size);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (size <= 0)
                return -ENODATA;

        *lldp = s;
        s = NULL;

        return 0;
}

int sd_network_link_get_timezone(int ifindex, char **ret) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "TIMEZONE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = s;
        s = NULL;
        return 0;
}

static int network_get_link_strv(const char *key, int ifindex, char ***ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        _cleanup_strv_free_ char **a = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, key, &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = strv_length(a);

        *ret = a;
        a = NULL;

        return r;
}

_public_ int sd_network_link_get_dns(int ifindex, char ***ret) {
        return network_get_link_strv("DNS", ifindex, ret);
}

_public_ int sd_network_link_get_ntp(int ifindex, char ***ret) {
        return network_get_link_strv("NTP", ifindex, ret);
}

_public_ int sd_network_link_get_domains(int ifindex, char ***ret) {
        return network_get_link_strv("DOMAINS", ifindex, ret);
}

_public_ int sd_network_link_get_carrier_bound_to(int ifindex, char ***ret) {
        return network_get_link_strv("CARRIER_BOUND_TO", ifindex, ret);
}

_public_ int sd_network_link_get_carrier_bound_by(int ifindex, char ***ret) {
        return network_get_link_strv("CARRIER_BOUND_BY", ifindex, ret);
}

_public_ int sd_network_link_get_wildcard_domain(int ifindex) {
        int r;
        _cleanup_free_ char *p = NULL, *s = NULL;

        assert_return(ifindex > 0, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "WILDCARD_DOMAIN", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        return parse_boolean(s);
}

static inline int MONITOR_TO_FD(sd_network_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static inline sd_network_monitor* FD_TO_MONITOR(int fd) {
        return (sd_network_monitor*) (unsigned long) (fd + 1);
}

static int monitor_add_inotify_watch(int fd) {
        int k;

        k = inotify_add_watch(fd, "/run/systemd/netif/links/", IN_MOVED_TO|IN_DELETE);
        if (k >= 0)
                return 0;
        else if (errno != ENOENT)
                return -errno;

        k = inotify_add_watch(fd, "/run/systemd/netif/", IN_CREATE|IN_ISDIR);
        if (k >= 0)
                return 0;
        else if (errno != ENOENT)
                return -errno;

        k = inotify_add_watch(fd, "/run/systemd/", IN_CREATE|IN_ISDIR);
        if (k < 0)
                return -errno;

        return 0;
}

_public_ int sd_network_monitor_new(sd_network_monitor **m, const char *category) {
        _cleanup_close_ int fd = -1;
        int k;
        bool good = false;

        assert_return(m, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!category || streq(category, "links")) {
                k = monitor_add_inotify_watch(fd);
                if (k < 0)
                        return k;

                good = true;
        }

        if (!good)
                return -EINVAL;

        *m = FD_TO_MONITOR(fd);
        fd = -1;

        return 0;
}

_public_ sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m) {
        int fd;

        if (m) {
                fd = MONITOR_TO_FD(m);
                close_nointr(fd);
        }

        return NULL;
}

_public_ int sd_network_monitor_flush(sd_network_monitor *m) {
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;
        int fd, k;

        assert_return(m, -EINVAL);

        fd = MONITOR_TO_FD(m);

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return -errno;
        }

        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                if (e->mask & IN_ISDIR) {
                        k = monitor_add_inotify_watch(fd);
                        if (k < 0)
                                return k;

                        k = inotify_rm_watch(fd, e->wd);
                        if (k < 0)
                                return -errno;
                }
        }

        return 0;
}

_public_ int sd_network_monitor_get_fd(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        return MONITOR_TO_FD(m);
}

_public_ int sd_network_monitor_get_events(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        /* For now we will only return POLLIN here, since we don't
         * need anything else ever for inotify.  However, let's have
         * this API to keep our options open should we later on need
         * it. */
        return POLLIN;
}

_public_ int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(timeout_usec, -EINVAL);

        /* For now we will only return (uint64_t) -1, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *timeout_usec = (uint64_t) -1;
        return 0;
}
