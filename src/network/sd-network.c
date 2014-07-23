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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <net/if.h>

#include "util.h"
#include "macro.h"
#include "strv.h"
#include "fileio.h"
#include "sd-network.h"
#include "network-internal.h"
#include "dhcp-lease-internal.h"

_public_ int sd_network_get_link_state(int ifindex, char **state) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(state, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "ADMIN_STATE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        else if (r < 0)
                return r;
        else if (!s)
                return -EIO;

        if (streq(s, "initializing"))
                return -EBUSY;

        *state = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_get_operational_state(char **state) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(state, -EINVAL);

        r = parse_env_file("/run/systemd/netif/state", NEWLINE, "OPER_STATE",
                           &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        else if (r < 0)
                return r;
        else if (!s)
                return -EIO;

        *state = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_get_link_operational_state(int ifindex, char **state) {
        _cleanup_free_ char *s = NULL, *p = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(state, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "OPER_STATE", &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        else if (r < 0)
                return r;
        else if (!s)
                return -EIO;

        *state = s;
        s = NULL;

        return 0;
}

_public_ int sd_network_get_dhcp_lease(int ifindex, sd_dhcp_lease **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        sd_dhcp_lease *lease = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, "DHCP_LEASE", &s, NULL);

        if (r < 0)
                return r;
        else if (!s)
                return -EIO;

        r = dhcp_lease_load(s, &lease);
        if (r < 0)
                return r;

        *ret = lease;

        return 0;
}

static int network_get_strv(const char *key, int ifindex, char ***ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        _cleanup_strv_free_ char **a = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        r = parse_env_file(p, NEWLINE, key, &s, NULL);
        if (r < 0)
                return r;
        else if (!s) {
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

_public_ int sd_network_get_dns(int ifindex, char ***ret) {
        return network_get_strv("DNS", ifindex, ret);
}

_public_ int sd_network_get_ntp(int ifindex, char ***ret) {
        return network_get_strv("NTP", ifindex, ret);
}

static inline int MONITOR_TO_FD(sd_network_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static inline sd_network_monitor* FD_TO_MONITOR(int fd) {
        return (sd_network_monitor*) (unsigned long) (fd + 1);
}

_public_ int sd_network_monitor_new(sd_network_monitor **m, const char *category) {
        int fd, k;
        bool good = false;

        assert_return(m, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!category || streq(category, "links")) {
                k = inotify_add_watch(fd, "/run/systemd/netif/links/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        safe_close(fd);
                        return -errno;
                }

                good = true;
        }

        if (!category || streq(category, "leases")) {
                k = inotify_add_watch(fd, "/run/systemd/netif/leases/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        safe_close(fd);
                        return -errno;
                }

                good = true;
        }

        if (!good) {
                close_nointr(fd);
                return -EINVAL;
        }

        *m = FD_TO_MONITOR(fd);
        return 0;
}

_public_ sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m) {
        int fd;

        assert_return(m, NULL);

        fd = MONITOR_TO_FD(m);
        close_nointr(fd);

        return NULL;
}

_public_ int sd_network_monitor_flush(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        return flush_fd(MONITOR_TO_FD(m));
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
