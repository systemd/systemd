/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
#include <sys/inotify.h>

#include "sd-cloud-provider.h"

#include "alloc-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int cloud_provider_link_get_string(int ifindex, const char *field, char **ret) {
        char path[STRLEN("/run/systemd/cloud-provider/netif/links/") + DECIMAL_STR_MAX(ifindex) + 1];
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        xsprintf(path, "/run/systemd/cloud-provider/netif/links/%i", ifindex);

        r = parse_env_file(NULL, path, field, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = TAKE_PTR(s);

        return 0;
}

_public_ int sd_cloud_provider_azure_get_ipv4_prefixlen(int ifindex, char **prefixlen) {
        return cloud_provider_link_get_string(ifindex, "AZURE_IPV4_PREFIXLEN", prefixlen);
}

static int cloud_provider_link_get_strv(int ifindex, const char *key, char ***ret) {
        char path[STRLEN("/run/systemd/cloud-provider/netif/links/") + DECIMAL_STR_MAX(ifindex) + 1];
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        xsprintf(path, "/run/systemd/cloud-provider/netif/links/%i", ifindex);
        r = parse_env_file(NULL, path, key, &s);
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
        r = (int) strv_length(a);

        *ret = TAKE_PTR(a);

        return r;
}

_public_ int sd_cloud_provider_azure_link_get_ipv4_private_ips(int ifindex, char ***ret) {
        return cloud_provider_link_get_strv(ifindex, "AZURE_IPV4_PRIVATE_IPS", ret);
}

_public_ int sd_cloud_provider_azure_link_get_ipv4_public_ips(int ifindex, char ***ret) {
        return cloud_provider_link_get_strv(ifindex, "AZURE_IPV4_PUBLIC_IPS", ret);
}

_public_ int sd_cloud_provider_azure_link_get_ipv4_subnet(int ifindex, char ***ret) {
        return cloud_provider_link_get_strv(ifindex, "AZURE_IPV4_SUBNET", ret);
}

static int MONITOR_TO_FD(sd_cloud_provider_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static sd_cloud_provider_monitor* FD_TO_MONITOR(int fd) {
        return (sd_cloud_provider_monitor*) (unsigned long) (fd + 1);
}

static int monitor_add_inotify_watch(int fd) {
        int k;

        k = inotify_add_watch(fd, "/run/systemd/cloud-provider/netif/", IN_CREATE|IN_ISDIR);
        if (k >= 0)
                return 0;
        else if (errno != ENOENT)
                return -errno;

        return 0;
}

_public_ int sd_cloud_provider_monitor_new(sd_cloud_provider_monitor **m) {
        _cleanup_close_ int fd = -1;
        int r;

        assert_return(m, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = monitor_add_inotify_watch(fd);
        if (r < 0)
                return r;

        *m = FD_TO_MONITOR(TAKE_FD(fd));
        return 0;
}

_public_ sd_cloud_provider_monitor* sd_cloud_provider_monitor_unref(sd_cloud_provider_monitor *m) {
        if (m)
                close_nointr(MONITOR_TO_FD(m));

        return NULL;
}

_public_ int sd_cloud_provider_monitor_flush(sd_cloud_provider_monitor *m) {
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;
        int fd, k;

        assert_return(m, -EINVAL);

        fd = MONITOR_TO_FD(m);

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
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

_public_ int sd_cloud_provider_monitor_get_fd(sd_cloud_provider_monitor *m) {

        assert_return(m, -EINVAL);

        return MONITOR_TO_FD(m);
}

_public_ int sd_cloud_provider_monitor_get_events(sd_cloud_provider_monitor *m) {

        assert_return(m, -EINVAL);

        return POLLIN;
}

_public_ int sd_cloud_provider_monitor_get_timeout(sd_cloud_provider_monitor *m, uint64_t *timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(timeout_usec, -EINVAL);

        *timeout_usec = (uint64_t) -1;
        return 0;
}
