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

#include "util.h"
#include "strv.h"
#include "path-util.h"
#include "cgroup-util.h"

#include "cgroup-semantics.h"

static int parse_cpu_shares(const CGroupSemantics *s, const char *value, char **ret) {
        unsigned long ul;

        assert(s);
        assert(value);
        assert(ret);

        if (safe_atolu(value, &ul) < 0 || ul < 1)
                return -EINVAL;

        if (asprintf(ret, "%lu", ul) < 0)
                return -ENOMEM;

        return 1;
}

static int parse_memory_limit(const CGroupSemantics *s, const char *value, char **ret) {
        off_t sz;

        assert(s);
        assert(value);
        assert(ret);

        if (parse_bytes(value, &sz) < 0 || sz <= 0)
                return -EINVAL;

        if (asprintf(ret, "%llu", (unsigned long long) sz) < 0)
                return -ENOMEM;

        return 1;
}

static int parse_device(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        char *x;
        unsigned k;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return -ENOMEM;

        k = strv_length(l);
        if (k < 1 || k > 2)
                return -EINVAL;

        if (!streq(l[0], "*") && !path_startswith(l[0], "/dev"))
                return -EINVAL;

        if (!isempty(l[1]) && !in_charset(l[1], "rwm"))
                return -EINVAL;

        x = strdup(value);
        if (!x)
                return -ENOMEM;

        *ret = x;
        return 1;
}

static int parse_blkio_weight(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        unsigned long ul;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return -ENOMEM;

        if (strv_length(l) != 1)
                return 0; /* Returning 0 will cause parse_blkio_weight_device() be tried instead */

        if (safe_atolu(l[0], &ul) < 0 || ul < 10 || ul > 1000)
                return -EINVAL;

        if (asprintf(ret, "%lu", ul) < 0)
                return -ENOMEM;

        return 1;
}

static int parse_blkio_weight_device(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        unsigned long ul;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return -ENOMEM;

        if (strv_length(l) != 2)
                return -EINVAL;

        if (!path_startswith(l[0], "/dev"))
                return -EINVAL;

        if (safe_atolu(l[1], &ul) < 0 || ul < 10 || ul > 1000)
                return -EINVAL;

        if (asprintf(ret, "%s %lu", l[0], ul) < 0)
                return -ENOMEM;

        return 1;
}

static int parse_blkio_bandwidth(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        off_t bytes;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return -ENOMEM;

        if (strv_length(l) != 2)
                return -EINVAL;

        if (!path_startswith(l[0], "/dev")) {
                return -EINVAL;
        }

        if (parse_bytes(l[1], &bytes) < 0 || bytes <= 0)
                return -EINVAL;

        if (asprintf(ret, "%s %llu", l[0], (unsigned long long) bytes) < 0)
                return -ENOMEM;

        return 0;
}

static int map_device(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        unsigned k;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return -ENOMEM;

        k = strv_length(l);
        if (k < 1 || k > 2)
                return -EINVAL;

        if (streq(l[0], "*")) {

                if (asprintf(ret, "a *:*%s%s",
                             isempty(l[1]) ? "" : " ", strempty(l[1])) < 0)
                        return -ENOMEM;
        } else {
                struct stat st;

                if (stat(l[0], &st) < 0) {
                        log_warning("Couldn't stat device %s", l[0]);
                        return -errno;
                }

                if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
                        log_warning("%s is not a device.", l[0]);
                        return -ENODEV;
                }

                if (asprintf(ret, "%c %u:%u%s%s",
                             S_ISCHR(st.st_mode) ? 'c' : 'b',
                             major(st.st_rdev), minor(st.st_rdev),
                             isempty(l[1]) ? "" : " ", strempty(l[1])) < 0)
                        return -ENOMEM;
        }

        return 0;
}

static int map_blkio(const CGroupSemantics *s, const char *value, char **ret) {
        _cleanup_strv_free_ char **l = NULL;
        struct stat st;
        dev_t d;

        assert(s);
        assert(value);
        assert(ret);

        l = strv_split_quoted(value);
        if (!l)
                return log_oom();

        if (strv_length(l) != 2)
                return -EINVAL;

        if (stat(l[0], &st) < 0) {
                log_warning("Couldn't stat device %s", l[0]);
                return -errno;
        }

        if (S_ISBLK(st.st_mode))
                d = st.st_rdev;
        else if (major(st.st_dev) != 0) {
                /* If this is not a device node then find the block
                 * device this file is stored on */
                d = st.st_dev;

                /* If this is a partition, try to get the originating
                 * block device */
                block_get_whole_disk(d, &d);
        } else {
                log_warning("%s is not a block device and file system block device cannot be determined or is not local.", l[0]);
                return -ENODEV;
        }

        if (asprintf(ret, "%u:%u %s", major(d), minor(d), l[1]) < 0)
                return -ENOMEM;

        return 0;
}

static const CGroupSemantics semantics[] = {
        { "cpu",     "cpu.shares",                 "CPUShare",              false, parse_cpu_shares,          NULL,       NULL },
        { "memory",  "memory.soft_limit_in_bytes", "MemorySoftLimit",       false, parse_memory_limit,        NULL,       NULL },
        { "memory",  "memory.limit_in_bytes",      "MemoryLimit",           false, parse_memory_limit,        NULL,       NULL },
        { "devices", "devices.allow",              "DeviceAllow",           true,  parse_device,              map_device, NULL },
        { "devices", "devices.deny",               "DeviceDeny",            true,  parse_device,              map_device, NULL },
        { "blkio",   "blkio.weight",               "BlockIOWeight",         false, parse_blkio_weight,        NULL,       NULL },
        { "blkio",   "blkio.weight_device",        "BlockIOWeight",         true,  parse_blkio_weight_device, map_blkio,  NULL },
        { "blkio",   "blkio.read_bps_device",      "BlockIOReadBandwidth",  true,  parse_blkio_bandwidth,     map_blkio,  NULL },
        { "blkio",   "blkio.write_bps_device",     "BlockIOWriteBandwidth", true,  parse_blkio_bandwidth,     map_blkio,  NULL }
};

int cgroup_semantics_find(
                const char *controller,
                const char *name,
                const char *value,
                char **ret,
                const CGroupSemantics **_s) {

        _cleanup_free_ char *c = NULL;
        unsigned i;
        int r;

        assert(name);
        assert(_s);
        assert(!value == !ret);

        if (!controller) {
                r = cg_controller_from_attr(name, &c);
                if (r < 0)
                        return r;

                controller = c;
        }

        for (i = 0; i < ELEMENTSOF(semantics); i++) {
                const CGroupSemantics *s = semantics + i;
                bool matches_name, matches_pretty;

                if (controller && s->controller && !streq(s->controller, controller))
                        continue;

                matches_name = s->name && streq(s->name, name);
                matches_pretty = s->pretty && streq(s->pretty, name);

                if (!matches_name && !matches_pretty)
                        continue;

                if (value) {
                        if (matches_pretty && s->map_pretty) {

                                r = s->map_pretty(s, value, ret);
                                if (r < 0)
                                        return r;

                                if (r == 0)
                                        continue;

                        } else {
                                char *x;

                                x = strdup(value);
                                if (!x)
                                        return -ENOMEM;

                                *ret = x;
                        }
                }

                *_s = s;
                return 1;
        }

        *ret = NULL;
        *_s = NULL;
        return 0;
}
