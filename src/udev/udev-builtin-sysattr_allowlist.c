/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "device-internal.h"
#include "device-util.h"
#include "errno-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "set.h"
#include "sd-device.h"
#include "string-util.h"
#include "strv.h"
#include "udev-builtin.h"

static int get_version(char **version) {
        _cleanup_free_ char *cmdline = NULL;
        const char *env;
        char *ret;
        int r;

        r = proc_cmdline_get_key("sysfsallowver", 0, &cmdline);
        if (r < 0)
                return r;

        env = getenv("SYSFS_ALLOWLIST_VERSION");
        if (env) {
                /* If prefixed with ':' the kernel cmdline takes precedence */
                if (*env == ':' && cmdline)
                        ret = TAKE_PTR(cmdline);
                else {
                        ret = strdup(env);
                        if (!ret)
                                return -ENOMEM;
                }
        }
        else
                ret = TAKE_PTR(cmdline);

        *version = ret;
        return 0;
}

static int builtin_sysattr_allowlist_generate(UdevEvent *event, int argc, char **argv, bool test) {
        _cleanup_free_ char *version = NULL;
        sd_device *device = event->dev;
        const char *id = NULL;
        int r;

        if (argc <= 0 || isempty(argv[1]))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                        "Failed to generate allow list for sysfs attributes, missing device ID.");

        id = argv[1];

        r = get_version(&version);
        if (r < 0)
                return log_error_errno(r, "Failed to get version: %m");

        r = udev_builtin_hwdb_lookup(device, "sysattr_allowlist:", id, NULL, test);
        if (r < 0)
                return log_error_errno(r, "Failed to query HWDB for %s: %m", id);

        FOREACH_DEVICE_PROPERTY(device, key, value) {
                const char *suffix = startswith(key, "SYSATTR_ALLOWLIST");
                if(!suffix)
                        continue;

                // If we have plain "SYSATTR_ALLOWLIST", or "SYSATTR_ALLOWLIST_VER" where VER is higher or equal then version
                if (isempty(suffix) || strverscmp_improved(version, suffix + 1) >= 0) {
                        _cleanup_strv_free_ char **l = strv_split(value, ",");
                        r = set_put_strdupv(&device->sysattrs_allowlist, l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add sysattr allowlist for %s: %m", id);
                }
        }

        return 0;
}

const UdevBuiltin udev_builtin_sysattr_allowlist = {
        .name = "sysattr_allowlist",
        .cmd = builtin_sysattr_allowlist_generate,
        .help = "Read allowed sysfs attributes from hwdb and generate allowlist",
};
