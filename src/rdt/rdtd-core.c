/* SPDX-License-Identifier: LGPL-2.1+ */

#include "rdtd.h"
#include "def.h"
#include "rdtd-resctrl.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "log.h"
#include "fileio.h"

int rdtd_parse_config(void) {
        _cleanup_free_ char *val = NULL;
        const char *log;
        size_t n;
        int r;

        r = parse_env_file(NULL, "/etc/systemd/rdtd.conf", NEWLINE, "rdtd_log", &val, NULL);
        if (r == -ENOENT || !val)
                return 0;
        if (r < 0)
                return r;

        /* unquote */
        n = strlen(val);
        if (n >= 2 &&
            ((val[0] == '"' && val[n-1] == '"') ||
             (val[0] == '\'' && val[n-1] == '\''))) {
                val[n - 1] = '\0';
                log = val + 1;
        } else
                log = val;

        r = log_set_max_level_from_string_realm(LOG_REALM_UDEV, log);
        if (r < 0)
                log_debug_errno(r, "failed to set udev log level '%s', ignoring: %m", log);

        return 0;
}

int manager_get_rdtinfo(Manager *m) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        struct RdtInfo *info;
        int ret;

        assert(m);

        log_debug("get rdt info %s\n", RESCTRL_PATH_INFO);
        d = opendir(RESCTRL_PATH_INFO);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        info = new0(RdtInfo, 1);
        if (!info)
                return -ENOMEM;

        FOREACH_DIRENT(de, d, return -errno) {
                log_debug("Parsing info file '%s'", de->d_name);
                if (streq(de->d_name, RESCTRL_TYPE_L3)) {
                        ret = resctrl_get_l3_info(&info->l3_info, de->d_name);
                        if (ret < 0)
                                goto out;
                }
        }

        m->rdtinfo = info;
        return 0;
out:
        free(info);
        return ret;
}

int manager_enumerate_groups(Manager *m) {
        int r, fd;

        assert(m);

        fd = resctrl_lock();
        if (fd < 0)
                return -EINVAL;

        /* scan runtime configs */
        r = rdt_scan_runtime_configs(m);
        if (r < 0) {
                resctrl_unlock(fd);
                return r;
        }

        /* scan static configs */
        r = rdt_scan_static_configs(m);
        if (r < 0) {
                resctrl_unlock(fd);
                return r;
        }

        resctrl_unlock(fd);
        return 0;
}
