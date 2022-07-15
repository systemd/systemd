/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "integrity-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"

static const char *arg_dest = NULL;
static const char *arg_integritytab = NULL;
static char *arg_options = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_options, freep);

static int create_disk(
                const char *name,
                const char *device,
                const char *key_file,
                const char *options) {

        _cleanup_free_ char *n = NULL, *dd = NULL, *e = NULL, *name_escaped = NULL, *key_file_escaped = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;
        char *dmname = NULL;

        assert(name);
        assert(device);

        name_escaped = specifier_escape(name);
        if (!name_escaped)
                return log_oom();

        e = unit_name_escape(name);
        if (!e)
                return log_oom();

        r = unit_name_build("systemd-integritysetup", e, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = unit_name_from_path(device, ".device", &dd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest, NULL, n, &f);
        if (r < 0)
                return r;

        if (key_file) {
                if (!path_is_absolute(key_file))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "key file not absolute file path %s", key_file);

                key_file_escaped = specifier_escape(key_file);
                if (!key_file_escaped)
                        return log_oom();
        }

        if (options) {
                r = parse_integrity_options(options, NULL, NULL, NULL, NULL, NULL);
                if (r < 0)
                        return r;
        }

        fprintf(f,
                "[Unit]\n"
                "Description=Integrity Setup for %%I\n"
                "Documentation=man:integritytab(5) man:systemd-integritysetup-generator(8) man:systemd-integritysetup@.service(8)\n"
                "SourcePath=%s\n"
                "DefaultDependencies=no\n"
                "IgnoreOnIsolate=true\n"
                "After=integritysetup-pre.target systemd-udevd-kernel.socket\n"
                "Before=blockdev@dev-mapper-%%i.target\n"
                "Wants=blockdev@dev-mapper-%%i.target\n"
                "Conflicts=umount.target\n"
                "Before=integritysetup.target\n"
                "BindsTo=%s\n"
                "After=%s\n"
                "Before=umount.target\n",
                arg_integritytab,
                dd, dd);

        fprintf(f,
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "TimeoutSec=0\n"
                "ExecStart=" ROOTLIBEXECDIR "/systemd-integritysetup attach '%s' '%s' '%s' '%s'\n"
                "ExecStop=" ROOTLIBEXECDIR "/systemd-integritysetup detach '%s'\n",
                name_escaped, device, empty_to_dash(key_file_escaped), empty_to_dash(options),
                name_escaped);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", n);

        r = generator_add_symlink(arg_dest, "integritysetup.target", "requires", n);
        if (r < 0)
                return r;

        dmname = strjoina("dev-mapper-", e, ".device");
        return generator_add_symlink(arg_dest, dmname, "requires", n);
}

static int add_integritytab_devices(void) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned integritytab_line = 0;
        int r;

        r = fopen_unlocked(arg_integritytab, "re", &f);
        if (r < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", arg_integritytab);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL, *name = NULL, *device_id = NULL, *device_path = NULL, *key_file = NULL, *options = NULL;
                char *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", arg_integritytab);
                if (r == 0)
                        break;

                integritytab_line++;

                l = strstrip(line);
                if (!l)
                        continue;

                if (IN_SET(l[0], 0, '#'))
                        continue;

                /* The key file and the options are optional */
                r = sscanf(l, "%ms %ms %ms %ms", &name, &device_id, &key_file, &options);
                if (!IN_SET(r, 2, 3, 4)) {
                        log_error("Failed to parse %s:%u, ignoring.", l, integritytab_line);
                        continue;
                }

                device_path = fstab_node_to_udev_node(device_id);
                if (!device_path) {
                        log_error("Failed to find device %s:%u, ignoring.", device_id, integritytab_line);
                        continue;
                }

                r = create_disk(name, device_path, empty_or_dash_to_null(key_file), empty_or_dash_to_null(options));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        assert_se(arg_dest = dest);

        arg_integritytab = getenv("SYSTEMD_INTEGRITYTAB") ?: "/etc/integritytab";

        return add_integritytab_devices();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
