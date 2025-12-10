/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "alloc-util.h"
#include "dropin.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "log.h"
#include "path-util.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"

static const char *arg_dest = NULL;

/* Generate unit files that call the systemd-clonesetup binary to create or remove clone devices. */
static int generate_clone_units(
                const char *clone_name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev,
                const char *options) {

        /* unit files for each device */
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *source_unit = NULL, *dest_unit = NULL, *metadata_unit = NULL,
                            *e = NULL, *unit = NULL,
                            *clone_dev_path = NULL, *clone_dev_path_escaped = NULL,
                            *clone_dev_path_unit_escaped = NULL,
                            *clone_name_spec_escaped = NULL, *source_spec_escaped = NULL,
                            *dest_spec_escaped = NULL, *metadata_spec_escaped = NULL,
                            *options_spec_escaped = NULL,
                            *dmname = NULL;
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        /* Escape clone name for unit specifiers and then ExecStart/ExecStop parsing. */
        clone_name_spec_escaped = specifier_escape(clone_name);
        if (!clone_name_spec_escaped)
                return log_oom();

        /* create clone_dev_path that holds path for new cloned device */
        clone_dev_path = path_join("/dev/mapper", clone_name);
        if (!clone_dev_path)
                return log_oom();

        clone_dev_path_escaped = specifier_escape(clone_dev_path);
        if (!clone_dev_path_escaped)
                return log_oom();

        r = unit_name_path_escape(clone_dev_path, &clone_dev_path_unit_escaped);
        if (r < 0)
                return log_error_errno(r, "Failed to escape clone device path: %m");

        /* escape clone name */
        e = unit_name_escape(clone_name);
        if (!e)
                return log_oom();

        /* Generate unit name for the clone service */
        r = unit_name_build("systemd-clonesetup", e, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        /* Generate unit names for dependencies */
        r = unit_name_from_path(source_dev, ".device", &source_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate source device unit name: %m");

        r = unit_name_from_path(dest_dev, ".device", &dest_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate dest device unit name: %m");

        r = unit_name_from_path(metadata_dev, ".device", &metadata_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate metadata device unit name: %m");

        /* Escape device paths for unit specifiers and then ExecStart parsing. */
        source_spec_escaped = specifier_escape(source_dev);
        if (!source_spec_escaped)
                return log_oom();

        dest_spec_escaped = specifier_escape(dest_dev);
        if (!dest_spec_escaped)
                return log_oom();

        metadata_spec_escaped = specifier_escape(metadata_dev);
        if (!metadata_spec_escaped)
                return log_oom();

        if (options) {
                options_spec_escaped = specifier_escape(options);
                if (!options_spec_escaped)
                        return log_oom();
        }

        r = generator_open_unit_file(arg_dest, /* source = */ NULL, unit, &f);
        if (r < 0)
                return r;

        /* With DefaultDependencies=no, order after udev so backing /dev nodes are ready in early boot.
         * The : exec prefix on ExecStart=/ExecStop= disables $ { } env-var expansion by the manager. */
        fprintf(f,
                "[Unit]\n"
                "Description=Create dm-clone device %1$s\n"
                "Documentation=man:clonetab(5) man:systemd-clonesetup(8) man:systemd-clonesetup-generator(8)\n"
                "DefaultDependencies=no\n"
                "BindsTo=%2$s %3$s %4$s\n"
                "After=%2$s %3$s %4$s systemd-udevd-kernel.socket\n"
                "Before=blockdev@%5$s.target clonesetup.target shutdown.target\n"
                "Wants=blockdev@%5$s.target\n"
                "Conflicts=shutdown.target\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=:" SYSTEMD_CLONESETUP_PATH " add '%6$s' '%7$s' '%8$s' '%9$s' '%10$s'\n"
                "ExecStop=:" SYSTEMD_CLONESETUP_PATH " remove '%6$s'\n"
                "TimeoutSec=0\n",
                clone_dev_path_escaped,
                source_unit, dest_unit, metadata_unit,
                clone_dev_path_unit_escaped,
                clone_name_spec_escaped, source_spec_escaped, dest_spec_escaped, metadata_spec_escaped, options_spec_escaped ?: "");

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", unit);

        /* symlink unit file to enable it */
        r = unit_name_from_path(clone_dev_path, ".device", &dmname);
        if (r < 0)
                return log_error_errno(r, "Failed to generate clone device unit name: %m");

        r = generator_add_symlink(arg_dest, dmname, "requires", unit);
        if (r < 0)
                return r;

        /* Extend device timeout to allow clone service to complete */
        r = write_drop_in(arg_dest, dmname, 40, "device-timeout",
                          "# Automatically generated by systemd-clonesetup-generator\n\n"
                          "[Unit]\n"
                          "JobRunningTimeoutSec=infinity\n");
        if (r < 0)
                log_warning_errno(r, "Failed to write device timeout drop-in: %m");

        /* Add to clonesetup.target so it starts at boot */
        r = generator_add_symlink(arg_dest, "clonesetup.target", "requires", unit);
        if (r < 0)
                return r;

        return 0;
}

/* Field validation — what each check covers:
 *   control chars, \, ', whitespace  → string_is_safe() on all fields
 *   / in name                        → string_is_safe(name, STRING_FILENAME)
 *   .. in device paths               → path_is_normalized()
 *   non-/dev/ device paths           → path_is_absolute() + path_startswith(path, "/dev/")
 *   % specifier expansion            → specifier_escape() applied before writing unit file
 *   $ { } env-var expansion          → : exec prefix on ExecStart=/ExecStop= */
static int validate_fields(const char *fname, unsigned clone_line, const char *name, const char *src, const char *dst, const char *meta, const char *options) {
        if (!string_is_safe(name, STRING_FILENAME)) {
                log_error("Invalid clone name '%s' in %s:%u, ignoring.", name, fname, clone_line);
                return -EINVAL;
        }

        if (!string_is_safe(src, 0) || !path_is_valid(src) || !path_is_normalized(src) ||
                        !path_is_absolute(src) || !path_startswith(src, "/dev/")) {
                log_error("Invalid src path '%s' in %s:%u, ignoring.", src, fname, clone_line);
                return -EINVAL;
        }

        if (!string_is_safe(dst, 0) || !path_is_valid(dst) || !path_is_normalized(dst) ||
                        !path_is_absolute(dst) || !path_startswith(dst, "/dev/")) {
                log_error("Invalid dst path '%s' in %s:%u, ignoring.", dst, fname, clone_line);
                return -EINVAL;
        }

        if (!string_is_safe(meta, 0) || !path_is_valid(meta) || !path_is_normalized(meta) ||
                        !path_is_absolute(meta) || !path_startswith(meta, "/dev/")) {
                log_error("Invalid meta path '%s' in %s:%u, ignoring.", meta, fname, clone_line);
                return -EINVAL;
        }

        if (options && !string_is_safe(options, 0)) {
                log_error("Invalid options '%s' in %s:%u, ignoring.", options, fname, clone_line);
                return -EINVAL;
        }
        return 0;
}

static int add_clone_devices(void) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned clone_line = 0;
        int r, ret = 0;
        const char *fname;

        fname = secure_getenv("SYSTEMD_CLONETAB") ?: "/etc/clonetab";

        r = fopen_unlocked(fname, "re", &f);
        if (r < 0) {
                if (r != -ENOENT)
                        log_error_errno(r, "Failed to open %s: %m", fname);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL, *src = NULL, *name = NULL, *dst = NULL, *meta = NULL, *options = NULL;
                int k;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", fname);
                if (r == 0)
                        break;

                clone_line++;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                k = sscanf(line, "%ms %ms %ms %ms %ms", &name, &src, &dst, &meta, &options);
                if (k < 4 || k > 5) {
                        log_error("Failed to parse %s:%u, ignoring.", fname, clone_line);
                        continue;
                }

                r = validate_fields(fname, clone_line, name, src, dst, meta, options);
                if (r < 0)
                        continue;
                RET_GATHER(ret, generate_clone_units(name, src, dst, meta, options));
        }

        return ret;
}

/* This generator reads /etc/clonetab and for each entry, writes unit files
 * (creates systemd-clonesetup@<name>.service and clonesetup.target.requires/systemd-clonesetup@<name>.service)
 * that clonesetup.target requires, and that run systemd-clonesetup (add device at boot,
 * remove it at shutdown); systemd-clonesetup (used in systemd-clonesetup@.service) is the binary that
 * uses device-mapper ioctls to create and remove the dm-clone devices.
 * clonesetup.target groups these units so they run together at boot.
 * Boot chain: sysinit.target has clonesetup.target in sysinit.target.wants/ (see units/meson.build),
 * so at boot clonesetup.target starts and pulls in these units via clonesetup.target.requires/. */
static int run(const char *dest, const char *dest_early, const char *dest_late) {

        /* dest usually is /run/systemd/generator */
        assert_se(arg_dest = dest);

        return add_clone_devices();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
