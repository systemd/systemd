/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "dropin.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "hashmap.h"
#include "log.h"
#include "path-util.h"
#include "special.h"
#include "string-util.h"
#include "unit-name.h"

typedef struct clone_device {
        char *uuid;
        char *datadev;
        char *name;
        char *options;
        bool clone;
} clone_device;

static const char *arg_dest = NULL;
static const char *arg_runtime_directory = NULL;
static Hashmap *arg_disks = NULL;

static clone_device* clone_device_free(clone_device *d) {
        if (!d)
                return NULL;

        free(d->uuid);
        free(d->datadev);
        free(d->name);
        free(d->options);
        return mfree(d);
}

static int generate_clone_units(const char *clone_name, const char *source_dev, const char *dest_dev,
        const char *metadata_dev, const char *options) {

        /* unit files for each device */
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *source_unit = NULL, *dest_unit = NULL, *metadata_unit = NULL;
        _cleanup_free_ char *escaped_source = NULL, *escaped_dest = NULL, *escaped_metadata = NULL;
        _cleanup_free_ char *e = NULL, *unit = NULL;
        _cleanup_free_ char *dev_path = NULL;
        _cleanup_free_ char *clone_dev_path = NULL;
        const char *dmname;
        int r;

        assert(clone_name);
        assert(source_dev);
        assert(dest_dev);
        assert(metadata_dev);

        /* create clone_dev_path that holds path for new cloned device */
        clone_dev_path = path_join("/dev/mapper", clone_name);
        if (!clone_dev_path)
                return log_oom();

        /* escape clone name */
        e = unit_name_escape(clone_name);
        if (!e)
                return log_oom();

        /* Generate unit name for the clone service */
        r = unit_name_build("systemd-clone", e, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        log_info("unit name=%s", unit);

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

        /* Escape device paths for ExecStart command */
        escaped_source = cescape(source_dev);
        if (!escaped_source)
                return log_oom();

        escaped_dest = cescape(dest_dev);
        if (!escaped_dest)
                return log_oom();

        escaped_metadata = cescape(metadata_dev);
        if (!escaped_metadata)
                return log_oom();

        r = generator_open_unit_file(arg_dest, /* source = */ NULL, unit, &f);
        if (r < 0)
                return r;

        /* Check if we're using loop devices and add setup if needed */
        bool setup_loop = startswith(source_dev, "/dev/loop") && startswith(dest_dev, "/dev/loop") && startswith(metadata_dev, "/dev/loop");

        fprintf(f,
                "[Unit]\n"
                "Description=Create dm-clone device %s\n"
                "Documentation=man:dmsetup(8) man:fstab(5) man:systemd-fstab-generator(8)\n"
                "DefaultDependencies=no\n",
                clone_dev_path);

        if (!setup_loop) {
                fprintf(f,
                        "BindsTo=%s %s %s\n"
                        "Requires=%s %s %s\n"
                        "After=%s %s %s\n",
                        source_unit, dest_unit, metadata_unit,
                        source_unit, dest_unit, metadata_unit,
                        source_unit, dest_unit, metadata_unit);
        }

        fprintf(f,
                "Before=blockdev@dev-mapper-%s.target\n"
                "Wants=blockdev@dev-mapper-%s.target\n"
                "Conflicts=shutdown.target\n"
                "\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n",
                e, e);

        if (setup_loop)
                fprintf(f, "ExecStartPre=/usr/share/script.sh\n");

        fprintf(f,
                "ExecStart=" SYSTEMD_CLONE_PATH " add '%s' '%s' '%s' '%s' '%s'\n"
                "ExecStop=" SYSTEMD_CLONE_PATH " remove %s\n"
                "TimeoutSec=0\n",
                clone_name, escaped_source, escaped_dest, escaped_metadata, "",
                clone_name);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", unit);

        // symlink unit file to enable it
        dmname = strjoina("dev-mapper-", e, ".device");
        r = generator_add_symlink(arg_dest, dmname, "requires", unit);
        if (r < 0)
                return r;

        /* Extend device timeout to allow clone service to complete */
        r = write_drop_in(arg_dest, dmname, 40, "device-timeout",
                          "# Automatically generated by systemd-clone-generator\n\n"
                          "[Unit]\n"
                          "JobTimeoutSec=infinity\n");
        if (r < 0)
                log_warning_errno(r, "Failed to write device timeout drop-in: %m");

        /* Add to clone.target so it starts at boot */
        r = generator_add_symlink(arg_dest, SPECIAL_CLONE_TARGET, "requires", unit);
        if (r < 0)
                return r;

        return 0;
}

static int add_clone_devices(void) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned clone_line = 0;
        int r, ret = 0;
        const char *fname;

        fname = getenv("SYSTEMD_CLONETAB") ?: "/etc/clonetab";

        log_info("Parsing %s", fname);
        r = fopen_unlocked(fname, "re", &f);
        if (r < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", fname);
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

                RET_GATHER(ret, generate_clone_units(name, src, dst, meta, options));
        }

        return ret;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(clone_device_hash_ops, char, string_hash_func, string_compare_func,
                                              clone_device, clone_device_free);


static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        // dest usually is /run/systemd/generator
        assert_se(arg_dest = dest);

        arg_runtime_directory = getenv("RUNTIME_DIRECTORY") ?: "/run/systemd/dev-clone";

        arg_disks = hashmap_new(&clone_device_hash_ops);
        if (!arg_disks)
                return log_oom();

        r = add_clone_devices();
        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
