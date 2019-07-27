/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"

#define SYSTEMD_VERITYSETUP_SERVICE "systemd-veritysetup@root.service"

static const char *arg_dest = NULL;
static bool arg_enabled = true;
static char *arg_root_hash = NULL;
static char *arg_data_what = NULL;
static char *arg_hash_what = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_data_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hash_what, freep);

static int create_device(void) {
        _cleanup_free_ char *u = NULL, *v = NULL, *d = NULL, *e = NULL, *u_escaped = NULL, *v_escaped = NULL, *root_hash_escaped = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *to;
        int r;

        /* If all three pieces of information are missing, then verity is turned off */
        if (!arg_root_hash && !arg_data_what && !arg_hash_what)
                return 0;

        /* if one of them is missing however, the data is simply incomplete and this is an error */
        if (!arg_root_hash)
                log_error("Verity information incomplete, root hash unspecified.");
        if (!arg_data_what)
                log_error("Verity information incomplete, root data device unspecified.");
        if (!arg_hash_what)
                log_error("Verity information incomplete, root hash device unspecified.");

        if (!arg_root_hash || !arg_data_what || !arg_hash_what)
                return -EINVAL;

        log_debug("Using root verity data device %s,\n"
                  "                  hash device %s,\n"
                  "                and root hash %s.", arg_data_what, arg_hash_what, arg_root_hash);

        u = fstab_node_to_udev_node(arg_data_what);
        if (!u)
                return log_oom();
        v = fstab_node_to_udev_node(arg_hash_what);
        if (!v)
                return log_oom();

        u_escaped = specifier_escape(u);
        if (!u_escaped)
                return log_oom();
        v_escaped = specifier_escape(v);
        if (!v_escaped)
                return log_oom();

        r = unit_name_from_path(u, ".device", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");
        r = unit_name_from_path(v, ".device", &e);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        root_hash_escaped = specifier_escape(arg_root_hash);
        if (!root_hash_escaped)
                return log_oom();

        r = generator_open_unit_file(arg_dest, NULL, SYSTEMD_VERITYSETUP_SERVICE, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=Integrity Protection Setup for %%I\n"
                "Documentation=man:systemd-veritysetup-generator(8) man:systemd-veritysetup@.service(8)\n"
                "SourcePath=/proc/cmdline\n"
                "DefaultDependencies=no\n"
                "Conflicts=umount.target\n"
                "BindsTo=%s %s\n"
                "IgnoreOnIsolate=true\n"
                "After=cryptsetup-pre.target %s %s\n"
                "Before=cryptsetup.target umount.target\n"
                "\n[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=" ROOTLIBEXECDIR "/systemd-veritysetup attach root '%s' '%s' '%s'\n"
                "ExecStop=" ROOTLIBEXECDIR "/systemd-veritysetup detach root\n",
                d, e,
                d, e,
                u_escaped, v_escaped, root_hash_escaped);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write file unit "SYSTEMD_VERITYSETUP_SERVICE": %m");

        to = strjoina(arg_dest, "/cryptsetup.target.requires/" SYSTEMD_VERITYSETUP_SERVICE);

        (void) mkdir_parents(to, 0755);
        if (symlink("../" SYSTEMD_VERITYSETUP_SERVICE, to) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", to);

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "systemd.verity")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse verity= kernel command line switch %s. Ignoring.", value);
                else
                        arg_enabled = r;

        } else if (proc_cmdline_key_streq(key, "roothash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_root_hash, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_root_data")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_data_what, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_root_hash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_hash_what, value);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int determine_devices(void) {
        _cleanup_free_ void *m = NULL;
        sd_id128_t root_uuid, verity_uuid;
        char ids[37];
        size_t l;
        int r;

        /* Try to automatically derive the root data and hash device paths from the root hash */

        if (!arg_root_hash)
                return 0;

        if (arg_data_what && arg_hash_what)
                return 0;

        r = unhexmem(arg_root_hash, strlen(arg_root_hash), &m, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to parse root hash: %s", arg_root_hash);
        if (l < sizeof(sd_id128_t)) {
                log_debug("Root hash is shorter than 128 bits (32 characters), ignoring for discovering verity partition.");
                return 0;
        }

        if (!arg_data_what) {
                memcpy(&root_uuid, m, sizeof(root_uuid));

                arg_data_what = path_join("/dev/disk/by-partuuid", id128_to_uuid_string(root_uuid, ids));
                if (!arg_data_what)
                        return log_oom();
        }

        if (!arg_hash_what) {
                memcpy(&verity_uuid, (uint8_t*) m + l - sizeof(verity_uuid), sizeof(verity_uuid));

                arg_hash_what = path_join("/dev/disk/by-partuuid", id128_to_uuid_string(verity_uuid, ids));
                if (!arg_hash_what)
                        return log_oom();
        }

        return 1;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse kernel command line: %m");

        /* For now we only support the root device on verity. Later on we might want to add support for /etc/veritytab
         * or similar to define additional mappings */

        if (!arg_enabled)
                return 0;

        r = determine_devices();
        if (r < 0)
                return r;

        return create_device();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
