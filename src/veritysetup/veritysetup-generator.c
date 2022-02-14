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
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "specifier.h"
#include "string-util.h"
#include "unit-name.h"

#define SYSTEMD_VERITYSETUP_SERVICE_ROOT "systemd-veritysetup@root.service"
#define SYSTEMD_VERITYSETUP_SERVICE_USR "systemd-veritysetup@usr.service"

static const char *arg_dest = NULL;
static bool arg_enabled = true;
static bool arg_read_veritytab = true;
static const char *arg_veritytab = NULL;
static char *arg_root_hash = NULL;
static char *arg_root_data_what = NULL;
static char *arg_root_hash_what = NULL;
static char *arg_root_options = NULL;
static char *arg_usr_hash = NULL;
static char *arg_usr_data_what = NULL;
static char *arg_usr_hash_what = NULL;
static char *arg_usr_options = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_data_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_data_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_hash_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_options, freep);

static int create_device(
                const char *name,
                const char *service,
                const char *hash,
                const char *data_what,
                const char *hash_what,
                const char *options) {

        _cleanup_free_ char *u = NULL, *v = NULL, *d = NULL, *e = NULL, *u_escaped = NULL, *v_escaped = NULL,
                            *hash_escaped = NULL, *options_escaped = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *to, *from;
        int r;

        assert(name);
        assert(service);

        /* If all three pieces of information are missing, then verity is turned off */
        if (!hash && !data_what && !hash_what)
                return 0;

        /* if one of them is missing however, the data is simply incomplete and this is an error */
        if (!hash)
                log_error("Verity information for %s incomplete, hash unspecified.", name);
        if (!data_what)
                log_error("Verity information for %s incomplete, data device unspecified.", name);
        if (!hash_what)
                log_error("Verity information for %s incomplete, hash device unspecified.", name);

        if (!hash || !data_what || !hash_what)
                return -EINVAL;

        log_debug("Using %s verity data device %s, hash device %s, options %s, and hash %s.", name, data_what, hash_what, options, hash);

        u = fstab_node_to_udev_node(data_what);
        if (!u)
                return log_oom();
        v = fstab_node_to_udev_node(hash_what);
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

        options_escaped = specifier_escape(strempty(options));
        if (!options_escaped)
                return log_oom();

        hash_escaped = specifier_escape(hash);
        if (!hash_escaped)
                return log_oom();

        r = generator_open_unit_file(arg_dest, NULL, service, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=Verity Protection Setup for %%I\n"
                "Documentation=man:systemd-veritysetup-generator(8) man:systemd-veritysetup@.service(8)\n"
                "SourcePath=/proc/cmdline\n"
                "DefaultDependencies=no\n"
                "Conflicts=umount.target\n"
                "BindsTo=%s %s\n"
                "IgnoreOnIsolate=true\n"
                "After=veritysetup-pre.target systemd-udevd-kernel.socket %s %s\n"
                "Before=veritysetup.target umount.target\n"
                "\n[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                "ExecStart=" ROOTLIBEXECDIR "/systemd-veritysetup attach '%s' '%s' '%s' '%s' '%s'\n"
                "ExecStop=" ROOTLIBEXECDIR "/systemd-veritysetup detach '%s' \n",
                d, e,
                d, e,
                name, u_escaped, v_escaped, hash_escaped, options_escaped,
                name);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write file unit %s: %m", service);

        to = strjoina(arg_dest, "/veritysetup.target.requires/", service);
        from = strjoina("../", service);

        (void) mkdir_parents(to, 0755);
        if (symlink(from, to) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", to);

        return 0;
}

static int create_root_device(void) {
        return create_device("root", SYSTEMD_VERITYSETUP_SERVICE_ROOT, arg_root_hash, arg_root_data_what, arg_root_hash_what, arg_root_options);
}

static int create_usr_device(void) {
        return create_device("usr", SYSTEMD_VERITYSETUP_SERVICE_USR, arg_usr_hash, arg_usr_data_what, arg_usr_hash_what, arg_usr_options);
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        if (proc_cmdline_key_streq(key, "systemd.verity")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse verity= kernel command line switch %s. Ignoring.", value);
                else
                        arg_enabled = r;

        } else if (streq(key, "veritytab")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse veritytab= kernel command line switch %s. Ignoring.", value);
                else
                        arg_read_veritytab = r;

        } else if (proc_cmdline_key_streq(key, "roothash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_root_hash, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_root_data")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_root_data_what, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_root_hash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_root_hash_what, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_root_options")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_root_options, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "usrhash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_usr_hash, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_usr_data")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_usr_data_what, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_usr_hash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_usr_hash_what, value);
                if (r < 0)
                        return log_oom();

        } else if (proc_cmdline_key_streq(key, "systemd.verity_usr_options")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = free_and_strdup(&arg_usr_options, value);
                if (r < 0)
                        return log_oom();

        }

        return 0;
}

static int determine_device(
                const char *name,
                const char *hash,
                char **data_what,
                char **hash_what) {

        sd_id128_t data_uuid, verity_uuid;
        _cleanup_free_ void *m = NULL;
        size_t l;
        int r;

        assert(name);
        assert(data_what);
        assert(hash_what);

        if (!hash)
                return 0;

        if (*data_what && *hash_what)
                return 0;

        r = unhexmem(hash, strlen(hash), &m, &l);
        if (r < 0)
                return log_error_errno(r, "Failed to parse hash: %s", hash);
        if (l < sizeof(sd_id128_t)) {
                log_debug("Root hash for %s is shorter than 128 bits (32 characters), ignoring for discovering verity partition.", name);
                return 0;
        }

        if (!*data_what) {
                memcpy(&data_uuid, m, sizeof(data_uuid));

                *data_what = path_join("/dev/disk/by-partuuid", SD_ID128_TO_UUID_STRING(data_uuid));
                if (!*data_what)
                        return log_oom();
        }

        if (!*hash_what) {
                memcpy(&verity_uuid, (uint8_t*) m + l - sizeof(verity_uuid), sizeof(verity_uuid));

                *hash_what = path_join("/dev/disk/by-partuuid", SD_ID128_TO_UUID_STRING(verity_uuid));
                if (!*hash_what)
                        return log_oom();
        }

        log_info("Using data device %s and hash device %s for %s.", *data_what, *hash_what, name);

        return 1;
}

static int determine_devices(void) {
        int r;

        r = determine_device("root", arg_root_hash, &arg_root_data_what, &arg_root_hash_what);
        if (r < 0)
                return r;

        return determine_device("usr", arg_usr_hash, &arg_usr_data_what, &arg_usr_hash_what);
}

static int create_disk(
                const char *name,
                const char *data_device,
                const char *hash_device,
                const char *roothash,
                const char *options,
                const char *source) {

        _cleanup_free_ char *n = NULL, *dd = NULL, *du = NULL, *hd = NULL, *hu = NULL, *e = NULL,
                            *du_escaped = NULL, *hu_escaped = NULL, *name_escaped = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *dmname;
        bool noauto, nofail, netdev, attach_in_initrd;
        int r;

        assert(name);
        assert(data_device);
        assert(hash_device);
        assert(roothash);

        noauto = fstab_test_yes_no_option(options, "noauto\0" "auto\0");
        nofail = fstab_test_yes_no_option(options, "nofail\0" "fail\0");
        netdev = fstab_test_option(options, "_netdev\0");
        attach_in_initrd = fstab_test_option(options, "x-initrd.attach\0");

        name_escaped = specifier_escape(name);
        if (!name_escaped)
                return log_oom();

        e = unit_name_escape(name);
        if (!e)
                return log_oom();

        du = fstab_node_to_udev_node(data_device);
        if (!du)
                return log_oom();

        hu = fstab_node_to_udev_node(hash_device);
        if (!hu)
                return log_oom();

        r = unit_name_build("systemd-veritysetup", e, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        du_escaped = specifier_escape(du);
        if (!du_escaped)
                return log_oom();

        hu_escaped = specifier_escape(hu);
        if (!hu_escaped)
                return log_oom();

        r = unit_name_from_path(du, ".device", &dd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = unit_name_from_path(hu, ".device", &hd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest, NULL, n, &f);
        if (r < 0)
                return r;

        r = generator_write_veritysetup_unit_section(f, source);
        if (r < 0)
                return r;

        if (netdev)
                fprintf(f, "After=remote-fs-pre.target\n");

        /* If initrd takes care of attaching the disk then it should also detach it during shutdown. */
        if (!attach_in_initrd)
                fprintf(f, "Conflicts=umount.target\n");

        if (!nofail)
                fprintf(f,
                        "Before=%s\n",
                        netdev ? "remote-veritysetup.target" : "veritysetup.target");

        if (path_startswith(du, "/dev/"))
                fprintf(f,
                        "BindsTo=%s\n"
                        "After=%s\n"
                        "Before=umount.target\n",
                        dd, dd);
        else
                /* For loopback devices, add systemd-tmpfiles-setup-dev.service
                   dependency to ensure that loopback support is available in
                   the kernel (/dev/loop-control needs to exist) */
                fprintf(f,
                        "RequiresMountsFor=%s\n"
                        "Requires=systemd-tmpfiles-setup-dev.service\n"
                        "After=systemd-tmpfiles-setup-dev.service\n",
                        du_escaped);

        if (path_startswith(hu, "/dev/"))
                fprintf(f,
                        "BindsTo=%s\n"
                        "After=%s\n"
                        "Before=umount.target\n",
                        hd, hd);
        else
                /* For loopback devices, add systemd-tmpfiles-setup-dev.service
                   dependency to ensure that loopback support is available in
                   the kernel (/dev/loop-control needs to exist) */
                fprintf(f,
                        "RequiresMountsFor=%s\n"
                        "Requires=systemd-tmpfiles-setup-dev.service\n"
                        "After=systemd-tmpfiles-setup-dev.service\n",
                        hu_escaped);

        r = generator_write_veritysetup_service_section(f, name, du_escaped, hu_escaped, roothash, options);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", n);

        if (!noauto) {
                r = generator_add_symlink(arg_dest,
                                          netdev ? "remote-veritysetup.target" : "veritysetup.target",
                                          nofail ? "wants" : "requires", n);
                if (r < 0)
                        return r;
        }

        dmname = strjoina("dev-mapper-", e, ".device");
        return generator_add_symlink(arg_dest, dmname, "requires", n);
}

static int add_veritytab_devices(void) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned veritytab_line = 0;
        int r;

        if (!arg_read_veritytab)
                return 0;

        r = fopen_unlocked(arg_veritytab, "re", &f);
        if (r < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", arg_veritytab);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL, *name = NULL, *data_device = NULL, *hash_device = NULL,
                                    *roothash = NULL, *options = NULL;
                char *l, *data_uuid, *hash_uuid;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", arg_veritytab);
                if (r == 0)
                        break;

                veritytab_line++;

                l = strstrip(line);
                if (IN_SET(l[0], 0, '#'))
                        continue;

                r = sscanf(l, "%ms %ms %ms %ms %ms", &name, &data_device, &hash_device, &roothash, &options);
                if (!IN_SET(r, 4, 5)) {
                        log_error("Failed to parse %s:%u, ignoring.", arg_veritytab, veritytab_line);
                        continue;
                }

                data_uuid = startswith(data_device, "UUID=");
                if (!data_uuid)
                        data_uuid = path_startswith(data_device, "/dev/disk/by-uuid/");

                hash_uuid = startswith(hash_device, "UUID=");
                if (!hash_uuid)
                        hash_uuid = path_startswith(hash_device, "/dev/disk/by-uuid/");

                r = create_disk(name,
                                data_device,
                                hash_device,
                                roothash,
                                options,
                                arg_veritytab);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);

        arg_veritytab = getenv("SYSTEMD_VERITYTAB") ?: "/etc/veritytab";

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse kernel command line: %m");

        if (!arg_enabled)
                return 0;

        r = add_veritytab_devices();
        if (r < 0)
                return r;

        r = determine_devices();
        if (r < 0)
                return r;

        r = create_root_device();
        if (r < 0)
                return r;

        return create_usr_device();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
