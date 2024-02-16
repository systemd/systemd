/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "dropin.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "hashmap.h"
#include "id128-util.h"
#include "log.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"

typedef struct crypto_device {
        char *uuid;
        char *keyfile;
        char *keydev;
        char *headerdev;
        char *datadev;
        char *name;
        char *options;
        bool create;
} crypto_device;

static const char *arg_dest = NULL;
static bool arg_enabled = true;
static bool arg_read_crypttab = true;
static const char *arg_crypttab = NULL;
static const char *arg_runtime_directory = NULL;
static bool arg_allow_list = false;
static Hashmap *arg_disks = NULL;
static char *arg_default_options = NULL;
static char *arg_default_keyfile = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_disks, hashmap_freep);
STATIC_DESTRUCTOR_REGISTER(arg_default_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_default_keyfile, freep);

static int split_locationspec(const char *locationspec, char **ret_file, char **ret_device) {
        _cleanup_free_ char *file = NULL, *device = NULL;
        const char *c;

        assert(ret_file);
        assert(ret_device);

        if (!locationspec) {
                *ret_file = *ret_device = NULL;
                return 0;
        }

        c = strrchr(locationspec, ':');
        if (c) {
                /* The device part has to be either an absolute path to device node (/dev/something,
                 * /dev/foo/something, or even possibly /dev/foo/something:part), or a fstab device
                 * specification starting with LABEL= or similar. The file part has the same syntax.
                 *
                 * Let's try to guess if the second part looks like a device specification, or just part of a
                 * filename with a colon. fstab_node_to_udev_node() will convert the fstab device syntax to
                 * an absolute path. If we didn't get an absolute path, assume that it is just part of the
                 * first file argument. */

                device = fstab_node_to_udev_node(c + 1);
                if (!device)
                        return log_oom();

                if (path_is_absolute(device))
                        file = strndup(locationspec, c-locationspec);
                else {
                        log_debug("Location specification argument contains a colon, but \"%s\" doesn't look like a device specification.\n"
                                  "Assuming that \"%s\" is a single device specification.",
                                  c + 1, locationspec);
                        device = mfree(device);
                        c = NULL;
                }
        }

        if (!c)
                /* No device specified */
                file = strdup(locationspec);

        if (!file)
                return log_oom();

        *ret_file = TAKE_PTR(file);
        *ret_device = TAKE_PTR(device);

        return 0;
}

static int generate_device_mount(
                const char *name,
                const char *device,
                const char *type_prefix, /* "keydev" or "headerdev" */
                const char *device_timeout,
                bool canfail,
                bool readonly,
                char **unit,
                char **mount) {

        _cleanup_free_ char *u = NULL, *where = NULL, *name_escaped = NULL, *device_unit = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;
        usec_t timeout_us;

        assert(name);
        assert(device);
        assert(unit);
        assert(mount);

        r = mkdir_parents(arg_runtime_directory, 0755);
        if (r < 0)
                return r;

        r = mkdir(arg_runtime_directory, 0700);
        if (r < 0 && errno != EEXIST)
                return -errno;

        name_escaped = cescape(name);
        if (!name_escaped)
                return -ENOMEM;

        where = strjoin(arg_runtime_directory, "/", type_prefix, "-", name_escaped);
        if (!where)
                return -ENOMEM;

        r = mkdir(where, 0700);
        if (r < 0 && errno != EEXIST)
                return -errno;

        r = unit_name_from_path(where, ".mount", &u);
        if (r < 0)
                return r;

        r = generator_open_unit_file(arg_dest, NULL, u, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "DefaultDependencies=no\n\n"
                "[Mount]\n"
                "What=%s\n"
                "Where=%s\n"
                "Options=%s%s\n", device, where, readonly ? "ro" : "rw", canfail ? ",nofail" : "");

        if (device_timeout) {
                r = parse_sec_fix_0(device_timeout, &timeout_us);
                if (r >= 0) {
                        r = unit_name_from_path(device, ".device", &device_unit);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate unit name: %m");

                        r = write_drop_in_format(arg_dest, device_unit, 90, "device-timeout",
                                "# Automatically generated by systemd-cryptsetup-generator \n\n"
                                "[Unit]\nJobRunningTimeoutSec=%s", device_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write device drop-in: %m");

                } else
                        log_warning_errno(r, "Failed to parse %s, ignoring: %m", device_timeout);

        }

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        *unit = TAKE_PTR(u);
        *mount = TAKE_PTR(where);

        return 0;
}

static int generate_device_umount(const char *name,
                                  const char *device_mount,
                                  const char *type_prefix, /* "keydev" or "headerdev" */
                                  char **ret_umount_unit) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *u = NULL, *name_escaped = NULL, *mount = NULL;
        int r;

        assert(name);
        assert(ret_umount_unit);

        name_escaped = cescape(name);
        if (!name_escaped)
                return -ENOMEM;

        u = strjoin(type_prefix, "-", name_escaped, "-umount.service");
        if (!u)
                return -ENOMEM;

        r = unit_name_from_path(device_mount, ".mount", &mount);
        if (r < 0)
                return r;

        r = generator_open_unit_file(arg_dest, NULL, u, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "DefaultDependencies=no\n"
                "After=%s\n\n"
                "[Service]\n"
                "ExecStart=-" UMOUNT_PATH " %s\n\n", mount, device_mount);

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        *ret_umount_unit = TAKE_PTR(u);
        return 0;
}

static int print_dependencies(FILE *f, const char* device_path, const char* timeout_value, bool canfail) {
        int r;

        assert(f);
        assert(device_path);

        if (STR_IN_SET(device_path, "-", "none"))
                /* None, nothing to do */
                return 0;

        if (PATH_IN_SET(device_path,
                        "/dev/urandom",
                        "/dev/random",
                        "/dev/hw_random",
                        "/dev/hwrng")) {
                /* RNG device, add random dep */
                fputs("After=systemd-random-seed.service\n", f);
                return 0;
        }

        _cleanup_free_ char *udev_node = fstab_node_to_udev_node(device_path);
        if (!udev_node)
                return log_oom();

        if (path_equal(udev_node, "/dev/null"))
                return 0;

        if (path_startswith(udev_node, "/dev/")) {
                /* We are dealing with a block device, add dependency for corresponding unit */
                _cleanup_free_ char *unit = NULL;

                r = unit_name_from_path(udev_node, ".device", &unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate unit name: %m");

                fprintf(f, "After=%1$s\n", unit);
                if (canfail) {
                        fprintf(f, "Wants=%1$s\n", unit);
                        if (timeout_value) {
                                r = write_drop_in_format(arg_dest, unit, 90, "device-timeout",
                                        "# Automatically generated by systemd-cryptsetup-generator \n\n"
                                        "[Unit]\nJobRunningTimeoutSec=%s", timeout_value);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to write device drop-in: %m");
                        }
                } else
                        fprintf(f, "Requires=%1$s\n", unit);
        } else {
                /* Regular file, add mount dependency */
                _cleanup_free_ char *escaped_path = specifier_escape(device_path);
                if (!escaped_path)
                        return log_oom();

                fprintf(f, "%s=%s\n", canfail ? "WantsMountsFor" : "RequiresMountsFor", escaped_path);
        }

        return 0;
}

static bool attach_in_initrd(const char *name, const char *options) {
        assert(name);

        /* Imply x-initrd.attach in case the volume name is among those defined in the Discoverable Partition
         * Specification for partitions that we require to be mounted during the initrd → host transition,
         * i.e. for the root fs itself, and /usr/. This mirrors similar behaviour in
         * systemd-fstab-generator. */

        return fstab_test_option(options, "x-initrd.attach\0") ||
                STR_IN_SET(name, "root", "usr");
}

static int create_disk(
                const char *name,
                const char *device,
                const char *key_file,
                const char *keydev,
                const char *headerdev,
                const char *options,
                const char *source) {

        _cleanup_free_ char *n = NULL, *d = NULL, *u = NULL, *e = NULL,
                *keydev_mount = NULL, *keyfile_timeout_value = NULL,
                *filtered = NULL, *u_escaped = NULL, *name_escaped = NULL, *header_path = NULL, *key_file_buffer = NULL,
                *tmp_fstype = NULL, *filtered_header = NULL, *headerdev_mount = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *dmname;
        bool noauto, nofail, swap, netdev;
        int r, detached_header, keyfile_can_timeout, tmp;

        assert(name);
        assert(device);

        noauto = fstab_test_yes_no_option(options, "noauto\0" "auto\0");
        nofail = fstab_test_yes_no_option(options, "nofail\0" "fail\0");
        swap = fstab_test_option(options, "swap\0");
        netdev = fstab_test_option(options, "_netdev\0");

        keyfile_can_timeout = fstab_filter_options(options,
                                                   "keyfile-timeout\0",
                                                   NULL, &keyfile_timeout_value, NULL, NULL);
        if (keyfile_can_timeout < 0)
                return log_error_errno(keyfile_can_timeout, "Failed to parse keyfile-timeout= option value: %m");

        detached_header = fstab_filter_options(
                options,
                "header\0",
                NULL,
                &header_path,
                NULL,
                headerdev ? &filtered_header : NULL);
        if (detached_header < 0)
                return log_error_errno(detached_header, "Failed to parse header= option value: %m");

        tmp = fstab_filter_options(options, "tmp\0", NULL, &tmp_fstype, NULL, NULL);
        if (tmp < 0)
                return log_error_errno(tmp, "Failed to parse tmp= option value: %m");

        if (tmp && swap)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Device '%s' cannot be both 'tmp' and 'swap'. Ignoring.",
                                       name);

        name_escaped = specifier_escape(name);
        if (!name_escaped)
                return log_oom();

        e = unit_name_escape(name);
        if (!e)
                return log_oom();

        u = fstab_node_to_udev_node(device);
        if (!u)
                return log_oom();

        r = unit_name_build("systemd-cryptsetup", e, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        u_escaped = specifier_escape(u);
        if (!u_escaped)
                return log_oom();

        r = unit_name_from_path(u, ".device", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        if (keydev && !key_file)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Key device is specified, but path to the key file is missing.");

        r = generator_open_unit_file(arg_dest, NULL, n, &f);
        if (r < 0)
                return r;

        r = generator_write_cryptsetup_unit_section(f, source);
        if (r < 0)
                return r;

        if (netdev)
                fprintf(f, "After=remote-fs-pre.target\n");

        /* If initrd takes care of attaching the disk then it should also detach it during shutdown. */
        if (!attach_in_initrd(name, options))
                fprintf(f,
                        "Conflicts=umount.target\n"
                        "Before=umount.target\n");

        if (keydev) {
                _cleanup_free_ char *unit = NULL, *umount_unit = NULL;

                r = generate_device_mount(
                        name,
                        keydev,
                        "keydev",
                        keyfile_timeout_value,
                        /* canfail = */ keyfile_can_timeout > 0,
                        /* readonly= */ true,
                        &unit,
                        &keydev_mount);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate keydev mount unit: %m");

                r = generate_device_umount(name, keydev_mount, "keydev", &umount_unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate keydev umount unit: %m");

                key_file_buffer = path_join(keydev_mount, key_file);
                if (!key_file_buffer)
                        return log_oom();

                key_file = key_file_buffer;

                fprintf(f, "After=%s\n", unit);
                if (keyfile_can_timeout > 0)
                        fprintf(f, "Wants=%s\n", unit);
                else
                        fprintf(f, "Requires=%s\n", unit);

                if (umount_unit)
                        fprintf(f,
                                "Wants=%s\n"
                                "Before=%s\n",
                                umount_unit,
                                umount_unit
                        );
        }

        if (headerdev) {
                _cleanup_free_ char *unit = NULL, *umount_unit = NULL, *p = NULL;

                r = generate_device_mount(
                        name,
                        headerdev,
                        "headerdev",
                        NULL,
                        /* canfail=  */ false, /* header is always necessary */
                        /* readonly= */ false, /* LUKS2 recovery requires rw header access */
                        &unit,
                        &headerdev_mount);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate header device mount unit: %m");

                r = generate_device_umount(name, headerdev_mount, "headerdev", &umount_unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate header device umount unit: %m");

                p = path_join(headerdev_mount, header_path);
                if (!p)
                        return log_oom();

                free_and_replace(header_path, p);

                if (isempty(filtered_header))
                        p = strjoin("header=", header_path);
                else
                        p = strjoin(filtered_header, ",header=", header_path);

                if (!p)
                        return log_oom();

                free_and_replace(filtered_header, p);
                options = filtered_header;

                fprintf(f, "After=%s\n"
                           "Requires=%s\n", unit, unit);

                if (umount_unit)
                        fprintf(f,
                                "Wants=%s\n"
                                "Before=%s\n",
                                umount_unit,
                                umount_unit
                        );
        }

        if (!nofail)
                fprintf(f,
                        "Before=%s\n",
                        netdev ? "remote-cryptsetup.target" : "cryptsetup.target");

        if (key_file && !keydev) {
                r = print_dependencies(f, key_file,
                        keyfile_timeout_value,
                        /* canfail= */ keyfile_can_timeout > 0 || nofail);
                if (r < 0)
                        return r;
        }

        /* Check if a header option was specified */
        if (detached_header > 0 && !headerdev) {
                r = print_dependencies(f, header_path,
                        /* timeout_value= */ NULL,
                        /* canfail= */ nofail);
                if (r < 0)
                        return r;
        }

        if (path_startswith(u, "/dev/"))
                fprintf(f,
                        "BindsTo=%s\n"
                        "After=%s\n",
                        d, d);
        else
                /* For loopback devices make sure to explicitly load loop.ko, as this code might run very
                 * early where device nodes created via systemd-tmpfiles-setup-dev.service might not be
                 * around yet. Hence let's sync on the module itself. */
                fprintf(f,
                        "RequiresMountsFor=%s\n"
                        "Wants=modprobe@loop.service\n"
                        "After=modprobe@loop.service\n",
                        u_escaped);

        r = generator_write_timeouts(arg_dest, device, name, options, &filtered);
        if (r < 0)
                log_warning_errno(r, "Failed to write device timeout drop-in: %m");

        r = generator_write_cryptsetup_service_section(f, name, u, key_file, filtered);
        if (r < 0)
                return r;

        if (tmp) {
                _cleanup_free_ char *tmp_fstype_escaped = NULL;

                if (tmp_fstype) {
                        tmp_fstype_escaped = specifier_escape(tmp_fstype);
                        if (!tmp_fstype_escaped)
                                return log_oom();
                }

                fprintf(f,
                        "ExecStartPost=" LIBEXECDIR "/systemd-makefs '%s' '/dev/mapper/%s'\n",
                        tmp_fstype_escaped ?: "ext4", name_escaped);
        }

        if (swap)
                fprintf(f,
                        "ExecStartPost=" LIBEXECDIR "/systemd-makefs swap '/dev/mapper/%s'\n",
                        name_escaped);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", n);

        if (!noauto) {
                r = generator_add_symlink(arg_dest,
                                          netdev ? "remote-cryptsetup.target" : "cryptsetup.target",
                                          nofail ? "wants" : "requires", n);
                if (r < 0)
                        return r;
        }

        dmname = strjoina("dev-mapper-", e, ".device");
        r = generator_add_symlink(arg_dest, dmname, "requires", n);
        if (r < 0)
                return r;

        if (!noauto && !nofail) {
                r = write_drop_in(arg_dest, dmname, 40, "device-timeout",
                                  "# Automatically generated by systemd-cryptsetup-generator\n\n"
                                  "[Unit]\n"
                                  "JobTimeoutSec=infinity\n");
                if (r < 0)
                        log_warning_errno(r, "Failed to write device timeout drop-in: %m");
        }

        return 0;
}

static crypto_device* crypt_device_free(crypto_device *d) {
        if (!d)
                return NULL;

        free(d->uuid);
        free(d->keyfile);
        free(d->keydev);
        free(d->name);
        free(d->options);
        return mfree(d);
}

static crypto_device *get_crypto_device(const char *uuid) {
        int r;
        crypto_device *d;

        assert(uuid);

        d = hashmap_get(arg_disks, uuid);
        if (!d) {
                d = new0(struct crypto_device, 1);
                if (!d)
                        return NULL;

                d->uuid = strdup(uuid);
                if (!d->uuid)
                        return mfree(d);

                r = hashmap_put(arg_disks, d->uuid, d);
                if (r < 0) {
                        free(d->uuid);
                        return mfree(d);
                }
        }

        return d;
}

static bool warn_uuid_invalid(const char *uuid, const char *key) {
        assert(key);

        if (!id128_is_valid(uuid)) {
                log_warning("Failed to parse %s= kernel command line switch. UUID is invalid, ignoring.", key);
                return true;
        }

        return false;
}

static int filter_header_device(const char *options,
                                char **ret_headerdev,
                                char **ret_filtered_headerdev_options) {
        int r;
        _cleanup_free_ char *headerfile = NULL, *headerdev = NULL, *headerspec = NULL,
                            *filtered_headerdev = NULL, *filtered_headerspec = NULL;

        assert(ret_headerdev);
        assert(ret_filtered_headerdev_options);

        r = fstab_filter_options(options, "header\0", NULL, &headerspec, NULL, &filtered_headerspec);
        if (r < 0)
                return log_error_errno(r, "Failed to parse header= option value: %m");

        if (r > 0) {
                r = split_locationspec(headerspec, &headerfile, &headerdev);
                if (r < 0)
                        return r;

                if (isempty(filtered_headerspec))
                        filtered_headerdev = strjoin("header=", headerfile);
                else
                        filtered_headerdev = strjoin(filtered_headerspec, ",header=", headerfile);

                if (!filtered_headerdev)
                        return log_oom();
        } else
                filtered_headerdev = TAKE_PTR(filtered_headerspec);

        *ret_filtered_headerdev_options = TAKE_PTR(filtered_headerdev);
        *ret_headerdev = TAKE_PTR(headerdev);

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        _cleanup_free_ char *uuid = NULL, *uuid_value = NULL;
        crypto_device *d;
        int r;

        if (streq(key, "luks")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse luks= kernel command line switch %s. Ignoring.", value);
                else
                        arg_enabled = r;

        } else if (streq(key, "luks.crypttab")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse luks.crypttab= kernel command line switch %s. Ignoring.", value);
                else
                        arg_read_crypttab = r;

        } else if (streq(key, "luks.uuid")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                d = get_crypto_device(startswith(value, "luks-") ?: value);
                if (!d)
                        return log_oom();

                d->create = arg_allow_list = true;

        } else if (streq(key, "luks.options")) {
                _cleanup_free_ char *headerdev = NULL, *filtered_headerdev_options = NULL;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = sscanf(value, "%m[0-9a-fA-F-]=%ms", &uuid, &uuid_value);
                if (r != 2)
                        return free_and_strdup_warn(&arg_default_options, value);

                if (warn_uuid_invalid(uuid, key))
                        return 0;

                d = get_crypto_device(uuid);
                if (!d)
                        return log_oom();

                r = filter_header_device(uuid_value, &headerdev, &filtered_headerdev_options);
                if (r < 0)
                        return r;

                free_and_replace(d->options, filtered_headerdev_options);
                free_and_replace(d->headerdev, headerdev);
        } else if (streq(key, "luks.key")) {
                size_t n;
                _cleanup_free_ char *keyfile = NULL, *keydev = NULL;
                const char *keyspec;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                n = strspn(value, ALPHANUMERICAL "-");
                if (value[n] != '=')
                        return free_and_strdup_warn(&arg_default_keyfile, value);

                uuid = strndup(value, n);
                if (!uuid)
                        return log_oom();

                if (warn_uuid_invalid(uuid, key))
                        return 0;

                d = get_crypto_device(uuid);
                if (!d)
                        return log_oom();

                keyspec = value + n + 1;
                r = split_locationspec(keyspec, &keyfile, &keydev);
                if (r < 0)
                        return r;

                free_and_replace(d->keyfile, keyfile);
                free_and_replace(d->keydev, keydev);
        } else if (streq(key, "luks.data")) {
                size_t n;
                _cleanup_free_ char *datadev = NULL;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                n = strspn(value, ALPHANUMERICAL "-");
                if (value[n] != '=') {
                        log_warning("Failed to parse luks.data= kernel command line switch. UUID is invalid, ignoring.");
                        return 0;
                }

                uuid = strndup(value, n);
                if (!uuid)
                        return log_oom();

                if (warn_uuid_invalid(uuid, key))
                        return 0;

                d = get_crypto_device(uuid);
                if (!d)
                        return log_oom();

                datadev = fstab_node_to_udev_node(value + n + 1);
                if (!datadev)
                        return log_oom();

                free_and_replace(d->datadev, datadev);
        } else if (streq(key, "luks.name")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = sscanf(value, "%m[0-9a-fA-F-]=%ms", &uuid, &uuid_value);
                if (r == 2) {
                        d = get_crypto_device(uuid);
                        if (!d)
                                return log_oom();

                        d->create = arg_allow_list = true;

                        free_and_replace(d->name, uuid_value);
                } else
                        log_warning("Failed to parse luks name switch %s. Ignoring.", value);
        }

        return 0;
}

static int add_crypttab_devices(void) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned crypttab_line = 0;
        int r;

        if (!arg_read_crypttab)
                return 0;

        r = fopen_unlocked(arg_crypttab, "re", &f);
        if (r < 0) {
                if (errno != ENOENT)
                        log_error_errno(errno, "Failed to open %s: %m", arg_crypttab);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL, *name = NULL, *device = NULL, *keyspec = NULL, *options = NULL,
                                    *keyfile = NULL, *keydev = NULL, *headerdev = NULL, *filtered_header = NULL;
                crypto_device *d = NULL;
                char *uuid;
                int k;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", arg_crypttab);
                if (r == 0)
                        break;

                crypttab_line++;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                k = sscanf(line, "%ms %ms %ms %ms", &name, &device, &keyspec, &options);
                if (k < 2 || k > 4) {
                        log_error("Failed to parse %s:%u, ignoring.", arg_crypttab, crypttab_line);
                        continue;
                }

                uuid = startswith(device, "UUID=");
                if (!uuid)
                        uuid = path_startswith(device, "/dev/disk/by-uuid/");
                if (!uuid)
                        uuid = startswith(name, "luks-");
                if (uuid)
                        d = hashmap_get(arg_disks, uuid);

                if (arg_allow_list && !d) {
                        log_info("Not creating device '%s' because it was not specified on the kernel command line.", name);
                        continue;
                }

                r = split_locationspec(keyspec, &keyfile, &keydev);
                if (r < 0)
                        return r;

                if (options && (!d || !d->options)) {
                        r = filter_header_device(options, &headerdev, &filtered_header);
                        if (r < 0)
                                return r;
                        free_and_replace(options, filtered_header);
                }

                r = create_disk(name,
                                device,
                                keyfile,
                                keydev,
                                (d && d->options) ? d->headerdev : headerdev,
                                (d && d->options) ? d->options : options,
                                arg_crypttab);
                if (r < 0)
                        return r;

                if (d)
                        d->create = false;
        }

        return 0;
}

static int add_proc_cmdline_devices(void) {
        int r;
        crypto_device *d;

        HASHMAP_FOREACH(d, arg_disks) {
                _cleanup_free_ char *device = NULL;

                if (!d->create)
                        continue;

                if (!d->name) {
                        d->name = strjoin("luks-", d->uuid);
                        if (!d->name)
                                return log_oom();
                }

                device = strjoin("UUID=", d->uuid);
                if (!device)
                        return log_oom();

                r = create_disk(d->name,
                                d->datadev ?: device,
                                d->keyfile ?: arg_default_keyfile,
                                d->keydev,
                                d->headerdev,
                                d->options ?: arg_default_options,
                                "/proc/cmdline");
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(crypt_device_hash_ops, char, string_hash_func, string_compare_func,
                                              crypto_device, crypt_device_free);

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);

        arg_crypttab = getenv("SYSTEMD_CRYPTTAB") ?: "/etc/crypttab";
        arg_runtime_directory = getenv("RUNTIME_DIRECTORY") ?: "/run/systemd/cryptsetup";

        arg_disks = hashmap_new(&crypt_device_hash_ops);
        if (!arg_disks)
                return log_oom();

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse kernel command line: %m");

        if (!arg_enabled)
                return 0;

        r = add_crypttab_devices();
        if (r < 0)
                return r;

        r = add_proc_cmdline_devices();
        if (r < 0)
                return r;

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
