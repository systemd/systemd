/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "dropin.h"
#include "efi-loader.h"
#include "efivars.h"
#include "errno-util.h"
#include "factory-reset.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "initrd-util.h"
#include "loop-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-name.h"
#include "virt.h"

typedef enum MountPointFlags {
        MOUNT_RW         = 1 << 0,
        MOUNT_GROWFS     = 1 << 1,
        MOUNT_MEASURE    = 1 << 2,
        MOUNT_VALIDATEFS = 1 << 3,
} MountPointFlags;

static const char *arg_dest = NULL;
static const char *arg_dest_late = NULL;
static bool arg_enabled = true;
static GptAutoRoot arg_auto_root = _GPT_AUTO_ROOT_INVALID;
static GptAutoRoot arg_auto_usr = _GPT_AUTO_ROOT_INVALID;
static VeritySettings arg_verity_settings = VERITY_SETTINGS_DEFAULT;
static bool arg_swap_enabled = true;
static char *arg_root_fstype = NULL;
static char *arg_root_options = NULL;
static int arg_root_rw = -1;
static char *arg_usr_fstype = NULL;
static char *arg_usr_options = NULL;
static ImagePolicy *arg_image_policy = NULL;
static ImageFilter *arg_image_filter = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_root_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_filter, image_filter_freep);

#define LOADER_PARTITION_IDLE_USEC (120 * USEC_PER_SEC)

static int add_cryptsetup(
                const char *id,
                const char *what,
                const char *mount_opts,
                MountPointFlags flags,
                bool require,
                char **ret_device) {

#if HAVE_LIBCRYPTSETUP
        _cleanup_free_ char *e = NULL, *n = NULL, *d = NULL, *options = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(id);
        assert(what);

        r = unit_name_from_path(what, ".device", &d);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        e = unit_name_escape(id);
        if (!e)
                return log_oom();

        r = unit_name_build("systemd-cryptsetup", e, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest_late, /* source= */ NULL, n, &f);
        if (r < 0)
                return r;

        r = generator_write_cryptsetup_unit_section(f, NULL);
        if (r < 0)
                return r;

        fprintf(f,
                "Before=umount.target cryptsetup.target\n"
                "Conflicts=umount.target\n"
                "BindsTo=%s\n"
                "After=%s\n",
                d, d);

        if (!FLAGS_SET(flags, MOUNT_RW)) {
                options = strdup("read-only");
                if (!options)
                        return log_oom();
        }

        r = efi_measured_uki(LOG_WARNING);
        if (r > 0)
                /* Enable TPM2 based unlocking automatically, if we have a TPM. See #30176. */
                if (!strextend_with_separator(&options, ",", "tpm2-device=auto"))
                        return log_oom();

        if (FLAGS_SET(flags, MOUNT_MEASURE)) {
                /* We only measure the root volume key into PCR 15 if we are booted with sd-stub (i.e. in a
                 * UKI), and sd-stub measured the UKI. We do this in order not to step into people's own PCR
                 * assignment, under the assumption that people who are fine to use sd-stub with its PCR
                 * assignments are also OK with our PCR 15 use here. */
                if (r > 0)
                        if (!strextend_with_separator(&options, ",", "tpm2-measure-pcr=yes,tpm2-measure-keyslot-nvpcr=yes"))
                                return log_oom();
                if (r == 0)
                        log_debug("Will not measure volume key of volume '%s', not booted via systemd-stub with measurements enabled.", id);
        }

        r = generator_write_cryptsetup_service_section(f, id, what, NULL, options);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write file %s: %m", n);

        r = generator_write_device_timeout(arg_dest_late, what, mount_opts, /* filtered= */ NULL);
        if (r < 0)
                return r;

        r = generator_add_symlink(arg_dest_late, d, "wants", n);
        if (r < 0)
                return r;

        const char *dmname = strjoina("dev-mapper-", e, ".device");

        if (require) {
                r = generator_add_symlink(arg_dest_late, "cryptsetup.target", "requires", n);
                if (r < 0)
                        return r;

                r = generator_add_symlink(arg_dest_late, dmname, "requires", n);
                if (r < 0)
                        return r;
        }

        r = write_drop_in_format(arg_dest_late, dmname, 50, "job-timeout",
                                 "# Automatically generated by systemd-gpt-auto-generator\n\n"
                                 "[Unit]\n"
                                 "JobTimeoutSec=infinity"); /* the binary handles timeouts anyway */
        if (r < 0)
                log_warning_errno(r, "Failed to write device timeout drop-in, ignoring: %m");

        if (ret_device) {
                char *s;

                s = path_join("/dev/mapper", id);
                if (!s)
                        return log_oom();

                *ret_device = s;
        }

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Partition is encrypted, but systemd-gpt-auto-generator was compiled without libcryptsetup support.");
#endif
}

#if ENABLE_EFI
static int add_veritysetup(
                const char *id,
                const char *data_what,
                const char *hash_what,
                const char *mount_opts,
                MountPointFlags flags) {

#if HAVE_LIBCRYPTSETUP
        int r;

        assert(id);
        assert(data_what);
        assert(hash_what);

        _cleanup_free_ char *dd = NULL;
        r = unit_name_from_path(data_what, ".device", &dd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate data device unit name: %m");

        _cleanup_free_ char *dh = NULL;
        r = unit_name_from_path(hash_what, ".device", &dh);
        if (r < 0)
                return log_error_errno(r, "Failed to generate hash device unit name: %m");

        _cleanup_free_ char *e = unit_name_escape(id);
        if (!e)
                return log_oom();

        _cleanup_free_ char *n = NULL;
        r = unit_name_build("systemd-veritysetup", e, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        _cleanup_fclose_ FILE *f = NULL;
        r = generator_open_unit_file(arg_dest_late, /* source= */ NULL, n, &f);
        if (r < 0)
                return r;

        r = generator_write_veritysetup_unit_section(f, /* source= */ NULL);
        if (r < 0)
                return r;

        fprintf(f,
                "Before=veritysetup.target\n"
                "BindsTo=%1$s %2$s\n"
                "After=%1$s %2$s\n",
                dd, dh);

        _cleanup_free_ char *options =
                strdup("root-hash-signature=auto"); /* auto means: derive signature from udev property ID_DISSECT_PART_ROOTHASH_SIG */
        if (!options)
                return log_oom();

        if (FLAGS_SET(flags, MOUNT_MEASURE)) {
                r = efi_measured_uki(LOG_WARNING);
                if (r > 0 && !strextend_with_separator(&options, ",", "tpm2-measure-nvpcr=yes"))
                        return log_oom();
                if (r == 0)
                        log_debug("Will not measure root hash/signature of volume '%s', not booted via systemd-stub with measurements enabled.", id);
        }

        r = generator_write_veritysetup_service_section(
                        f,
                        id,
                        data_what,
                        hash_what,
                        /* roothash= */ NULL,        /* NULL means: derive root hash from udev property ID_DISSECT_PART_ROOTHASH */
                        options);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write file %s: %m", n);

        r = generator_write_device_timeout(arg_dest_late, data_what, mount_opts, /* filtered= */ NULL);
        if (r < 0)
                return r;

        r = generator_write_device_timeout(arg_dest_late, hash_what, mount_opts, /* filtered= */ NULL);
        if (r < 0)
                return r;

        r = generator_add_symlink(arg_dest_late, dd, "wants", n);
        if (r < 0)
                return r;

        r = generator_add_symlink(arg_dest_late, dh, "wants", n);
        if (r < 0)
                return r;

        _cleanup_free_ char *dmname = NULL;
        dmname = strjoin("dev-mapper-", e, ".device");
        if (!dmname)
                return log_oom();

        r = write_drop_in_format(
                        arg_dest_late,
                        dmname, 50, "job-timeout",
                        "# Automatically generated by systemd-gpt-auto-generator\n\n"
                        "[Unit]\n"
                        "JobTimeoutSec=infinity"); /* the binary handles timeouts anyway */
        if (r < 0)
                return log_error_errno(r, "Failed to write device timeout drop-in: %m");

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "Partition is Verity protected, but systemd-gpt-auto-generator was compiled without libcryptsetup support.");
#endif
}
#endif

static int add_mount(
                const char *id,
                const char *what,
                const char *where,
                const char *fstype,
                MountPointFlags flags,
                const char *options,
                const char *description,
                const char *post) {

        _cleanup_free_ char *unit = NULL, *crypto_what = NULL, *opts_filtered = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Note that we don't apply specifier escaping on the input strings here, since we know they are not configured
         * externally, but all originate from our own sources here, and hence we know they contain no % characters that
         * could potentially be understood as specifiers. */

        assert(id);
        assert(what);
        assert(where);
        assert(description);

        log_debug("Adding %s: %s fstype=%s", where, what, fstype ?: "(any)");

        if (streq_ptr(fstype, "crypto_LUKS")) {
                /* Mount options passed are determined by partition_pick_mount_options(), whose result
                 * is known to not contain timeout options. */
                r = add_cryptsetup(id, what, /* mount_opts= */ NULL, flags, /* require= */ true, &crypto_what);
                if (r < 0)
                        return r;

                what = crypto_what;
                fstype = NULL;
        } else if (fstype) {
                r = dissect_fstype_ok(fstype);
                if (r < 0)
                        return log_error_errno(r, "Unable to determine of dissected file system type '%s' is permitted: %m", fstype);
                if (!r)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIDRM),
                                        "Refusing to automatically mount uncommon file system '%s' to '%s'.",
                                        fstype, where);
        }

        r = generator_write_device_timeout(arg_dest_late, what, options, &opts_filtered);
        if (r < 0)
                return r;

        r = unit_name_from_path(where, ".mount", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest_late, /* source= */ NULL, unit, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=%s\n"
                "Documentation=man:systemd-gpt-auto-generator(8)\n",
                description);

        if (post)
                fprintf(f, "Before=%s\n", post);

        /* NB: here we do not write to arg_dest_late, but to arg_dest! We typically leave the normal
         * generator drop-in dir for explicit configuration via systemd-fstab-generator or similar, and put
         * out automatic configuration in the arg_dest_late directory. But this one is an exception, since we
         * need to override the static version of the fsck root service file. */
        r = generator_write_fsck_deps(f, arg_dest, what, where, fstype, opts_filtered);
        if (r < 0)
                return r;

        r = generator_write_blockdev_dependency(f, what);
        if (r < 0)
                return r;

        fprintf(f,
                "\n"
                "[Mount]\n"
                "What=%s\n"
                "Where=%s\n",
                what, where);

        if (fstype)
                fprintf(f, "Type=%s\n", fstype);

        if (opts_filtered)
                fprintf(f, "Options=%s\n", opts_filtered);

        r = generator_write_mount_timeout(f, where, opts_filtered);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", unit);

        if (FLAGS_SET(flags, MOUNT_VALIDATEFS)) {
                r = generator_hook_up_validatefs(arg_dest_late, where, post);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, MOUNT_GROWFS)) {
                r = generator_hook_up_growfs(arg_dest_late, where, post);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, MOUNT_MEASURE)) {
                r = generator_hook_up_pcrfs(arg_dest_late, where, post);
                if (r < 0)
                        return r;
        }

        if (post) {
                r = generator_add_symlink(arg_dest_late, post, "requires", unit);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int path_is_busy(const char *where) {
        int r;

        assert(where);

        /* already a mountpoint; generators run during reload */
        r = path_is_mount_point_full(where, /* root= */ NULL, AT_SYMLINK_FOLLOW);
        if (r > 0)
                return false;
        /* The directory will be created by the mount or automount unit when it is started. */
        if (r == -ENOENT)
                return false;

        if (r < 0)
                return log_warning_errno(r, "Cannot check if \"%s\" is a mount point: %m", where);

        /* not a mountpoint but it contains files */
        r = dir_is_empty(where, /* ignore_hidden_or_backup= */ false);
        if (r == -ENOTDIR) {
                log_debug("\"%s\" is not a directory, ignoring.", where);
                return true;
        } else if (r < 0)
                return log_warning_errno(r, "Cannot check if \"%s\" is empty: %m", where);
        else if (r == 0) {
                log_debug("\"%s\" already populated, ignoring.", where);
                return true;
        }

        return false;
}

static int add_partition_mount(
                PartitionDesignator d,
                DissectedPartition *p,
                const char *id,
                const char *where,
                const char *description) {

        _cleanup_free_ char *options = NULL;
        int r;

        assert(p);

        r = path_is_busy(where);
        if (r != 0)
                return r < 0 ? r : 0;

        r = partition_pick_mount_options(
                        d,
                        dissected_partition_fstype(p),
                        p->rw,
                        /* discard= */ true,
                        &options,
                        /* ret_ms_flags= */ NULL);
        if (r < 0)
                return r;

        return add_mount(
                        id,
                        p->node,
                        where,
                        p->fstype,
                        (p->rw ? MOUNT_RW : 0) |
                        MOUNT_VALIDATEFS |
                        (p->growfs ? MOUNT_GROWFS : 0) |
                        (STR_IN_SET(id, "root", "var") ? MOUNT_MEASURE : 0), /* by default measure rootfs and /var, since they contain the "identity" of the system */
                        options,
                        description,
                        SPECIAL_LOCAL_FS_TARGET);
}

static int add_partition_swap(DissectedPartition *p) {
        const char *what;
        _cleanup_free_ char *name = NULL, *crypto_what = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(p);
        assert(p->node);

        if (!arg_swap_enabled)
                return 0;

        /* Disable the swap auto logic if at least one swap is defined in /etc/fstab, see #6192. */
        r = fstab_has_fstype("swap");
        if (r < 0)
                return log_error_errno(r, "Failed to parse fstab: %m");
        if (r > 0) {
                log_debug("swap specified in fstab, ignoring.");
                return 0;
        }

        if (streq_ptr(p->fstype, "crypto_LUKS")) {
                r = add_cryptsetup("swap", p->node, /* mount_opts= */ NULL, MOUNT_RW, /* require= */ true, &crypto_what);
                if (r < 0)
                        return r;
                what = crypto_what;
        } else
                what = p->node;

        log_debug("Adding swap: %s", what);

        r = unit_name_from_path(what, ".swap", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest_late, /* source= */ NULL, name, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=Swap Partition\n"
                "Documentation=man:systemd-gpt-auto-generator(8)\n");

        r = generator_write_blockdev_dependency(f, what);
        if (r < 0)
                return r;

        fprintf(f,
                "\n"
                "[Swap]\n"
                "What=%s\n",
                what);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", name);

        return generator_add_symlink(arg_dest_late, SPECIAL_SWAP_TARGET, "wants", name);
}

static int add_automount(
                const char *id,
                const char *what,
                const char *where,
                const char *fstype,
                MountPointFlags flags,
                const char *options,
                const char *description,
                usec_t timeout) {

        _cleanup_free_ char *unit = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(id);
        assert(where);
        assert(description);

        r = add_mount(id,
                      what,
                      where,
                      fstype,
                      flags,
                      options,
                      description,
                      /* post= */ NULL);
        if (r < 0)
                return r;

        r = unit_name_from_path(where, ".automount", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest_late, /* source= */ NULL, unit, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=%s\n"
                "Documentation=man:systemd-gpt-auto-generator(8)\n"
                "[Automount]\n"
                "Where=%s\n"
                "TimeoutIdleSec="USEC_FMT"\n",
                description,
                where,
                timeout / USEC_PER_SEC);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit %s: %m", unit);

        return generator_add_symlink(arg_dest_late, SPECIAL_LOCAL_FS_TARGET, "wants", unit);
}

static int add_partition_xbootldr(DissectedPartition *p) {
        _cleanup_free_ char *options = NULL;
        int r;

        assert(p);
        assert(!in_initrd());

        r = path_is_busy("/boot");
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        r = partition_pick_mount_options(
                        PARTITION_XBOOTLDR,
                        dissected_partition_fstype(p),
                        /* rw= */ true,
                        /* discard= */ false,
                        &options,
                        /* ret_ms_flags= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to determine default mount options for /boot/: %m");

        return add_automount(
                        "boot",
                        p->node,
                        "/boot",
                        p->fstype,
                        MOUNT_RW,
                        options,
                        "Boot Loader Partition",
                        LOADER_PARTITION_IDLE_USEC);
}

#if ENABLE_EFI
static int add_partition_esp(DissectedPartition *p, bool has_xbootldr) {
        const char *esp_path = NULL, *id = NULL;
        _cleanup_free_ char *options = NULL;
        int r;

        assert(p);
        assert(!in_initrd());

        /* Check if there's an existing fstab entry for ESP. If so, we just skip the gpt-auto logic. */
        r = fstab_has_node(p->node);
        if (r < 0)
                log_warning_errno(r, "Failed to check if fstab entry for device '%s' exists, ignoring: %m",
                                  p->node);
        if (r > 0)
                return 0;

        /* If XBOOTLDR partition is not present and /boot/ is unused and empty, we'll take that.
         * Otherwise, if /efi/ is unused and empty (or missing), we'll take that.
         * Otherwise, we do nothing. */
        if (!has_xbootldr) {
                r = path_is_busy("/boot");
                if (r < 0)
                        return r;
                if (r == 0) {
                        esp_path = "/boot";
                        id = "boot";
                }
        }

        if (!esp_path) {
                r = path_is_busy("/efi");
                if (r < 0)
                        return r;
                if (r > 0)
                        return 0;

                esp_path = "/efi";
                id = "efi";
        }

        r = partition_pick_mount_options(
                        PARTITION_ESP,
                        dissected_partition_fstype(p),
                        /* rw= */ true,
                        /* discard= */ false,
                        &options,
                        /* ret_ms_flags= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to determine default mount options for %s: %m", esp_path);

        return add_automount(
                        id,
                        p->node,
                        esp_path,
                        p->fstype,
                        MOUNT_RW,
                        options,
                        "EFI System Partition Automount",
                        LOADER_PARTITION_IDLE_USEC);
}
#else
static int add_partition_esp(DissectedPartition *p, bool has_xbootldr) {
        return 0;
}
#endif

static int add_partition_root_rw(DissectedPartition *p) {
        const char *path;
        int r;

        assert(p);
        assert(!in_initrd());

        /* Invoked on the main system (not initrd), to honour GPT flag 60 on the root fs (ro) */

        if (arg_root_rw >= 0) {
                log_debug("Parameter ro/rw specified on kernel command line, not generating drop-in for systemd-remount-fs.service.");
                return 0;
        }

        if (!p->rw) {
                log_debug("Root partition marked read-only in GPT partition table, not generating drop-in for systemd-remount-fs.service.");
                return 0;
        }

        r = generator_enable_remount_fs_service(arg_dest_late);
        if (r < 0)
                return r;

        path = strjoina(arg_dest_late, "/systemd-remount-fs.service.d/50-remount-rw.conf");

        r = write_string_file(path,
                              "# Automatically generated by systemd-gpt-auto-generator\n\n"
                              "[Service]\n"
                              "Environment=SYSTEMD_REMOUNT_ROOT_RW=1\n",
                              WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_NOFOLLOW|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write drop-in file %s: %m", path);

        return 0;
}

static int add_partition_root_growfs(DissectedPartition *p) {

        assert(p);
        assert(!in_initrd());

        /* Invoked on the main system (not initrd), to honour GPT flag 59 on the root fs (growfs) */

        if (!p->growfs) {
                log_debug("Root partition not marked for growing the file system in the GPT partition table, not generating drop-in for systemd-growfs-root.service.");
                return 0;
        }

        return generator_hook_up_growfs(arg_dest_late, "/", SPECIAL_LOCAL_FS_TARGET);
}

static int add_partition_root_flags(DissectedPartition *p) {
        int r = 0;

        assert(p);
        assert(!in_initrd());

        RET_GATHER(r, add_partition_root_growfs(p));
        RET_GATHER(r, add_partition_root_rw(p));

        return r;
}

#if ENABLE_EFI
static int add_root_cryptsetup(void) {
#if HAVE_LIBCRYPTSETUP

        assert(arg_auto_root != GPT_AUTO_ROOT_OFF);

        /* If a device /dev/gpt-auto-root-luks or /dev/disk/by-designator/root-luks appears, then make it
         * pull in systemd-cryptsetup@root.service, which sets it up, and causes /dev/gpt-auto-root or
         * /dev/disk/by-designator/root to appear which is all we are looking for. */

        const char *bdev =
                IN_SET(arg_auto_root, GPT_AUTO_ROOT_DISSECT, GPT_AUTO_ROOT_DISSECT_FORCE) ?
                "/dev/disk/by-designator/root-luks" : "/dev/gpt-auto-root-luks";

        if (IN_SET(arg_auto_root, GPT_AUTO_ROOT_FORCE, GPT_AUTO_ROOT_DISSECT_FORCE)) {
                /* Similar logic as in add_root_mount(), see below */
                FactoryResetMode f = factory_reset_mode();
                if (f < 0)
                        log_warning_errno(f, "Failed to determine whether we are in factory reset mode, assuming not: %m");

                if (IN_SET(f, FACTORY_RESET_ON, FACTORY_RESET_COMPLETE))
                        bdev =
                                IN_SET(arg_auto_root, GPT_AUTO_ROOT_DISSECT, GPT_AUTO_ROOT_DISSECT_FORCE) ?
                                "/dev/disk/by-designator/root-luks-ignore-factory-reset" :
                                "/dev/gpt-auto-root-luks-ignore-factory-reset";
        }

        return add_cryptsetup(
                        "root",
                        bdev,
                        arg_root_options,
                        MOUNT_RW|MOUNT_MEASURE,
                        /* require= */ false,
                        /* ret_device= */ NULL);
#else
        return 0;
#endif
}
#endif

static int add_root_mount(void) {
#if ENABLE_EFI
        _cleanup_free_ char *options = NULL;
        int r;

        /* Explicitly disabled? Then exit immediately */
        if (arg_auto_root == GPT_AUTO_ROOT_OFF)
                return 0;

        /* Neither explicitly enabled nor disabled? Then decide based on the EFI partition variables to be set */
        if (arg_auto_root < 0) {
                if (!is_efi_boot()) {
                        log_debug("Not an EFI boot, not creating root mount.");
                        return 0;
                }

                r = efi_loader_get_device_part_uuid(/* ret= */ NULL);
                if (r == -ENOENT) {
                        log_notice("EFI loader partition unknown, not processing %s.\n"
                                   "(The boot loader did not set EFI variable LoaderDevicePartUUID.)",
                                   in_initrd() ? "/sysroot" : "/");
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to read loader partition UUID: %m");
        }

        /* OK, we shall look for a root device, so let's wait for a root device to show up.  A udev rule will
         * create the link for us under the right name.
         *
         * There are two distinct names: the /dev/gpt-auto-root-ignore-factory-reset symlink is created for
         * the root partition if factory reset mode is enabled or complete, and the /dev/gpt-auto-root
         * symlink is only created if factory reset mode is off or already complete (thus taking factory
         * reset state into account). In scenarios where the root disk is partially reformatted during
         * factory reset the latter is the link to use, otherwise the former (so that we don't accidentally
         * mount a root partition too early that is about to be wiped and replaced by another one). */

        const char *bdev =
                IN_SET(arg_auto_root, GPT_AUTO_ROOT_DISSECT, GPT_AUTO_ROOT_DISSECT_FORCE) ?
                "/dev/disk/by-designator/root" : "/dev/gpt-auto-root";
        if (IN_SET(arg_auto_root, GPT_AUTO_ROOT_FORCE, GPT_AUTO_ROOT_DISSECT_FORCE)) {
                FactoryResetMode f = factory_reset_mode();
                if (f < 0)
                        log_warning_errno(f, "Failed to determine whether we are in factory reset mode, assuming not: %m");

                if (IN_SET(f, FACTORY_RESET_ON, FACTORY_RESET_COMPLETE))
                        bdev =
                                IN_SET(arg_auto_root, GPT_AUTO_ROOT_DISSECT, GPT_AUTO_ROOT_DISSECT_FORCE) ?
                                "/dev/disk/by-designator/root-ignore-factory-reset" :
                                "/dev/gpt-auto-root-ignore-factory-reset";
        }

        if (in_initrd()) {
                r = generator_write_initrd_root_device_deps(arg_dest_late, bdev);
                if (r < 0)
                        return 0;

                r = add_root_cryptsetup();
                if (r < 0)
                        return r;

                /* If a device /dev/disk/by-designator/root-verity or
                 * /dev/disk/by-designator/root-verity-data appears, then make it pull in
                 * systemd-cryptsetup@root.service, which sets it up, and causes /dev/disk/by-designator/root
                 * to appear. */
                r = add_veritysetup(
                                "root",
                                "/dev/disk/by-designator/root-verity-data",
                                "/dev/disk/by-designator/root-verity",
                                arg_root_options,
                                MOUNT_MEASURE);
                if (r < 0)
                        return r;
        }

        /* Note that we do not need to enable systemd-remount-fs.service here. If /etc/fstab exists,
         * systemd-fstab-generator will pull it in for us, and otherwise add_partition_root_flags() will do
         * it, after the initrd transition. */

        r = partition_pick_mount_options(
                        PARTITION_ROOT,
                        arg_root_fstype,
                        arg_root_rw > 0,
                        /* discard= */ true,
                        &options,
                        /* ret_ms_flags= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to pick root mount options: %m");

        if (arg_root_options)
                if (!strextend_with_separator(&options, ",", arg_root_options))
                        return log_oom();

        return add_mount(
                        "root",
                        bdev,
                        in_initrd() ? "/sysroot" : "/",
                        arg_root_fstype,
                        (arg_root_rw > 0 ? MOUNT_RW : 0) |
                        (in_initrd() ? MOUNT_VALIDATEFS : 0) |
                        MOUNT_MEASURE,
                        options,
                        "Root Partition",
                        in_initrd() ? SPECIAL_INITRD_ROOT_FS_TARGET : SPECIAL_LOCAL_FS_TARGET);
#else
        return 0;
#endif
}

static int add_usr_mount(void) {
#if ENABLE_EFI
        int r;

        /* /usr/ discovery must be enabled explicitly. */
        if (arg_auto_usr <= 0)
                return 0;

        /* We do not support the other gpt-auto modes for /usr/, but the parser should already have checked that. */
        assert(arg_auto_usr == GPT_AUTO_ROOT_DISSECT);

        if (arg_root_fstype && !arg_usr_fstype) {
                arg_usr_fstype = strdup(arg_root_fstype);
                if (!arg_usr_fstype)
                        return log_oom();
        }

        if (arg_root_options && !arg_usr_options) {
                arg_usr_options = strdup(arg_root_options);
                if (!arg_usr_options)
                        return log_oom();
        }

        if (in_initrd()) {
                r = add_cryptsetup(
                                "usr",
                                "/dev/disk/by-designator/usr-luks",
                                arg_usr_options,
                                MOUNT_RW|MOUNT_MEASURE,
                                /* require= */ false,
                                /* ret_device= */ NULL);
                if (r < 0)
                        return r;

                /* If a device /dev/disk/by-designator/usr-verity or
                 * /dev/disk/by-designator/usr-verity-data appears, then make it pull in
                 * systemd-cryptsetup@usr.service, which sets it up, and causes /dev/disk/by-designator/usr
                 * to appear. */
                r = add_veritysetup(
                                "usr",
                                "/dev/disk/by-designator/usr-verity-data",
                                "/dev/disk/by-designator/usr-verity",
                                arg_usr_options,
                                MOUNT_MEASURE);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *options = NULL;
        r = partition_pick_mount_options(
                        PARTITION_USR,
                        arg_usr_fstype,
                        /* rw= */ false,
                        /* discard= */ true,
                        &options,
                        /* ret_ms_flags= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to pick /usr/ mount options: %m");

        if (arg_usr_options)
                if (!strextend_with_separator(&options, ",", arg_usr_options))
                        return log_oom();

        r = add_mount("usr",
                      "/dev/disk/by-designator/usr",
                      in_initrd() ? "/sysusr/usr" : "/usr",
                      arg_usr_fstype,
                      /* flags= */ 0,
                      options,
                      "/usr/ Partition",
                      in_initrd() ? SPECIAL_INITRD_USR_FS_TARGET : SPECIAL_LOCAL_FS_TARGET);
        if (r < 0)
                return r;

        if (in_initrd()) {
                log_debug("Synthesizing entry what=/sysusr/usr where=/sysroot/usr opts=bind");

                r = add_mount("usr-bind",
                              "/sysusr/usr",
                              "/sysroot/usr",
                              /* fstype= */ NULL,
                              MOUNT_VALIDATEFS,
                              "bind",
                              "/usr/ Partition (Final)",
                              SPECIAL_INITRD_FS_TARGET);
                if (r < 0)
                        return r;
        }
#endif
        return 0;
}

static int process_loader_partitions(DissectedPartition *esp, DissectedPartition *xbootldr) {
        sd_id128_t loader_uuid;
        int r;

        assert(esp);
        assert(xbootldr);

        /* If any paths in fstab look similar to our favorite paths for ESP or XBOOTLDR, we just exit
         * early. We also don't bother with cases where one is configured explicitly and the other shall be
         * mounted automatically. */

        r = fstab_has_mount_point_prefix_strv(STRV_MAKE("/boot", "/efi"));
        if (r > 0) {
                log_debug("Found mount entries in the /boot/ or /efi/ hierarchies in fstab, not generating ESP or XBOOTLDR mounts.");
                return 0;
        }
        if (r < 0)
                log_debug_errno(r, "Failed to check fstab existing paths, ignoring: %m");

        if (!is_efi_boot()) {
                log_debug("Not an EFI boot, skipping loader partition UUID check.");
                goto mount;
        }

        /* Let's check if LoaderDevicePartUUID points to either ESP or XBOOTLDR. We prefer it pointing
         * to the ESP, but we accept XBOOTLDR too. If it points to neither of them, don't mount any
         * loader partitions, since they are not the ones used for booting. */

        r = efi_loader_get_device_part_uuid(&loader_uuid);
        if (r == -ENOENT) {
                log_debug_errno(r, "EFI loader partition unknown, skipping ESP and XBOOTLDR mounts.");
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read loader partition UUID, ignoring: %m");

        if (esp->found && sd_id128_equal(esp->uuid, loader_uuid))
                goto mount;

        if (xbootldr->found && sd_id128_equal(xbootldr->uuid, loader_uuid)) {
                log_debug("LoaderDevicePartUUID points to XBOOTLDR partition.");
                goto mount;
        }

        log_debug("LoaderDevicePartUUID points to neither ESP nor XBOOTLDR, ignoring.");
        return 0;

mount:
        r = 0;

        if (xbootldr->found)
                RET_GATHER(r, add_partition_xbootldr(xbootldr));
        if (esp->found)
                RET_GATHER(r, add_partition_esp(esp, xbootldr->found));

        return r;
}

static int enumerate_partitions(dev_t devnum) {
        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_free_ char *devname = NULL;
        int r;

        assert(!in_initrd());

        /* Run on the final root fs (not in the initrd), to mount auxiliary partitions, and hook in rw
         * remount and growfs of the root partition */

        r = block_get_whole_disk(devnum, &devnum);
        if (r < 0)
                return log_debug_errno(r, "Failed to get whole block device for " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devnum));

        r = devname_from_devnum(S_IFBLK, devnum, &devname);
        if (r < 0)
                return log_debug_errno(r, "Failed to get device node of " DEVNUM_FORMAT_STR ": %m",
                                       DEVNUM_FORMAT_VAL(devnum));

        /* Let's take a LOCK_SH lock on the block device, in case udevd is already running. If we don't take
         * the lock, udevd might end up issuing BLKRRPART in the middle, and we don't want that, since that
         * might remove all partitions while we are operating on them. */
        r = loop_device_open_from_path(devname, O_RDONLY, LOCK_SH, &loop);
        if (r < 0)
                return log_debug_errno(r, "Failed to open %s: %m", devname);

        r = dissect_loop_device(
                        loop,
                        &arg_verity_settings,
                        /* mount_options= */ NULL,
                        arg_image_policy ?: &image_policy_host,
                        arg_image_filter,
                        DISSECT_IMAGE_GPT_ONLY|
                        DISSECT_IMAGE_USR_NO_ROOT|
                        DISSECT_IMAGE_DISKSEQ_DEVNODE|
                        DISSECT_IMAGE_ALLOW_EMPTY,
                        /* NB! Unlike most other places where we dissect block devices we do not use
                         * DISSECT_IMAGE_ADD_PARTITION_DEVICES here: we want that the kernel finds the
                         * devices, and udev probes them before we mount them via .mount units much later
                         * on. And thus we also don't set DISSECT_IMAGE_PIN_PARTITION_DEVICES here, because
                         * we don't actually mount anything immediately. */
                        &m);
        if (r < 0) {
                bool ok = r == -ENOPKG;
                dissect_log_error(ok ? LOG_DEBUG : LOG_ERR, r, devname, NULL);
                return ok ? 0 : r;
        }

        if (m->partitions[PARTITION_SWAP].found)
                RET_GATHER(r, add_partition_swap(m->partitions + PARTITION_SWAP));

        RET_GATHER(r, process_loader_partitions(m->partitions + PARTITION_ESP, m->partitions + PARTITION_XBOOTLDR));

        if (m->partitions[PARTITION_HOME].found)
                RET_GATHER(r, add_partition_mount(PARTITION_HOME, m->partitions + PARTITION_HOME,
                                                  "home", "/home", "Home Partition"));

        if (m->partitions[PARTITION_SRV].found)
                RET_GATHER(r, add_partition_mount(PARTITION_SRV, m->partitions + PARTITION_SRV,
                                                  "srv", "/srv", "Server Data Partition"));

        if (m->partitions[PARTITION_VAR].found)
                RET_GATHER(r, add_partition_mount(PARTITION_VAR, m->partitions + PARTITION_VAR,
                                                  "var", "/var", "Variable Data Partition"));

        if (m->partitions[PARTITION_TMP].found)
                RET_GATHER(r, add_partition_mount(PARTITION_TMP, m->partitions + PARTITION_TMP,
                                                  "var-tmp", "/var/tmp", "Temporary Data Partition"));

        if (m->partitions[PARTITION_ROOT].found)
                RET_GATHER(r, add_partition_root_flags(m->partitions + PARTITION_ROOT));

        return r;
}

static int add_mounts(void) {
        dev_t devno;
        int r;

        if (in_initrd())
                return 0;

        r = blockdev_get_root(LOG_ERR, &devno);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("Skipping automatic GPT dissection logic, root file system not backed by a (single) whole block device.");
                return 0;
        }

        return enumerate_partitions(devno);
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.gpt_auto") ||
            proc_cmdline_key_streq(key, "rd.systemd.gpt_auto")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse gpt-auto switch \"%s\", ignoring: %m", value);
                else
                        arg_enabled = r;

        } else if (streq(key, "root")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                /* Disable root disk logic if there's a root= value specified (unless it happens to be
                 * "gpt-auto" or "gpt-auto-force") */

                arg_auto_root = parse_gpt_auto_root("root=", value);
                assert(arg_auto_root >= 0);

        } else if (streq(key, "roothash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                /* Disable root disk logic if there's roothash= defined (i.e. verity enabled) */

                arg_auto_root = GPT_AUTO_ROOT_OFF;
                log_debug("Disabling root partition auto-detection, roothash= is set.");

                arg_verity_settings.designator = PARTITION_ROOT;

                iovec_done(&arg_verity_settings.root_hash);
                r = unhexmem(value, &arg_verity_settings.root_hash.iov_base, &arg_verity_settings.root_hash.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse roothash= from kernel command line: %m");

        } else if (streq(key, "usrhash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                arg_verity_settings.designator = PARTITION_USR;

                iovec_done(&arg_verity_settings.root_hash);
                r = unhexmem(value, &arg_verity_settings.root_hash.iov_base, &arg_verity_settings.root_hash.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse usrhash= from kernel command line: %m");

        } else if (streq(key, "rootfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_fstype, value);

        } else if (streq(key, "rootflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_root_options, ",", value))
                        return log_oom();

        } else if (streq(key, "mount.usr")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                /* Disable root disk logic if there's a root= value specified (unless it happens to be
                 * "gpt-auto" or "gpt-auto-force") */

                arg_auto_usr = parse_gpt_auto_root("mount.usr=", value);
                assert(arg_auto_usr >= 0);

                if (IN_SET(arg_auto_usr, GPT_AUTO_ROOT_ON, GPT_AUTO_ROOT_FORCE, GPT_AUTO_ROOT_DISSECT_FORCE)) {
                        log_warning("'gpt-auto', 'gpt-auto-force' and 'dissect-force' are not supported for mount.usr=. Automatically resorting to mount.usr=dissect mode instead.");
                        arg_auto_usr = GPT_AUTO_ROOT_DISSECT;
                }

        } else if (streq(key, "mount.usrfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_fstype, empty_to_null(value));

        } else if (streq(key, "mount.usrflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_usr_options, ",", value))
                        return log_oom();

        } else if (streq(key, "rw") && !value)
                arg_root_rw = true;
        else if (streq(key, "ro") && !value)
                arg_root_rw = false;
        else if (proc_cmdline_key_streq(key, "systemd.image_policy"))
                return parse_image_policy_argument(value, &arg_image_policy);
        else if (proc_cmdline_key_streq(key, "systemd.image_filter")) {
                _cleanup_(image_filter_freep) ImageFilter *f = NULL;

                r = image_filter_parse(value, &f);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse image filter: %s", value);

                image_filter_free(arg_image_filter);
                arg_image_filter = TAKE_PTR(f);

        } else if (streq(key, "systemd.swap")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse swap switch \"%s\", ignoring: %m", value);
                else
                        arg_swap_enabled = r;

                if (!arg_swap_enabled)
                        log_debug("Disabling swap partitions auto-detection, systemd.swap=no is defined.");

        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);
        assert_se(arg_dest_late = dest_late);

        if (detect_container() > 0) {
                log_debug("In a container, exiting.");
                return 0;
        }

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (!arg_enabled) {
                log_debug("Disabled, exiting.");
                return 0;
        }

        r = 0;
        RET_GATHER(r, add_root_mount());
        RET_GATHER(r, add_usr_mount());
        RET_GATHER(r, add_mounts());

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
