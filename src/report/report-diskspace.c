/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/statvfs.h>

#include "sd-device.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "json-util.h"
#include "libmount-util.h"
#include "log.h"
#include "metrics.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "report-diskspace.h"
#include "sort-util.h"
#include "stat-util.h"

/* Reports the size of and the disk space still available on all mounted, writable, block device backed file
 * systems, i.e. roughly what df(1) shows. Pseudo file systems (procfs, sysfs, tmpfs, …), network file
 * systems and other file systems not backed by a block device are skipped, as are read-only mounts: their
 * free space is not going to change, and typically is not meaningful anyway (squashfs, erofs, DDIs, …).
 *
 * A file system (i.e. a superblock, identified by its device number) that is mounted in multiple places
 * (bind mounts, btrfs subvolumes, …) is reported only once, under its shortest mount path. */

typedef struct FileSystem {
        dev_t devno;           /* the hashmap key: device number of the superblock */
        struct libmnt_fs *fs;  /* the mount we report the file system under, owned by the mount table */
        int fd;                /* O_PATH fd to the mount point */
        uint64_t free_bytes;
        uint64_t size_bytes;
} FileSystem;

static FileSystem* file_system_free(FileSystem *f) {
        if (!f)
                return NULL;

        safe_close(f->fd);
        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FileSystem*, file_system_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                file_system_hash_ops,
                dev_t, devt_hash_func, devt_compare_func,
                FileSystem, file_system_free);

static const char* file_system_path(const FileSystem *f) {
        assert(f);
        assert(f->fs);

        return ASSERT_PTR(sym_mnt_fs_get_target(f->fs));
}

/* Among the mount points of the same file system we prefer the shortest path, and among equally short ones
 * the alphabetically earlier. */
static bool path_is_preferred(const char *a, const char *b) {
        assert(a);
        assert(b);

        int ret = CMP(strlen(a), strlen(b));
        if (ret != 0)
                return ret;

        return path_compare(a, b);
}

static int file_system_compare(FileSystem *const *a, FileSystem *const *b) {
        return path_compare(file_system_path(*a), file_system_path(*b));
}

static int mount_collect(Hashmap **file_systems, struct libmnt_fs *fs) {
        int r;

        assert(file_systems);
        assert(fs);

        const char *target = sym_mnt_fs_get_target(fs);
        if (!target)
                return 0;

        const char *fstype = sym_mnt_fs_get_fstype(fs);
        if (!fstype)
                return 0;

        if (!fstype_is_blockdev_backed(fstype)) {
                log_debug("Mount '%s' of type %s is not backed by a block device, skipping.", target, fstype);
                return 0;
        }

        /* This covers both file systems that are read-only as a whole, and read-only bind mounts of
         * otherwise writable file systems, since libmount searches both the superblock and the per-mount
         * options here. */
        r = sym_mnt_fs_get_option(fs, "ro", /* value= */ NULL, /* valsz= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to check whether '%s' is mounted read-only: %m", target);
        if (r == 0) {
                log_debug("Mount '%s' is read-only, skipping.", target);
                return 0;
        }

        dev_t devno = sym_mnt_fs_get_devno(fs);
        if (devno == 0) {
                log_debug("Mount '%s' has no device number, skipping.", target);
                return 0;
        }

        FileSystem *existing = hashmap_get(*file_systems, &devno);
        if (existing && !path_is_preferred(target, file_system_path(existing))) {
                log_debug("File system mounted on '%s' is already known as '%s', skipping.",
                          target, file_system_path(existing));
                return 0;
        }

        /* Mount points below a directory we lack access to (or that have been unmounted since the mount
         * table was read) are simply not considered. */
        _cleanup_close_ int fd = open(target, O_PATH|O_CLOEXEC);
        if (fd < 0) {
                log_debug_errno(errno, "Failed to open mount point '%s', ignoring: %m", target);
                return 0;
        }

        /* Make sure the path still refers to the mount we are looking at, and not to something that was
         * mounted on top of it since, shadowing it. Also catches mount points that are hidden entirely. */
        int mnt_id;
        r = path_get_mnt_id_at(fd, /* path= */ NULL, &mnt_id);
        if (r < 0) {
                log_debug_errno(r, "Failed to get mount ID of '%s', ignoring: %m", target);
                return 0;
        }
        if (mnt_id != sym_mnt_fs_get_id(fs)) {
                log_debug("Mount '%s' is shadowed by another mount, skipping.", target);
                return 0;
        }

        struct statfs sfs;
        r = xstatfsat(fd, /* path= */ NULL, &sfs);
        if (r < 0) {
                log_debug_errno(r, "Failed to statfs() '%s', ignoring: %m", target);
                return 0;
        }

        /* Already excluded above based on the mount table, but let's check again on the authoritative data,
         * in case things changed in the meantime. */
        if (FLAGS_SET(sfs.f_flags, ST_RDONLY)) {
                log_debug("Mount '%s' is read-only, skipping.", target);
                return 0;
        }

        if (sfs.f_blocks == 0) {
                log_debug("Mount '%s' has zero size, skipping.", target);
                return 0;
        }

        /* Report the space available to unprivileged users as free, matching what df(1) shows as "Avail".
         * Space reserved for the superuser (typically 5% on ext4) is hence not counted as free. */
        uint64_t size_bytes, free_bytes;

        if (!MUL_SAFE(&free_bytes, (uint64_t) sfs.f_frsize, (uint64_t) sfs.f_bavail) ||
            !MUL_SAFE(&size_bytes, (uint64_t) sfs.f_frsize, (uint64_t) sfs.f_blocks)) {
                log_debug("Sizes of '%s' overflow, skipping.", target);
                return 0;
        }

        _cleanup_(file_system_freep) FileSystem *f = new(FileSystem, 1);
        if (!f)
                return log_oom();

        *f = (FileSystem) {
                .devno = devno,
                .fs = fs,
                .fd = TAKE_FD(fd),
                .free_bytes = free_bytes,
                .size_bytes = size_bytes,
        };

        /* Replace the entry we already have for this file system, if any, by the better one */
        file_system_free(hashmap_remove(*file_systems, &devno));

        if (hashmap_ensure_put(file_systems, &file_system_hash_ops, &f->devno, f) < 0)
                return log_oom();

        TAKE_PTR(f);
        return 0;
}

/* If the file system's backing block device is a stacked one (LUKS-style DM, …), returns the device node of
 * the block device it originates from, chased down through all layers. Returns NULL (and success) if the
 * backing device is not a stacked block device, or is not a block device at all. */
static int file_system_get_originating_source(const FileSystem *f, char **ret) {
        int r;

        assert(f);
        assert(ret);

        /* NB: We do not use f->devno here, but acquire the devno again from the fd. That's because on btrfs
         * we want the devnum of the backing device node, and not of the anymous superblock */
        dev_t devno;
        r = get_block_device_fd(f->fd, &devno);
        if (r < 0) {
                log_debug_errno(r, "Failed to get backing block device of '%s', ignoring: %m", file_system_path(f));
                *ret = NULL;
                return 0;
        }

        /* The mount's device number is the backing block device's (except for file systems that use
         * anonymous device numbers, such as btrfs, which we hence cannot trace this way). */
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        r = sd_device_new_from_devnum(&dev, 'b', devno);
        if (r < 0) {
                log_debug_errno(r, "Failed to get block device " DEVNUM_FORMAT_STR " backing '%s', ignoring: %m",
                                DEVNUM_FORMAT_VAL(f->devno), file_system_path(f));
                *ret = NULL;
                return 0;
        }

        _cleanup_(sd_device_unrefp) sd_device *origin = NULL;
        r = block_device_get_originating(dev, &origin, /* recursive= */ true);
        if (r < 0) {
                if (r != -ENOENT) /* -ENOENT means: not stacked */
                        log_device_debug_errno(dev, r, "Failed to determine originating block device, ignoring: %m");
                *ret = NULL;
                return 0;
        }

        const char *node;
        r = sd_device_get_devname(origin, &node);
        if (r < 0) {
                log_device_debug_errno(origin, r, "Failed to get device node of originating block device, ignoring: %m");
                *ret = NULL;
                return 0;
        }

        return strdup_to(ret, node);
}

static int file_system_send(
                const MetricFamily mf[static 2],
                sd_varlink *link,
                const FileSystem *f) {

        int r;

        assert(mf && mf[0].name && mf[1].name);
        assert(link);
        assert(f);

        _cleanup_free_ char *originating_source = NULL;
        r = file_system_get_originating_source(f, &originating_source);
        if (r < 0)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
        r = sd_json_buildo(
                        &fields,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("source", sym_mnt_fs_get_source(f->fs)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("originatingSource", originating_source),
                        SD_JSON_BUILD_PAIR_STRING("fstype", sym_mnt_fs_get_fstype(f->fs)));
        if (r < 0)
                return log_error_errno(r, "Failed to build metric fields: %m");

        r = metric_build_send_unsigned(mf + 0, link, file_system_path(f), f->free_bytes, fields);
        if (r < 0)
                return r;

        return metric_build_send_unsigned(mf + 1, link, file_system_path(f), f->size_bytes, fields);
}

static int diskspace_generate(
                const MetricFamily mf[static 2],
                sd_varlink *link,
                void *userdata) {

        int r;

        assert(mf);
        assert(link);

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        r = libmount_parse_mountinfo(/* source= */ NULL, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        /* First pass: collect all file systems we care about, keyed by superblock */
        _cleanup_hashmap_free_ Hashmap *file_systems = NULL;
        for (;;) {
                struct libmnt_fs *fs;

                r = sym_mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                r = mount_collect(&file_systems, fs);
                if (r < 0)
                        return r;
        }

        /* Second pass: report them, sorted by mount path for stable output */
        _cleanup_free_ FileSystem **sorted = NULL;
        size_t n = 0;
        FileSystem *f;
        HASHMAP_FOREACH(f, file_systems) {
                if (!GREEDY_REALLOC(sorted, n + 1))
                        return log_oom();

                sorted[n++] = f;
        }

        typesafe_qsort(sorted, n, file_system_compare);

        FOREACH_ARRAY(i, sorted, n) {
                r = file_system_send(mf, link, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily diskspace_metric_family_table[] = {
        /* Keep metrics ordered alphabetically. Both are generated by the same function, attached to the
         * first of them. */
        {
                "io.systemd.DiskSpace.FreeBytes",
                "Per file system metric: disk space available to unprivileged users in bytes, on writable "
                "block device backed file systems (object=mount point, fstype=file system type, "
                "source=backing device, originatingSource=device the backing device is stacked on, if any)",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = diskspace_generate,
        },
        {
                "io.systemd.DiskSpace.SizeBytes",
                "Per file system metric: file system size in bytes, on writable block device backed file "
                "systems (object=mount point, fstype=file system type, source=backing device, "
                "originatingSource=device the backing device is stacked on, if any)",
                METRIC_FAMILY_TYPE_GAUGE,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(diskspace_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(diskspace_metric_family_table, link, parameters, flags, userdata);
}
