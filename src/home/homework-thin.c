/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "dm-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "gpt.h"
#include "home-util.h"
#include "homework-thin.h"
#include "log.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-util.h"
#include "user-record.h"
#include "user-record-util.h"

#define HOME_THIN_TAG "systemd-homed"
#define HOME_THIN_CREATION_TAG_PREFIX "systemd-homed.creation-"
#define DISK_SIZE_ROUND_DOWN(x) ((x) & ~(U64_MB - 1))

typedef struct ThinVolumeInfo {
        char *uuid;
        char *vg;
        char *pool;
        char *name;
        char *attr;
        char **tags;
} ThinVolumeInfo;

typedef struct ThinPoolInfo {
        char *vg;
        char *name;
        char *attr;
        char *when_full;
        char *data_percent;
        char *metadata_percent;
        char *health;
        char *monitor;
        uint64_t size;
        uint64_t vg_free;
} ThinPoolInfo;

static void thin_volume_info_done(ThinVolumeInfo *info) {
        if (!info)
                return;

        free(info->uuid);
        free(info->vg);
        free(info->pool);
        free(info->name);
        free(info->attr);
        strv_free(info->tags);
}

static void thin_pool_info_done(ThinPoolInfo *info) {
        if (!info)
                return;

        free(info->vg);
        free(info->name);
        free(info->attr);
        free(info->when_full);
        free(info->data_percent);
        free(info->metadata_percent);
        free(info->health);
        free(info->monitor);
}

static int thin_volume_creation_tag(sd_id128_t creation_id, char **ret) {
        _cleanup_free_ char *tag = NULL;

        assert(ret);

        if (sd_id128_is_null(creation_id))
                return -EINVAL;

        if (asprintf(&tag,
                     HOME_THIN_CREATION_TAG_PREFIX SD_ID128_FORMAT_STR,
                     SD_ID128_FORMAT_VAL(creation_id)) < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(tag);
        return 0;
}

static int run_lvm_full(char * const argv[], char **ret_stdout, int *ret_exit_status) {
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        _cleanup_close_ int output_fd = -EBADF;
        int exit_status, r;

        assert(argv);
        assert(argv[0]);

        if (ret_stdout) {
                output_fd = memfd_new("homed-lvm-output");
                if (output_fd < 0)
                        return log_error_errno(output_fd, "Failed to allocate LVM output buffer: %m");
        }

        r = pidref_safe_fork_full(
                        "(homed-lvm)",
                        (int[]) { -EBADF, ret_stdout ? output_fd : STDERR_FILENO, STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG,
                        &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to fork LVM command: %m");
        if (r == 0) {
                if (setenv("LC_ALL", "C", 1) < 0) {
                        log_error_errno(errno, "Failed to select a stable LVM output locale: %m");
                        _exit(EXIT_FAILURE);
                }
                execvp(argv[0], argv);
                log_error_errno(errno, "Failed to execute %s: %m", argv[0]);
                _exit(EXIT_FAILURE);
        }

        r = pidref_wait_for_terminate_and_check(
                        argv[0],
                        &pidref,
                        WAIT_LOG_ABNORMAL | (ret_exit_status ? 0 : WAIT_LOG_NON_ZERO_EXIT_STATUS));
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS && !ret_exit_status)
                return -EPROTO;
        exit_status = r;

        if (ret_stdout) {
                r = read_full_file_full(
                                output_fd,
                                /* filename= */ NULL,
                                /* offset= */ 0,
                                /* size= */ 64U * 1024U,
                                /* flags= */ 0,
                                /* bind_name= */ NULL,
                                ret_stdout,
                                /* ret_size= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to read LVM output: %m");
        }

        if (ret_exit_status)
                *ret_exit_status = exit_status;

        return 0;
}

static int run_lvm(char * const argv[], char **ret_stdout) {
        return run_lvm_full(argv, ret_stdout, /* ret_exit_status= */ NULL);
}

static int split_pool(const char *pool, char **ret_vg, char **ret_pool) {
        _cleanup_free_ char *vg = NULL, *pool_name = NULL;
        const char *slash;

        assert(pool);
        assert(ret_vg);
        assert(ret_pool);

        slash = strchr(pool, '/');
        if (!slash || slash == pool || isempty(slash + 1) || strchr(slash + 1, '/'))
                return -EINVAL;

        vg = strndup(pool, slash - pool);
        pool_name = strdup(slash + 1);
        if (!vg || !pool_name)
                return -ENOMEM;
        if (!filename_is_valid(vg) || !filename_is_valid(pool_name))
                return -EINVAL;

        *ret_vg = TAKE_PTR(vg);
        *ret_pool = TAKE_PTR(pool_name);
        return 0;
}

int home_thin_volume_make_path(UserRecord *h, const char *pool, char **ret_path, char **ret_name) {
        _cleanup_free_ char *name = NULL, *path = NULL, *pool_name = NULL, *vg = NULL;
        int r;

        assert(h);
        assert(pool);
        assert(ret_path);
        assert(ret_name);

        r = split_pool(pool, &vg, &pool_name);
        if (r < 0)
                return r;
        if (sd_id128_is_null(h->uuid))
                return -EINVAL;

        if (asprintf(&name, "homed-" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(h->uuid)) < 0)
                return -ENOMEM;

        path = path_join("/dev", vg, name);
        if (!path)
                return -ENOMEM;

        *ret_path = TAKE_PTR(path);
        *ret_name = TAKE_PTR(name);
        return 0;
}

static int thin_volume_partition_name_from_path(const char *path, char **ret) {
        _cleanup_free_ char *name = NULL, *volume = NULL;
        int r;

        assert(path);
        assert(ret);

        r = path_extract_filename(path, &volume);
        if (r < 0)
                return r;
        if (!startswith(volume, "homed-") || strlen(volume) != STRLEN("homed-") + 32)
                return -EINVAL;

        name = strjoin(volume, "-part1");
        if (!name)
                return -ENOMEM;

        *ret = TAKE_PTR(name);
        return 0;
}

static int thin_volume_unmap_partition(const char *volume_path) {
        _cleanup_free_ char *name = NULL;
        usec_t until;
        int r;

        assert(volume_path);

        r = thin_volume_partition_name_from_path(volume_path, &name);
        if (r < 0)
                return r;

        until = usec_add(now(CLOCK_MONOTONIC), 2 * USEC_PER_SEC);
        for (;;) {
                r = dm_remove_device(name);
                if (r != -EBUSY || now(CLOCK_MONOTONIC) >= until)
                        return r;

                (void) usleep_safe(50 * USEC_PER_MSEC);
        }
}

int home_thin_volume_map_partition(
                UserRecord *h,
                int volume_fd,
                uint64_t offset,
                uint64_t size,
                char **ret_path) {

        _cleanup_free_ char *name = NULL, *node = NULL, *uuid = NULL;
        uint64_t volume_size;
        struct stat st;
        int r;

        assert(h);
        assert(volume_fd >= 0);
        assert(ret_path);

        if (sd_id128_is_null(h->uuid))
                return -EINVAL;
        if (offset % 512U != 0 || size == 0 || size % 512U != 0)
                return -EINVAL;

        if (fstat(volume_fd, &st) < 0)
                return -errno;
        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        r = blockdev_get_device_size(volume_fd, &volume_size);
        if (r < 0)
                return r;
        if (offset > volume_size || size > volume_size - offset)
                return -ERANGE;

        if (asprintf(&name,
                     "homed-" SD_ID128_FORMAT_STR "-part1",
                     SD_ID128_FORMAT_VAL(h->uuid)) < 0)
                return -ENOMEM;

        uuid = strjoin("HOMED-PART1-", SD_ID128_TO_STRING(h->uuid));
        node = path_join("/dev/mapper", name);
        if (!uuid || !node)
                return -ENOMEM;

        r = dm_create_linear(name, uuid, st.st_rdev, offset, size);
        if (r < 0)
                return r;

        r = device_wait_for_devlink(node, "block", 45 * USEC_PER_SEC, /* ret= */ NULL);
        if (r < 0) {
                (void) dm_remove_device(name);
                return r;
        }

        *ret_path = TAKE_PTR(node);
        return 1;
}

static int thin_volume_find_partition(UserRecord *h, int fd, uint64_t *ret_offset, uint64_t *ret_size) {
#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        const char *pttype = NULL;
        blkid_partlist partitions;
        int n, r;

        assert(h);
        assert(fd >= 0);
        assert(ret_offset);
        assert(ret_size);

        if (sd_id128_is_null(h->partition_uuid))
                return -ENXIO;

        r = dlopen_libblkid(LOG_DEBUG);
        if (r < 0)
                return r;

        b = sym_blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = sym_blkid_probe_set_device(b, fd, /* off= */ 0, /* size= */ 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        (void) sym_blkid_probe_enable_partitions(b, 1);
        (void) sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return -ENOPKG;

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) sym_blkid_probe_lookup_value(b, "PTTYPE", &pttype, /* len= */ NULL);
        if (!streq_ptr(pttype, "gpt"))
                return -ENOPKG;

        errno = 0;
        partitions = sym_blkid_probe_get_partitions(b);
        if (!partitions)
                return errno_or_else(ENOMEM);

        errno = 0;
        n = sym_blkid_partlist_numof_partitions(partitions);
        if (n < 0)
                return errno_or_else(EIO);

        for (int i = 0; i < n; i++) {
                sd_id128_t uuid;
                blkid_loff_t offset, size;
                blkid_partition partition;

                errno = 0;
                partition = sym_blkid_partlist_get_partition(partitions, i);
                if (!partition)
                        return errno_or_else(EIO);

                if (sd_id128_string_equal(
                                    sym_blkid_partition_get_type_string(partition),
                                    SD_GPT_USER_HOME) <= 0)
                        continue;

                r = blkid_partition_get_uuid_id128(partition, &uuid);
                if (r < 0 || !sd_id128_equal(uuid, h->partition_uuid))
                        continue;

                offset = sym_blkid_partition_get_start(partition);
                size = sym_blkid_partition_get_size(partition);
                if (offset < 0 || (uint64_t) offset > UINT64_MAX / 512U)
                        return -EINVAL;
                if (size <= 0 || (uint64_t) size > UINT64_MAX / 512U)
                        return -EINVAL;

                *ret_offset = (uint64_t) offset * 512U;
                *ret_size = (uint64_t) size * 512U;
                return 1;
        }

        return -ENOPKG;
#else
        return -EOPNOTSUPP;
#endif
}

static int thin_volume_info_parse(const char *text, ThinVolumeInfo *ret) {
        _cleanup_(thin_volume_info_done) ThinVolumeInfo info = {};
        _cleanup_strv_free_ char **fields = NULL;
        int r;

        assert(text);
        assert(ret);

        r = strv_split_full(&fields, text, "|", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r != 6)
                return -EBADMSG;

        STRV_FOREACH(field, fields)
                strstrip(*field);

        info.uuid = strdup(fields[0]);
        info.vg = strdup(fields[1]);
        info.pool = strdup(fields[2]);
        info.name = strdup(fields[3]);
        info.attr = strdup(fields[4]);
        if (!info.uuid || !info.vg || !info.pool || !info.name || !info.attr)
                return -ENOMEM;

        r = strv_split_full(&info.tags, fields[5], ",", /* flags= */ 0);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(info);
        return 0;
}

static int thin_volume_query(const char *path, ThinVolumeInfo *ret) {
        _cleanup_free_ char *text = NULL;
        int r;

        assert(path);
        assert(ret);

        r = run_lvm(STRV_MAKE(
                                "lvs",
                                "--noheadings",
                                "--unquoted",
                                "--separator", "|",
                                "--options", "lv_uuid,vg_name,pool_lv,lv_name,lv_attr,lv_tags",
                                path),
                    &text);
        if (r < 0)
                return r;

        r = thin_volume_info_parse(strstrip(text), ret);
        if (r < 0)
                return log_error_errno(r, "Unexpected LVM report for '%s': %m", path);

        return 0;
}

static int thin_pool_info_parse(const char *text, ThinPoolInfo *ret) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo info = {};
        _cleanup_strv_free_ char **fields = NULL;
        int r;

        assert(text);
        assert(ret);

        r = strv_split_full(&fields, text, "|", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r != 10)
                return -EBADMSG;

        STRV_FOREACH(field, fields)
                strstrip(*field);

        info.vg = strdup(fields[0]);
        info.name = strdup(fields[1]);
        info.attr = strdup(fields[2]);
        info.when_full = strdup(fields[3]);
        info.data_percent = strdup(fields[4]);
        info.metadata_percent = strdup(fields[5]);
        info.health = strdup(fields[6]);
        info.monitor = strdup(fields[7]);
        if (!info.vg || !info.name || !info.attr || !info.when_full ||
            !info.data_percent || !info.metadata_percent || !info.health || !info.monitor)
                return -ENOMEM;

        r = safe_atou64(fields[8], &info.size);
        if (r < 0)
                return r;
        r = safe_atou64(fields[9], &info.vg_free);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(info);
        return 0;
}

static int thin_pool_query(const char *reference, ThinPoolInfo *ret) {
        _cleanup_free_ char *text = NULL;
        int r;

        assert(reference);
        assert(ret);

        r = run_lvm(STRV_MAKE(
                                "lvs",
                                "--noheadings",
                                "--unquoted",
                                "--separator", "|",
                                "--units", "b",
                                "--nosuffix",
                                "--options",
                                "vg_name,lv_name,lv_attr,lv_when_full,data_percent,metadata_percent,lv_health_status,seg_monitor,lv_size,vg_free",
                                reference),
                    &text);
        if (r < 0)
                return r;

        r = thin_pool_info_parse(strstrip(text), ret);
        if (r < 0)
                return log_error_errno(r, "Unexpected LVM thin-pool report for '%s': %m", reference);

        return 0;
}

int home_thin_pool_default_size(const char *pool, uint64_t *ret_size, uint64_t *ret_backing_size) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo info = {};
        _cleanup_free_ char *pool_name = NULL, *reference = NULL, *vg = NULL;
        uint64_t backing_size, size;
        int r;

        assert(pool);
        assert(ret_size);

        r = split_pool(pool, &vg, &pool_name);
        if (r < 0)
                return log_error_errno(r, "Invalid LVM thin pool '%s': %m", pool);

        reference = strjoin(vg, "/", pool_name);
        if (!reference)
                return -ENOMEM;

        r = thin_pool_query(reference, &info);
        if (r < 0)
                return r;
        if (!streq(info.vg, vg) || !streq(info.name, pool_name))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "LVM report for thin pool %s identified a different volume, refusing.",
                                       reference);

        if (info.size > UINT64_MAX - info.vg_free)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW),
                                       "Backing capacity reported for LVM thin pool %s overflows.", reference);

        backing_size = info.size + info.vg_free;
        size = DISK_SIZE_ROUND_DOWN(MIN(backing_size, USER_DISK_SIZE_MAX));
        if (size < USER_DISK_SIZE_MIN)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "Backing capacity reported for LVM thin pool %s is below the minimum home size.",
                                       reference);

        *ret_size = size;
        if (ret_backing_size)
                *ret_backing_size = backing_size;
        return 0;
}

static int thin_pool_validate_configuration(const char *reference, const ThinPoolInfo *info) {
        assert(reference);
        assert(info);

        if (strlen(info->attr) < 9 || info->attr[0] != 't')
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                       "Configured LVM volume %s is not a thin pool.", reference);
        if (info->attr[1] != 'w')
                return log_error_errno(SYNTHETIC_ERRNO(EROFS),
                                       "LVM thin pool %s is read-only; repair it before using its home areas.",
                                       reference);
        if (IN_SET(info->attr[4], 'c', 'C'))
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                       "LVM thin pool %s requires a metadata check; run lvconvert --repair %s before using its home areas.",
                                       reference, reference);
        if (info->attr[8] != '-')
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "LVM thin pool %s is unhealthy (LV attribute '%c', status '%s'); repair or extend it before using its home areas.",
                                       reference, info->attr[8], strna(info->health));
        if (!isempty(info->health))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "LVM thin pool %s reports health status '%s'; repair or extend it before using its home areas.",
                                       reference, info->health);
        if (!streq(info->when_full, "error"))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "LVM thin pool %s uses when-full mode '%s'; run lvchange --errorwhenfull y %s so allocation failures reach the file system immediately.",
                                       reference, strna(info->when_full), reference);

        return 0;
}

static int thin_pool_validate_usage(const char *reference, const char *kind, const char *value) {
        double percent;
        int r;

        assert(reference);
        assert(kind);
        assert(value);

        r = safe_atod(value, &percent);
        if (r < 0 || !isfinite(percent) || percent < 0 || percent > 100)
                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(ERANGE),
                                       "LVM thin pool %s reported invalid %s usage '%s'.",
                                       reference, kind, value);
        if (percent >= 100)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "LVM thin pool %s has exhausted its %s space (%.2f%%); extend the pool before using its home areas.",
                                       reference, kind, percent);
        if (percent >= 80)
                log_warning("LVM thin pool %s %s usage is high (%.2f%%); extend the pool before it reaches 100%%.",
                            reference, kind, percent);
        else
                log_debug("LVM thin pool %s %s usage is %.2f%%.", reference, kind, percent);

        return 0;
}

static int thin_pool_prepare(const char *pool) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo info = {};
        _cleanup_free_ char *pool_name = NULL, *reference = NULL, *vg = NULL;
        int r;

        assert(pool);

        r = split_pool(pool, &vg, &pool_name);
        if (r < 0)
                return log_error_errno(r, "Invalid LVM thin pool '%s': %m", pool);

        reference = strjoin(vg, "/", pool_name);
        if (!reference)
                return -ENOMEM;

        r = thin_pool_query(reference, &info);
        if (r < 0)
                return r;
        if (!streq(info.vg, vg) || !streq(info.name, pool_name))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "LVM report for thin pool %s identified a different volume, refusing.",
                                       reference);

        r = thin_pool_validate_configuration(reference, &info);
        if (r < 0)
                return r;

        /* Usage and target health are only authoritative while the pool is active. Activating the pool does
         * not activate any home volume, and lets us reject exhaustion before creating or exposing one. */
        r = run_lvm(STRV_MAKE(
                                "lvchange",
                                "--ignoreactivationskip",
                                "--activate", "y",
                                reference),
                    /* ret_stdout= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to activate LVM thin pool %s for its health check: %m", reference);

        thin_pool_info_done(&info);
        info = (ThinPoolInfo) {};
        r = thin_pool_query(reference, &info);
        if (r < 0)
                return r;

        r = thin_pool_validate_configuration(reference, &info);
        if (r < 0)
                return r;
        if (info.attr[4] != 'a' || info.attr[6] != 't')
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "LVM thin pool %s did not activate with a usable thin-pool target (attributes '%s').",
                                       reference, info.attr);

        r = thin_pool_validate_usage(reference, "data", info.data_percent);
        if (r < 0)
                return r;
        r = thin_pool_validate_usage(reference, "metadata", info.metadata_percent);
        if (r < 0)
                return r;

        if (!streq(info.monitor, "monitored"))
                log_warning("LVM thin pool %s is not monitored by dmeventd (status '%s'); enable monitoring with lvchange --monitor y %s and configure automatic extension.",
                            reference, strna(info.monitor), reference);

        return 0;
}

static int thin_volume_query_optional(
                const char *vg,
                const char *pool,
                const char *name,
                ThinVolumeInfo *ret) {

        _cleanup_(thin_volume_info_done) ThinVolumeInfo pool_info = {};
        _cleanup_free_ char *pool_reference = NULL, *reference = NULL, *text = NULL;
        int exit_status, r;

        assert(vg);
        assert(pool);
        assert(name);
        assert(ret);

        reference = strjoin(vg, "/", name);
        pool_reference = strjoin(vg, "/", pool);
        if (!reference || !pool_reference)
                return -ENOMEM;

        r = run_lvm_full(STRV_MAKE(
                                "lvs",
                                "--noheadings",
                                "--unquoted",
                                "--separator", "|",
                                "--options", "lv_uuid,vg_name,pool_lv,lv_name,lv_attr,lv_tags",
                                reference),
                         &text,
                         &exit_status);
        if (r < 0)
                return r;

        if (exit_status == EXIT_SUCCESS) {
                r = thin_volume_info_parse(strstrip(text), ret);
                if (r < 0)
                        return log_error_errno(r, "Unexpected LVM report for '%s': %m", reference);

                return 1;
        }
        if (exit_status != 5)
                return -EPROTO;

        /* A missing row is authoritative only while the pool that would contain it is visible. Otherwise
         * the VG might merely be unavailable during early boot, and forgetting recovery state would orphan
         * the LV when its PVs appear later. */
        text = mfree(text);
        r = run_lvm_full(STRV_MAKE(
                                "lvs",
                                "--noheadings",
                                "--unquoted",
                                "--separator", "|",
                                "--options", "lv_uuid,vg_name,pool_lv,lv_name,lv_attr,lv_tags",
                                pool_reference),
                         &text,
                         &exit_status);
        if (r < 0)
                return r;
        if (exit_status != EXIT_SUCCESS)
                return -ENXIO;

        r = thin_volume_info_parse(strstrip(text), &pool_info);
        if (r < 0)
                return log_error_errno(r, "Unexpected LVM report for thin pool '%s': %m", pool_reference);
        if (!streq(pool_info.vg, vg) || !streq(pool_info.name, pool) || !startswith(pool_info.attr, "t"))
                return -EREMCHG;

        return 0;
}

static int thin_volume_validate(UserRecord *h, char **ret_path) {
        _cleanup_(thin_volume_info_done) ThinVolumeInfo info = {};
        _cleanup_free_ char *expected_name = NULL, *vg = NULL, *pool = NULL, *path = NULL, *reference = NULL;
        int r;

        assert(h);

        if (!h->thin_pool && !h->thin_volume && !h->thin_volume_uuid)
                return 0;
        if (!h->thin_pool || !h->thin_volume || !h->thin_volume_uuid)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Incomplete LVM thin-volume binding, refusing.");
        if (user_record_storage(h) != USER_LUKS)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "LVM thin-volume binding requires LUKS storage, refusing.");

        r = split_pool(h->thin_pool, &vg, &pool);
        if (r < 0)
                return log_error_errno(r, "Invalid LVM thin-pool binding '%s': %m", h->thin_pool);
        if (!filename_is_valid(h->thin_volume) || isempty(h->thin_volume_uuid))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Invalid LVM thin-volume binding, refusing.");

        r = home_thin_volume_make_path(h, h->thin_pool, &path, &expected_name);
        if (r < 0)
                return r;
        if (!streq(h->thin_volume, expected_name))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "LVM thin-volume name does not match the home record UUID, refusing.");

        reference = strjoin(vg, "/", h->thin_volume);
        if (!reference)
                return -ENOMEM;

        r = thin_volume_query(reference, &info);
        if (r < 0)
                return r;

        if (!streq(info.uuid, h->thin_volume_uuid) ||
            !streq(info.vg, vg) ||
            !streq(info.pool, pool) ||
            !streq(info.name, h->thin_volume) ||
            !strv_contains(info.tags, HOME_THIN_TAG))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "LVM volume %s does not match its systemd-homed binding, refusing.", path);

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return 1;
}

int home_thin_volume_create(
                UserRecord *h,
                const char *pool,
                uint64_t size,
                sd_id128_t creation_id,
                char **ret_path,
                char **ret_name,
                char **ret_uuid) {

        _cleanup_(thin_volume_info_done) ThinVolumeInfo info = {};
        _cleanup_free_ char *creation_tag = NULL, *vg = NULL, *pool_name = NULL, *name = NULL, *path = NULL,
                *size_arg = NULL;
        int r;

        assert(h);
        assert(pool);
        assert(size > 0);
        assert(!sd_id128_is_null(creation_id));
        assert(ret_path);
        assert(ret_name);
        assert(ret_uuid);

        r = split_pool(pool, &vg, &pool_name);
        if (r < 0)
                return log_error_errno(r, "Invalid LVM thin pool '%s': %m", pool);

        r = thin_pool_prepare(pool);
        if (r < 0)
                return r;

        r = home_thin_volume_make_path(h, pool, &path, &name);
        if (r == -EINVAL)
                return log_error_errno(r, "User record has no UUID, refusing to name thin volume.");
        if (r < 0)
                return r;

        if (asprintf(&size_arg, "%" PRIu64 "B", size) < 0)
                return -ENOMEM;

        r = thin_volume_creation_tag(creation_id, &creation_tag);
        if (r < 0)
                return r;

        r = run_lvm(STRV_MAKE(
                                "lvcreate",
                                "--yes",
                                "--activate", "y",
                                "--setactivationskip", "y",
                                "--ignoreactivationskip",
                                "--virtualsize", size_arg,
                                "--thinpool", pool,
                                "--name", name,
                                "--addtag", HOME_THIN_TAG,
                                "--addtag", creation_tag),
                    /* ret_stdout= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to create thin volume %s/%s: %m", vg, name);

        r = thin_volume_query(path, &info);
        if (r < 0) {
                (void) home_thin_volume_remove_created(path);
                return r;
        }
        if (!streq(info.vg, vg) || !streq(info.pool, pool_name) ||
            !streq(info.name, name) ||
            !strv_contains(info.tags, HOME_THIN_TAG) ||
            !strv_contains(info.tags, creation_tag)) {
                (void) home_thin_volume_remove_created(path);
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "New thin volume %s has unexpected LVM metadata.", path);
        }

        *ret_path = TAKE_PTR(path);
        *ret_name = TAKE_PTR(name);
        *ret_uuid = TAKE_PTR(info.uuid);
        return 1;
}

int home_thin_volume_activate(UserRecord *h, bool already_active, char **ret_path) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *mapping = NULL, *path = NULL;
        const char *image_path;
        uint64_t offset, size;
        int r;

        assert(h);

        if (!h->thin_pool && !h->thin_volume && !h->thin_volume_uuid)
                return 0;

        r = thin_volume_validate(h, &path);
        if (r <= 0)
                return r;

        r = thin_pool_prepare(h->thin_pool);
        if (r < 0)
                return r;

        if (already_active) {
                if (ret_path)
                        *ret_path = TAKE_PTR(path);
                return 1;
        }

        r = run_lvm(STRV_MAKE("lvchange", "--ignoreactivationskip", "--activate", "y", path), /* ret_stdout= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to activate thin volume %s: %m", path);

        image_path = user_record_image_path(h);
        if (!image_path || path_equal(image_path, path)) {
                r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                    "Thin-volume binding lacks its inner LUKS device path.");
                goto fail;
        }

        fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                r = log_error_errno(errno, "Failed to open thin volume %s: %m", path);
                goto fail;
        }

        r = thin_volume_find_partition(h, fd, &offset, &size);
        if (r < 0) {
                log_error_errno(r, "Failed to locate the home partition on thin volume %s: %m", path);
                goto fail;
        }

        /* Clear a mapping left behind by an interrupted operation before installing the one described by
         * the authenticated record and the GPT we just validated. A busy mapping is left intact and causes
         * activation to fail safely. */
        r = thin_volume_unmap_partition(path);
        if (r < 0) {
                log_error_errno(r, "Failed to remove stale partition mapping for %s: %m", path);
                goto fail;
        }

        r = home_thin_volume_map_partition(h, fd, offset, size, &mapping);
        if (r < 0) {
                log_error_errno(r, "Failed to map the home partition on thin volume %s: %m", path);
                goto fail;
        }

        r = device_wait_for_devlink(image_path, "block", 45 * USEC_PER_SEC, /* ret= */ NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to wait for thin-volume devlink %s: %m", image_path);
                goto fail;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return 1;

fail:
        (void) home_thin_volume_deactivate_path(path);
        return r;
}

int home_thin_volume_exists(UserRecord *h) {
        _cleanup_(thin_volume_info_done) ThinVolumeInfo info = {};
        _cleanup_free_ char *expected_name = NULL, *path = NULL, *pool = NULL, *vg = NULL;
        int r;

        assert(h);

        if (!h->thin_pool && !h->thin_volume && !h->thin_volume_uuid)
                return 0;
        if (!h->thin_pool || !h->thin_volume || !h->thin_volume_uuid)
                return -EBADMSG;
        if (user_record_storage(h) != USER_LUKS)
                return -EBADMSG;

        r = split_pool(h->thin_pool, &vg, &pool);
        if (r < 0)
                return r;
        if (!filename_is_valid(h->thin_volume) || isempty(h->thin_volume_uuid))
                return -EBADMSG;

        r = home_thin_volume_make_path(h, h->thin_pool, &path, &expected_name);
        if (r < 0)
                return r;
        if (!streq(h->thin_volume, expected_name))
                return -EREMCHG;

        r = thin_volume_query_optional(vg, pool, h->thin_volume, &info);
        if (r <= 0)
                return r;

        if (!streq(info.uuid, h->thin_volume_uuid) ||
            !streq(info.vg, vg) ||
            !streq(info.pool, pool) ||
            !streq(info.name, h->thin_volume) ||
            !strv_contains(info.tags, HOME_THIN_TAG))
                return -EREMCHG;

        return 1;
}

int home_thin_volume_deactivate_path(const char *path) {
        int r;

        assert(path);

        r = thin_volume_unmap_partition(path);
        if (r < 0)
                return log_error_errno(r, "Failed to remove partition mapping for thin volume %s: %m", path);

        r = run_lvm(STRV_MAKE("lvchange", "--activate", "n", path), /* ret_stdout= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to deactivate thin volume %s: %m", path);

        return 1;
}

int home_thin_volume_deactivate(UserRecord *h) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(h);

        r = thin_volume_validate(h, &path);
        if (r <= 0)
                return r;

        return home_thin_volume_deactivate_path(path);
}

int home_thin_volume_remove_created(const char *path) {
        int r;

        assert(path);

        r = thin_volume_unmap_partition(path);
        if (r < 0)
                return r;

        return run_lvm(STRV_MAKE("lvremove", "--yes", path), /* ret_stdout= */ NULL);
}

int home_thin_volume_remove(UserRecord *h) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(h);

        r = home_thin_volume_exists(h);
        if (r <= 0)
                return r;

        r = thin_volume_validate(h, &path);
        if (r < 0)
                return r;
        assert(r > 0);

        r = home_thin_volume_remove_created(path);
        if (r < 0)
                return log_error_errno(r, "Failed to remove thin volume %s: %m", path);

        log_info("Removed systemd-homed thin volume %s.", path);
        return 1;
}

int home_thin_volume_remove_incomplete(UserRecord *h) {
        _cleanup_(thin_volume_info_done) ThinVolumeInfo info = {};
        _cleanup_free_ char *creation_tag = NULL, *expected_name = NULL, *path = NULL, *pool = NULL, *vg = NULL;
        sd_id128_t creation_id;
        int r;

        assert(h);

        if (!h->thin_pool || !h->thin_volume || h->thin_volume_uuid)
                return -EBADMSG;
        if (user_record_storage(h) != USER_LUKS)
                return -EBADMSG;

        r = user_record_get_thin_volume_creation_id(h, &creation_id);
        if (r < 0)
                return r;

        r = thin_volume_creation_tag(creation_id, &creation_tag);
        if (r < 0)
                return r;

        r = split_pool(h->thin_pool, &vg, &pool);
        if (r < 0)
                return r;

        r = home_thin_volume_make_path(h, h->thin_pool, &path, &expected_name);
        if (r < 0)
                return r;
        if (!streq(h->thin_volume, expected_name))
                return -EREMCHG;

        r = thin_volume_query_optional(vg, pool, h->thin_volume, &info);
        if (r <= 0)
                return r;

        /* The deterministic name and the common homed tag are not ownership proof: both can belong to a
         * pre-existing home whose UUID was reused. Only the random tag written by this lvcreate transaction
         * permits recovery to remove the volume. */
        if (!strv_contains(info.tags, creation_tag))
                return 0;

        if (!streq(info.vg, vg) ||
            !streq(info.pool, pool) ||
            !streq(info.name, h->thin_volume) ||
            !strv_contains(info.tags, HOME_THIN_TAG))
                return -EREMCHG;

        r = home_thin_volume_remove_created(path);
        if (r < 0)
                return r;

        log_notice("Removed incomplete systemd-homed thin volume %s.", path);
        return 1;
}
