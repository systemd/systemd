/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2018 Dell Inc.
***/

#include <linux/fs.h>
#include <linux/magic.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "btrfs-util.h"
#include "device-util.h"
#include "devnum-util.h"
#include "efivars.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hibernate-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

#define HIBERNATION_SWAP_THRESHOLD 0.98

void hibernation_device_done(HibernationDevice *device) {
        assert(device);

        free(device->path);
}

int read_fiemap(int fd, struct fiemap **ret) {
        _cleanup_free_ struct fiemap *fiemap = NULL, *result_fiemap = NULL;
        struct stat statinfo;
        uint32_t result_extents = 0;
        uint64_t fiemap_start = 0, fiemap_length;
        const size_t n_extra = DIV_ROUND_UP(sizeof(struct fiemap), sizeof(struct fiemap_extent));

        assert(fd >= 0);
        assert(ret);

        if (fstat(fd, &statinfo) < 0)
                return log_debug_errno(errno, "Cannot determine file size: %m");
        if (!S_ISREG(statinfo.st_mode))
                return -ENOTTY;
        fiemap_length = statinfo.st_size;

        /* Zero this out in case we run on a file with no extents */
        fiemap = calloc(n_extra, sizeof(struct fiemap_extent));
        if (!fiemap)
                return -ENOMEM;

        result_fiemap = malloc_multiply(n_extra, sizeof(struct fiemap_extent));
        if (!result_fiemap)
                return -ENOMEM;

        /*  XFS filesystem has incorrect implementation of fiemap ioctl and
         *  returns extents for only one block-group at a time, so we need
         *  to handle it manually, starting the next fiemap call from the end
         *  of the last extent
         */
        while (fiemap_start < fiemap_length) {
                *fiemap = (struct fiemap) {
                        .fm_start = fiemap_start,
                        .fm_length = fiemap_length,
                        .fm_flags = FIEMAP_FLAG_SYNC,
                };

                /* Find out how many extents there are */
                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                /* Nothing to process */
                if (fiemap->fm_mapped_extents == 0)
                        break;

                /* Resize fiemap to allow us to read in the extents, result fiemap has to hold all
                 * the extents for the whole file. Add space for the initial struct fiemap. */
                if (!greedy_realloc0((void**) &fiemap, n_extra + fiemap->fm_mapped_extents, sizeof(struct fiemap_extent)))
                        return -ENOMEM;

                fiemap->fm_extent_count = fiemap->fm_mapped_extents;
                fiemap->fm_mapped_extents = 0;

                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                /* Resize result_fiemap to allow us to copy in the extents */
                if (!greedy_realloc((void**) &result_fiemap,
                                    n_extra + result_extents + fiemap->fm_mapped_extents, sizeof(struct fiemap_extent)))
                        return -ENOMEM;

                memcpy(result_fiemap->fm_extents + result_extents,
                       fiemap->fm_extents,
                       sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents);

                result_extents += fiemap->fm_mapped_extents;

                /* Highly unlikely that it is zero */
                if (_likely_(fiemap->fm_mapped_extents > 0)) {
                        uint32_t i = fiemap->fm_mapped_extents - 1;

                        fiemap_start = fiemap->fm_extents[i].fe_logical +
                                       fiemap->fm_extents[i].fe_length;

                        if (fiemap->fm_extents[i].fe_flags & FIEMAP_EXTENT_LAST)
                                break;
                }
        }

        memcpy(result_fiemap, fiemap, sizeof(struct fiemap));
        result_fiemap->fm_mapped_extents = result_extents;
        *ret = TAKE_PTR(result_fiemap);
        return 0;
}

static int read_resume_config(dev_t *ret_devno, uint64_t *ret_offset) {
        _cleanup_free_ char *devno_str = NULL, *offset_str = NULL;
        uint64_t offset;
        dev_t devno;
        int r;

        assert(ret_devno);
        assert(ret_offset);

        r = read_one_line_file("/sys/power/resume", &devno_str);
        if (r < 0)
                return log_debug_errno(r, "Failed to read /sys/power/resume: %m");

        r = parse_devnum(devno_str, &devno);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse /sys/power/resume devno '%s': %m", devno_str);

        r = read_one_line_file("/sys/power/resume_offset", &offset_str);
        if (r == -ENOENT) {
                log_debug_errno(r, "Kernel does not expose resume_offset, skipping.");
                offset = UINT64_MAX;
        } else if (r < 0)
                return log_debug_errno(r, "Failed to read /sys/power/resume_offset: %m");
        else {
                r = safe_atou64(offset_str, &offset);
                if (r < 0)
                        return log_debug_errno(r,
                                               "Failed to parse /sys/power/resume_offset '%s': %m", offset_str);
        }

        if (devno == 0 && offset > 0 && offset != UINT64_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Found resume_offset=%" PRIu64 " but resume= is unset, refusing.", offset);

        *ret_devno = devno;
        *ret_offset = offset;

        return 0;
}

/* entry in /proc/swaps */
typedef struct SwapEntry {
        char *path;
        bool swapfile;

        uint64_t size;
        uint64_t used;
        int priority;

        /* Not present in original entry */
        dev_t devno;
        uint64_t offset;
} SwapEntry;

typedef struct SwapEntries {
        SwapEntry *swaps;
        size_t n_swaps;
} SwapEntries;

static void swap_entry_done(SwapEntry *entry) {
        assert(entry);

        free(entry->path);
}

static void swap_entries_done(SwapEntries *entries) {
        assert(entries);

        FOREACH_ARRAY(i, entries->swaps, entries->n_swaps)
                swap_entry_done(i);

        free(entries->swaps);
}

static int swap_entry_get_resume_config(SwapEntry *swap) {
        _cleanup_close_ int fd = -EBADF;
        uint64_t offset_raw;
        struct stat st;
        int r;

        assert(swap);
        assert(swap->path);

        fd = open(swap->path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!swap->swapfile) {
                if (!S_ISBLK(st.st_mode))
                        return -ENOTBLK;

                swap->devno = st.st_rdev;
                swap->offset = 0;
                return 0;
        }

        r = stat_verify_regular(&st);
        if (r < 0)
                return r;

        r = get_block_device_fd(fd, &swap->devno);
        if (r < 0)
                return r;

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if swap file '%s' is on Btrfs: %m", swap->path);
        if (r > 0) {
                r = btrfs_get_file_physical_offset_fd(fd, &offset_raw);
                if (r < 0)
                        return r;
        } else {
                _cleanup_free_ struct fiemap *fiemap = NULL;

                r = read_fiemap(fd, &fiemap);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read extent map for swap file '%s': %m", swap->path);

                offset_raw = fiemap->fm_extents[0].fe_physical;
        }

        swap->offset = offset_raw / page_size();
        return 0;
}

static int read_swap_entries(SwapEntries *ret) {
        _cleanup_(swap_entries_done) SwapEntries entries = {};
        _cleanup_fclose_ FILE *f = NULL;

        assert(ret);

        f = fopen("/proc/swaps", "re");
        if (!f)
                return log_debug_errno(errno, "Failed to open /proc/swaps: %m");

        /* Remove header */
        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");

        for (unsigned i = 1;; i++) {
                _cleanup_(swap_entry_done) SwapEntry swap = {};
                _cleanup_free_ char *type = NULL;
                int k;

                k = fscanf(f,
                           "%ms "       /* device/file path */
                           "%ms "       /* type of swap */
                           "%" PRIu64   /* swap size */
                           "%" PRIu64   /* used */
                           "%i"         /* priority */
                           "\n",
                           &swap.path, &type, &swap.size, &swap.used, &swap.priority);
                if (k == EOF)
                        break;
                if (k != 5)
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse /proc/swaps line %u.", i);

                if (streq(type, "file")) {
                        if (endswith(swap.path, "\\040(deleted)")) {
                                log_debug("Swap file '%s' has been deleted, ignoring.", swap.path);
                                continue;
                        }

                        swap.swapfile = true;

                } else if (streq(type, "partition")) {
                        const char *node;

                        node = path_startswith(swap.path, "/dev/");
                        if (node && startswith(node, "zram")) {
                                log_debug("Swap partition '%s' is a zram device, ignoring.", swap.path);
                                continue;
                        }

                        swap.swapfile = false;

                } else {
                        log_debug("Swap type %s is not supported for hibernation, ignoring device: %s",
                                  type, swap.path);
                        continue;
                }

                if (!GREEDY_REALLOC(entries.swaps, entries.n_swaps + 1))
                        return log_oom_debug();

                entries.swaps[entries.n_swaps++] = TAKE_STRUCT(swap);
        }

        *ret = TAKE_STRUCT(entries);
        return 0;
}

/* Attempt to find a suitable device for hibernation by parsing /proc/swaps, /sys/power/resume, and
 * /sys/power/resume_offset.
 *
 * Beware:
 *  Never use a device or file that hasn't been somehow specified by a user who would also be entrusted
 *  with full system memory access (for example via /sys/power/resume) or that isn't an already active
 *  swap area! Otherwise various security attacks might become possible, for example an attacker could
 *  silently attach such a device and circumvent full disk encryption when it would be automatically used
 *  for hibernation. Also, having a swap area on top of encryption is not per se enough to protect from all
 *  such attacks.
 *
 * Returns:
 *  1 - Values are set in /sys/power/resume and /sys/power/resume_offset.
 *
 *  0 - No values are set in /sys/power/resume and /sys/power/resume_offset.
 *      ret will represent the highest priority swap with most remaining space discovered in /proc/swaps.
 *
 *  Negative value in the case of error */
int find_suitable_hibernation_device_full(HibernationDevice *ret_device, uint64_t *ret_size, uint64_t *ret_used) {
        _cleanup_(swap_entries_done) SwapEntries entries = {};
        SwapEntry *entry = NULL;
        uint64_t resume_config_offset;
        dev_t resume_config_devno;
        int r;

        assert(!ret_size == !ret_used);

        r = read_resume_config(&resume_config_devno, &resume_config_offset);
        if (r < 0)
                return r;

        r = read_swap_entries(&entries);
        if (r < 0)
                return r;
        if (entries.n_swaps == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSPC), "No swap space available for hibernation.");

        FOREACH_ARRAY(swap, entries.swaps, entries.n_swaps) {
                r = swap_entry_get_resume_config(swap);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get devno and offset for swap '%s': %m", swap->path);
                if (swap->devno == 0) {
                        assert(swap->swapfile);

                        log_debug("Swap file '%s' is not backed by block device, ignoring: %m", swap->path);
                        continue;
                }

                if (resume_config_devno > 0) {
                        if (swap->devno == resume_config_devno &&
                            (!swap->swapfile || resume_config_offset == UINT64_MAX || swap->offset == resume_config_offset)) {
                                /* /sys/power/resume (resume=) is set, and the calculated swap file offset
                                 * matches with /sys/power/resume_offset. If /sys/power/resume_offset is not
                                 * exposed, we can't do proper check anyway, so use the found swap file too. */
                                entry = swap;
                                break;
                        }

                        /* If resume= is set, don't try to use other swap spaces. */
                        continue;
                }

                if (!entry ||
                    swap->priority > entry->priority ||
                    swap->size - swap->used > entry->size - entry->used)
                        entry = swap;
        }

        if (!entry) {
                /* No need to check n_swaps == 0, since it's rejected early */
                assert(resume_config_devno > 0);
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSPC), "Cannot find swap entry corresponding to /sys/power/resume.");
        }

        if (ret_device)
                *ret_device = (HibernationDevice) {
                        .devno = entry->devno,
                        .offset = entry->offset,
                        .path = TAKE_PTR(entry->path),
                };

        if (ret_size) {
                *ret_size = entry->size;
                *ret_used = entry->used;
        }

        return resume_config_devno > 0;
}

static int get_proc_meminfo_active(unsigned long long *ret) {
        _cleanup_free_ char *active_str = NULL;
        unsigned long long active;
        int r;

        assert(ret);

        r = get_proc_field("/proc/meminfo", "Active(anon)", WHITESPACE, &active_str);
        if (r < 0)
                return log_debug_errno(r, "Failed to retrieve Active(anon) from /proc/meminfo: %m");

        r = safe_atollu(active_str, &active);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse Active(anon) '%s' from /proc/meminfo: %m", active_str);

        *ret = active;
        return 0;
}

int hibernation_is_safe(void) {
        unsigned long long active;
        uint64_t size, used;
        bool resume_set, bypass_space_check;
        int r;

        bypass_space_check = getenv_bool("SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK") > 0;

        r = find_suitable_hibernation_device_full(NULL, &size, &used);
        if (r == -ENOSPC && bypass_space_check)
                /* If we don't have any available swap space at all, and SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK
                 * is set, skip all remaining checks since we can't do that properly anyway. It is quite
                 * possible that the user is using a setup similar to #30083. When we actually perform
                 * hibernation in sleep.c we'll check everything again. */
                return 0;
        if (r < 0)
                return r;
        resume_set = r > 0;

        if (!resume_set && !is_efi_boot())
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Not running on EFI and resume= is not set. Hibernation is not safe.");

        if (bypass_space_check)
                return 0;

        r = get_proc_meminfo_active(&active);
        if (r < 0)
                return r;

        r = active <= (size - used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("Detected %s swap for hibernation: Active(anon)=%llu kB, size=%" PRIu64 " kB, used=%" PRIu64 " kB, threshold=%.2g%%",
                  r ? "enough" : "not enough", active, size, used, 100 * HIBERNATION_SWAP_THRESHOLD);
        if (!r)
                return -ENOSPC;

        return resume_set;
}

int write_resume_config(dev_t devno, uint64_t offset, const char *device) {
        char offset_str[DECIMAL_STR_MAX(uint64_t)];
        _cleanup_free_ char *path = NULL;
        const char *devno_str;
        int r;

        devno_str = FORMAT_DEVNUM(devno);
        xsprintf(offset_str, "%" PRIu64, offset);

        if (!device) {
                r = device_path_make_canonical(S_IFBLK, devno, &path);
                if (r < 0)
                        return log_error_errno(r,
                                               "Failed to format canonical device path for devno '" DEVNUM_FORMAT_STR "': %m",
                                               DEVNUM_FORMAT_VAL(devno));
                device = path;
        }

        /* We write the offset first since it's safer. Note that this file is only available in 4.17+, so
         * fail gracefully if it doesn't exist and we're only overwriting it with 0. */
        r = write_string_file("/sys/power/resume_offset", offset_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r == -ENOENT) {
                if (offset != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Can't configure hibernation offset %" PRIu64 ", kernel does not support /sys/power/resume_offset. Refusing.",
                                               offset);

                log_warning_errno(r, "/sys/power/resume_offset is unavailable, skipping writing swap file offset.");
        } else if (r < 0)
                return log_error_errno(r,
                                       "Failed to write swap file offset %s to /sys/power/resume_offset for device '%s': %m",
                                       offset_str, device);
        else
                log_debug("Wrote resume_offset=%s for device '%s' to /sys/power/resume_offset.",
                          offset_str, device);

        r = write_string_file("/sys/power/resume", devno_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r,
                                       "Failed to write device '%s' (%s) to /sys/power/resume: %m",
                                       device, devno_str);
        log_debug("Wrote resume=%s for device '%s' to /sys/power/resume.", devno_str, device);

        return 0;
}
