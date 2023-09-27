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

SwapEntry* swap_entry_free(SwapEntry *se) {
        if (!se)
                return NULL;

        free(se->path);

        return mfree(se);
}

HibernateLocation* hibernate_location_free(HibernateLocation *hl) {
        if (!hl)
                return NULL;

        swap_entry_free(hl->swap);

        return mfree(hl);
}

static int swap_device_to_devnum(const SwapEntry *swap, dev_t *ret_dev) {
        _cleanup_close_ int fd = -EBADF;
        struct stat sb;
        int r;

        assert(swap);
        assert(swap->path);

        fd = open(swap->path, O_CLOEXEC|O_PATH);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &sb) < 0)
                return -errno;

        if (swap->type == SWAP_BLOCK) {
                if (!S_ISBLK(sb.st_mode))
                        return -ENOTBLK;

                *ret_dev = sb.st_rdev;
                return 0;
        }

        r = stat_verify_regular(&sb);
        if (r < 0)
                return r;

        return get_block_device_fd(fd, ret_dev);
}

/*
 * Attempt to calculate the swap file offset on supported filesystems. On unsupported
 * filesystems, a debug message is logged and ret_offset is set to UINT64_MAX.
 */
static int calculate_swap_file_offset(const SwapEntry *swap, uint64_t *ret_offset) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ struct fiemap *fiemap = NULL;
        int r;

        assert(swap);
        assert(swap->path);
        assert(swap->type == SWAP_FILE);
        assert(ret_offset);

        fd = open(swap->path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open swap file %s to determine on-disk offset: %m", swap->path);

        r = fd_verify_regular(fd);
        if (r < 0)
                return log_debug_errno(r, "Selected swap file is not a regular file.");

        r = fd_is_fs_type(fd, BTRFS_SUPER_MAGIC);
        if (r < 0)
                return log_debug_errno(r, "Error checking %s for Btrfs filesystem: %m", swap->path);
        if (r > 0) {
                log_debug("%s: detection of swap file offset on Btrfs is not supported", swap->path);
                *ret_offset = UINT64_MAX;
                return 0;
        }

        r = read_fiemap(fd, &fiemap);
        if (r < 0)
                return log_debug_errno(r, "Unable to read extent map for '%s': %m", swap->path);

        *ret_offset = fiemap->fm_extents[0].fe_physical / page_size();
        return 0;
}

static int read_resume_files(dev_t *ret_resume, uint64_t *ret_resume_offset) {
        _cleanup_free_ char *resume_str = NULL, *resume_offset_str = NULL;
        uint64_t resume_offset;
        dev_t resume;
        int r;

        assert(ret_resume);
        assert(ret_resume_offset);

        r = read_one_line_file("/sys/power/resume", &resume_str);
        if (r < 0)
                return log_debug_errno(r, "Error reading /sys/power/resume: %m");

        r = parse_devnum(resume_str, &resume);
        if (r < 0)
                return log_debug_errno(r, "Error parsing /sys/power/resume device: %s: %m", resume_str);

        r = read_one_line_file("/sys/power/resume_offset", &resume_offset_str);
        if (r == -ENOENT) {
                log_debug_errno(r, "Kernel does not support resume_offset; swap file offset detection will be skipped.");
                resume_offset = 0;
        } else if (r < 0)
                return log_debug_errno(r, "Error reading /sys/power/resume_offset: %m");
        else {
                r = safe_atou64(resume_offset_str, &resume_offset);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse value in /sys/power/resume_offset \"%s\": %m", resume_offset_str);
        }

        if (resume_offset > 0 && resume == 0)
                log_debug("Warning: found /sys/power/resume_offset==%" PRIu64 ", but /sys/power/resume unset. Misconfiguration?",
                          resume_offset);

        *ret_resume = resume;
        *ret_resume_offset = resume_offset;
        return 0;
}

/*
 * Determine if the HibernateLocation matches the resume= (device) and resume_offset= (file).
 */
static bool location_is_resume_device(const HibernateLocation *location, dev_t sys_resume, uint64_t sys_offset) {
        if (!location)
                return false;

        return  sys_resume > 0 &&
                sys_resume == location->devno &&
                (sys_offset == location->offset || (sys_offset > 0 && location->offset == UINT64_MAX));
}

/*
 * Attempt to find the hibernation location by parsing /proc/swaps, /sys/power/resume, and
 * /sys/power/resume_offset.
 *
 * Beware:
 *  Never use a device or file as location that hasn't been somehow specified by a user that would also be
 *  entrusted with full system memory access (for example via /sys/power/resume) or that isn't an already
 *  active swap area!
 *  Otherwise various security attacks might become possible, for example an attacker could silently attach
 *  such a device and circumvent full disk encryption when it would be automatically used for hibernation.
 *  Also, having a swap area on top of encryption is not per se enough to protect from all such attacks.
 *
 * Returns:
 *  1 - Values are set in /sys/power/resume and /sys/power/resume_offset.
 *      ret_hibernate_location will represent matching /proc/swap entry if identified or NULL if not.
 *
 *  0 - No values are set in /sys/power/resume and /sys/power/resume_offset.
        ret_hibernate_location will represent the highest priority swap with most remaining space discovered in /proc/swaps.
 *
 *  Negative value in the case of error.
 */
int find_hibernate_location(HibernateLocation **ret_hibernate_location) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(hibernate_location_freep) HibernateLocation *hibernate_location = NULL;
        dev_t sys_resume = 0; /* Unnecessary initialization to appease gcc */
        uint64_t sys_offset = 0;
        bool resume_match = false;
        int r;

        /* read the /sys/power/resume & /sys/power/resume_offset values */
        r = read_resume_files(&sys_resume, &sys_offset);
        if (r < 0)
                return r;

        f = fopen("/proc/swaps", "re");
        if (!f) {
                log_debug_errno(errno, "Failed to open /proc/swaps: %m");
                return errno == ENOENT ? -EOPNOTSUPP : -errno; /* Convert swap not supported to a recognizable error */
        }

        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");
        for (unsigned i = 1;; i++) {
                _cleanup_(swap_entry_freep) SwapEntry *swap = NULL;
                _cleanup_free_ char *type = NULL;
                uint64_t swap_offset = 0;
                int k;

                swap = new(SwapEntry, 1);
                if (!swap)
                        return -ENOMEM;

                *swap = (SwapEntry) {
                        .type = _SWAP_TYPE_INVALID,
                };

                k = fscanf(f,
                           "%ms "       /* device/file path */
                           "%ms "       /* type of swap */
                           "%" PRIu64   /* swap size */
                           "%" PRIu64   /* used */
                           "%i\n",      /* priority */
                           &swap->path, &type, &swap->size, &swap->used, &swap->priority);
                if (k == EOF)
                        break;
                if (k != 5) {
                        log_debug("Failed to parse /proc/swaps:%u, ignoring", i);
                        continue;
                }

                if (streq(type, "file")) {

                        if (endswith(swap->path, "\\040(deleted)")) {
                                log_debug("Ignoring deleted swap file '%s'.", swap->path);
                                continue;
                        }

                        swap->type = SWAP_FILE;

                        r = calculate_swap_file_offset(swap, &swap_offset);
                        if (r < 0)
                                return r;

                } else if (streq(type, "partition")) {
                        const char *fn;

                        fn = path_startswith(swap->path, "/dev/");
                        if (fn && startswith(fn, "zram")) {
                                log_debug("%s: ignoring zram swap", swap->path);
                                continue;
                        }

                        swap->type = SWAP_BLOCK;

                } else {
                        log_debug("%s: swap type %s is unsupported for hibernation, ignoring", swap->path, type);
                        continue;
                }

                /* prefer resume device or highest priority swap with most remaining space */
                if (sys_resume == 0) {
                        if (hibernate_location && swap->priority < hibernate_location->swap->priority) {
                                log_debug("%s: ignoring device with lower priority", swap->path);
                                continue;
                        }
                        if (hibernate_location &&
                            (swap->priority == hibernate_location->swap->priority
                             && swap->size - swap->used < hibernate_location->swap->size - hibernate_location->swap->used)) {
                                log_debug("%s: ignoring device with lower usable space", swap->path);
                                continue;
                        }
                }

                dev_t swap_devno;
                r = swap_device_to_devnum(swap, &swap_devno);
                if (r < 0)
                        return log_debug_errno(r, "%s: failed to query device number: %m", swap->path);
                if (swap_devno == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODEV), "%s: not backed by block device.", swap->path);

                hibernate_location = hibernate_location_free(hibernate_location);
                hibernate_location = new(HibernateLocation, 1);
                if (!hibernate_location)
                        return -ENOMEM;

                *hibernate_location = (HibernateLocation) {
                        .devno = swap_devno,
                        .offset = swap_offset,
                        .swap = TAKE_PTR(swap),
                };

                /* if the swap is the resume device, stop the loop */
                if (location_is_resume_device(hibernate_location, sys_resume, sys_offset)) {
                        log_debug("%s: device matches configured resume settings.", hibernate_location->swap->path);
                        resume_match = true;
                        break;
                }

                log_debug("%s: is a candidate device.", hibernate_location->swap->path);
        }

        /* We found nothing at all */
        if (!hibernate_location)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSYS),
                                       "No possible swap partitions or files suitable for hibernation were found in /proc/swaps.");

        /* resume= is set but a matching /proc/swaps entry was not found */
        if (sys_resume != 0 && !resume_match)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOSYS),
                                       "No swap partitions or files matching resume config were found in /proc/swaps.");

        if (hibernate_location->offset == UINT64_MAX) {
                if (sys_offset == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOSYS), "Offset detection failed and /sys/power/resume_offset is not set.");

                hibernate_location->offset = sys_offset;
        }

        if (resume_match)
                log_debug("Hibernation will attempt to use swap entry with path: %s, device: %u:%u, offset: %" PRIu64 ", priority: %i",
                          hibernate_location->swap->path, major(hibernate_location->devno), minor(hibernate_location->devno),
                          hibernate_location->offset, hibernate_location->swap->priority);
        else
                log_debug("/sys/power/resume is not configured; attempting to hibernate with path: %s, device: %u:%u, offset: %" PRIu64 ", priority: %i",
                          hibernate_location->swap->path, major(hibernate_location->devno), minor(hibernate_location->devno),
                          hibernate_location->offset, hibernate_location->swap->priority);

        *ret_hibernate_location = TAKE_PTR(hibernate_location);

        if (resume_match)
                return 1;

        return 0;
}

bool enough_swap_for_hibernation(void) {
        _cleanup_free_ char *active = NULL;
        _cleanup_(hibernate_location_freep) HibernateLocation *hibernate_location = NULL;
        unsigned long long act = 0;
        int r;

        if (getenv_bool("SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK") > 0)
                return true;

        r = find_hibernate_location(&hibernate_location);
        if (r < 0)
                return false;

        /* If /sys/power/{resume,resume_offset} is configured but a matching entry
         * could not be identified in /proc/swaps, user is likely using Btrfs with a swapfile;
         * return true and let the system attempt hibernation.
         */
        if (r > 0 && !hibernate_location) {
                log_debug("Unable to determine remaining swap space; hibernation may fail");
                return true;
        }

        if (!hibernate_location)
                return false;

        r = get_proc_field("/proc/meminfo", "Active(anon)", WHITESPACE, &active);
        if (r < 0) {
                log_debug_errno(r, "Failed to retrieve Active(anon) from /proc/meminfo: %m");
                return false;
        }

        r = safe_atollu(active, &act);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse Active(anon) from /proc/meminfo: %s: %m", active);
                return false;
        }

        r = act <= (hibernate_location->swap->size - hibernate_location->swap->used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("%s swap for hibernation, Active(anon)=%llu kB, size=%" PRIu64 " kB, used=%" PRIu64 " kB, threshold=%.2g%%",
                  r ? "Enough" : "Not enough", act, hibernate_location->swap->size, hibernate_location->swap->used, 100*HIBERNATION_SWAP_THRESHOLD);

        return r;
}

int read_fiemap(int fd, struct fiemap **ret) {
        _cleanup_free_ struct fiemap *fiemap = NULL, *result_fiemap = NULL;
        struct stat statinfo;
        uint32_t result_extents = 0;
        uint64_t fiemap_start = 0, fiemap_length;
        const size_t n_extra = DIV_ROUND_UP(sizeof(struct fiemap), sizeof(struct fiemap_extent));

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
