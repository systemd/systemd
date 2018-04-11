/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek
  Copyright 2018 Dell Inc.
***/

#include <errno.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-parser.h"
#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "sleep-config.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "udev-util.h"

/* this is from kernel/power/swap.c, it's not exported currently */
#define HIBERNATE_SIG	"S1SUSPEND"
struct swsusp_header {
        //HACK - override the types not exported by kernel
        char reserved[4096 - 20 - sizeof(uint64_t) - sizeof(int) -
                        sizeof(uint32_t)];
        uint32_t        crc32;
        uint64_t        image;
        unsigned int    flags;	/* Flags to pass to the "boot" kernel */
        char            orig_sig[10];
        char            sig[10];
} __packed;

int parse_sleep_config(const char *verb, char ***_modes, char ***_states, usec_t *_delay) {

        _cleanup_strv_free_ char
                **suspend_mode = NULL, **suspend_state = NULL,
                **hibernate_mode = NULL, **hibernate_state = NULL,
                **hybrid_mode = NULL, **hybrid_state = NULL;
        char **modes, **states;
        usec_t delay = 180 * USEC_PER_MINUTE;

        const ConfigTableItem items[] = {
                { "Sleep",   "SuspendMode",      config_parse_strv,  0, &suspend_mode  },
                { "Sleep",   "SuspendState",     config_parse_strv,  0, &suspend_state },
                { "Sleep",   "HibernateMode",    config_parse_strv,  0, &hibernate_mode  },
                { "Sleep",   "HibernateState",   config_parse_strv,  0, &hibernate_state },
                { "Sleep",   "HybridSleepMode",  config_parse_strv,  0, &hybrid_mode  },
                { "Sleep",   "HybridSleepState", config_parse_strv,  0, &hybrid_state },
                { "Sleep",   "HibernateDelaySec", config_parse_sec,  0, &delay},
                {}
        };

        (void) config_parse_many_nulstr(PKGSYSCONFDIR "/sleep.conf",
                                        CONF_PATHS_NULSTR("systemd/sleep.conf.d"),
                                        "Sleep\0", config_item_table_lookup, items,
                                        CONFIG_PARSE_WARN, NULL);

        if (streq(verb, "suspend")) {
                /* empty by default */
                modes = TAKE_PTR(suspend_mode);

                if (suspend_state)
                        states = TAKE_PTR(suspend_state);
                else
                        states = strv_new("mem", "standby", "freeze", NULL);

        } else if (streq(verb, "hibernate")) {
                if (hibernate_mode)
                        modes = TAKE_PTR(hibernate_mode);
                else
                        modes = strv_new("platform", "shutdown", NULL);

                if (hibernate_state)
                        states = TAKE_PTR(hibernate_state);
                else
                        states = strv_new("disk", NULL);

        } else if (streq(verb, "hybrid-sleep")) {
                if (hybrid_mode)
                        modes = TAKE_PTR(hybrid_mode);
                else
                        modes = strv_new("suspend", "platform", "shutdown", NULL);

                if (hybrid_state)
                        states = TAKE_PTR(hybrid_state);
                else
                        states = strv_new("disk", NULL);

        } else if (streq(verb, "suspend-then-hibernate"))
                modes = states = NULL;
        else
                assert_not_reached("what verb");

        if ((!modes && STR_IN_SET(verb, "hibernate", "hybrid-sleep")) ||
            (!states && !streq(verb, "suspend-then-hibernate"))) {
                strv_free(modes);
                strv_free(states);
                return log_oom();
        }

        if (_modes)
                *_modes = modes;
        if (_states)
                *_states = states;
        if (_delay)
                *_delay = delay;

        return 0;
}

int can_sleep_state(char **types) {
        char **type;
        int r;
        _cleanup_free_ char *p = NULL;

        if (strv_isempty(types))
                return true;

        /* If /sys is read-only we cannot sleep */
        if (access("/sys/power/state", W_OK) < 0)
                return false;

        r = read_one_line_file("/sys/power/state", &p);
        if (r < 0)
                return false;

        STRV_FOREACH(type, types) {
                const char *word, *state;
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(word, l, p, WHITESPACE, state)
                        if (l == k && memcmp(word, *type, l) == 0)
                                return true;
        }

        return false;
}

int can_sleep_disk(char **types) {
        char **type;
        int r;
        _cleanup_free_ char *p = NULL;

        if (strv_isempty(types))
                return true;

        /* If /sys is read-only we cannot sleep */
        if (access("/sys/power/disk", W_OK) < 0)
                return false;

        r = read_one_line_file("/sys/power/disk", &p);
        if (r < 0)
                return false;

        STRV_FOREACH(type, types) {
                const char *word, *state;
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(word, l, p, WHITESPACE, state) {
                        if (l == k && memcmp(word, *type, l) == 0)
                                return true;

                        if (l == k + 2 &&
                            word[0] == '[' &&
                            memcmp(word + 1, *type, l - 2) == 0 &&
                            word[l-1] == ']')
                                return true;
                }
        }

        return false;
}

#define HIBERNATION_SWAP_THRESHOLD 0.98

static int find_hibernate_location(char **device, char **type, size_t *size, size_t *used) {
        _cleanup_fclose_ FILE *f;
        unsigned i;

        f = fopen("/proc/swaps", "re");
        if (!f) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to retrieve open /proc/swaps: %m");
                assert(errno > 0);
                return -errno;
        }

        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
                _cleanup_free_ char *dev_field = NULL, *type_field = NULL;
                size_t size_field, used_field;
                int k;

                k = fscanf(f,
                           "%ms "   /* device/file */
                           "%ms "   /* type of swap */
                           "%zu "   /* swap size */
                           "%zu "   /* used */
                           "%*i\n", /* priority */
                           &dev_field, &type_field, &size_field, &used_field);
                if (k != 4) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                if (streq(type_field, "partition") && endswith(dev_field, "\\040(deleted)")) {
                        log_warning("Ignoring deleted swapfile '%s'.", dev_field);
                        continue;
                }
                if (device)
                        *device = TAKE_PTR(dev_field);
                if (type)
                        *type = TAKE_PTR(type_field);
                if (size)
                        *size = size_field;
                if (used)
                        *used = used_field;
                return 0;
        }

        log_debug("No swap partitions were found.");
        return -ENOSYS;
}

static bool enough_memory_for_hibernation(void) {
        _cleanup_free_ char *active = NULL;
        unsigned long long act = 0;
        size_t size = 0, used = 0;
        int r;

        if (getenv_bool("SYSTEMD_BYPASS_HIBERNATION_MEMORY_CHECK") > 0)
                return true;

        r = find_hibernate_location(NULL, NULL, &size, &used);
        if (r < 0)
                return false;

        r = get_proc_field("/proc/meminfo", "Active(anon)", WHITESPACE, &active);
        if (r < 0) {
                log_error_errno(r, "Failed to retrieve Active(anon) from /proc/meminfo: %m");
                return false;
        }

        r = safe_atollu(active, &act);
        if (r < 0) {
                log_error_errno(r, "Failed to parse Active(anon) from /proc/meminfo: %s: %m",
                                active);
                return false;
        }

        r = act <= (size - used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("Hibernation is %spossible, Active(anon)=%llu kB, size=%zu kB, used=%zu kB, threshold=%.2g%%",
                  r ? "" : "im", act, size, used, 100*HIBERNATION_SWAP_THRESHOLD);

        return r;
}

int read_fiemap(int fd, struct fiemap **ret) {
        _cleanup_free_ struct fiemap *fiemap = NULL, *result_fiemap = NULL;
        int extents_size;
        struct stat statinfo;
        uint32_t result_extents = 0;
        uint64_t fiemap_start = 0, fiemap_length;
        size_t fiemap_size = 1, result_fiemap_size = 1;

        if (fstat(fd, &statinfo) < 0)
                return log_debug_errno(errno, "Cannot determine file size: %m");
        if (!S_ISREG(statinfo.st_mode))
                return -ENOTTY;
        fiemap_length = statinfo.st_size;

        /* zero this out in case we run on a file with no extents */
        fiemap = new0(struct fiemap, 1);
        if (!fiemap)
                return -ENOMEM;

        result_fiemap = new(struct fiemap, 1);
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

                /* Result fiemap has to hold all the extents for the whole file */
                extents_size = DIV_ROUND_UP(sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents,
                                            sizeof(struct fiemap));

                /* Resize fiemap to allow us to read in the extents */
                if (!GREEDY_REALLOC0(fiemap, fiemap_size, extents_size))
                        return -ENOMEM;

                fiemap->fm_extent_count = fiemap->fm_mapped_extents;
                fiemap->fm_mapped_extents = 0;

                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                extents_size = DIV_ROUND_UP(sizeof(struct fiemap_extent) * (result_extents + fiemap->fm_mapped_extents),
                                            sizeof(struct fiemap));

                /* Resize result_fiemap to allow us to read in the extents */
                if (!GREEDY_REALLOC(result_fiemap, result_fiemap_size,
                                    extents_size))
                        return -ENOMEM;

                memcpy(result_fiemap->fm_extents + result_extents,
                       fiemap->fm_extents,
                       sizeof(struct fiemap_extent) * fiemap->fm_mapped_extents);

                result_extents += fiemap->fm_mapped_extents;

                /* Highly unlikely that it is zero */
                if (fiemap->fm_mapped_extents > 0) {
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

static int find_hibernation_offset(char *device, unsigned long *device_out, uint64_t *offset_out) {
        _cleanup_free_ struct fiemap *fiemap = NULL;
        _cleanup_close_ int fd = -1;
        struct stat stb;
        int r;

        fd = open(device, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_debug_errno(errno, "Unable to open '%s': %m", device);
        r = fstat(fd, &stb);
        if (r < 0)
                return log_debug_errno(errno, "Unable to stat %s: %m", device);
        r = read_fiemap(fd, &fiemap);
        if (r < 0)
                return log_debug_errno(r, "Unable to read extent map for '%s': %m",
                                       device);
        if (fiemap->fm_mapped_extents == 0) {
                log_debug("No extents found in '%s'", device);
                return -EINVAL;
        }
        *offset_out = fiemap->fm_extents[0].fe_physical / page_size();
        *device_out = (unsigned long)stb.st_dev;
        return 0;
}

int write_hibernate_location_info(void) {
        _cleanup_free_ char *device = NULL, *type = NULL;
        char offset_str[DECIMAL_STR_MAX(uint64_t)];
        char device_str[DECIMAL_STR_MAX(uint64_t)];
        unsigned long dev;
        uint64_t offset;
        int r;

        r = find_hibernate_location(&device, &type, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Unable to find hibernation location: %m");

        /* if it's a swap partition, we just write the disk to /sys/power/resume */
        if (streq(type, "partition"))
                return write_string_file("/sys/power/resume", device, 0);
        else if (!streq(type, "file"))
                return log_debug_errno(EINVAL, "Invalid hibernate type %s: %m",
                                       type);

        /* Only available in 4.17+ */
        if (access("/sys/power/resume_offset", F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;
                return log_debug_errno(errno, "/sys/power/resume_offset unavailable: %m");
        }

        r = access("/sys/power/resume_offset", W_OK);
        if (r < 0)
                return log_debug_errno(errno, "/sys/power/resume_offset not writeable: %m");

        r = find_hibernation_offset(device, &dev, &offset);
        if (r < 0)
                return r;
        xsprintf(offset_str, "%" PRIu64, offset);
        r = write_string_file("/sys/power/resume_offset", offset_str, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write offset '%s': %m",
                                       offset_str);

        xsprintf(device_str, "%lx", dev);
        r = write_string_file("/sys/power/resume", device_str, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write device '%s': %m",
                                       device_str);
        return 0;
}

bool should_resume(void) {
        _cleanup_free_ struct swsusp_header *header = NULL;
        _cleanup_free_ char *swap = NULL, *type = NULL;
        _cleanup_udev_unref_ struct udev *udev;
        _cleanup_close_ int fd = -1;
        struct udev_device *dev = NULL;
        const char *node  = NULL;
        unsigned long stb_dev;
        uint64_t offset;
        int r;

        /* find preferred swap from last boot (OK if none set) */
        r =  find_hibernate_location(&swap, &type, NULL, NULL);
        if (r < 0) {
                log_debug_errno(r, "Unable to find any hibernation location: %m");
                return false;
        }

        /* determine where in the disk to probe */
        if (streq(type, "partition")) {
                offset = 0;
                node = swap;
        }
        else if (!streq(type, "file")) {
                r = find_hibernation_offset(swap, &stb_dev, &offset);
                if (r < 0)
                        return false;

                udev = udev_new();
                if (!udev) {
                        log_debug_errno(ENOMEM, "Unable to allocate udev: %m");
                        return false;
                }

                dev = udev_device_new_from_devnum(udev, 'b', stb_dev);
                if (!dev) {
                        log_debug_errno(ENODEV, "Unable to find device: %m");
                        return false;
                }

                node = udev_device_get_devnode(dev);
                if (!node) {
                        log_debug_errno(ENODEV, "Unable to find node: %m");
                        return false;
                }

        }
        else {
                log_debug("Unknown swap type selected %s", swap);
                return false;
        }

        /* probe for hibernate header */
        header = new(struct swsusp_header, 1);
        if (!header) {
                log_debug_errno(ENOMEM, "Unable to allocate header: %m");
                return false;
        }
        fd = open(node, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
                log_debug_errno(errno, "Unable to open '%s': %m", node);
                return false;
        }
        r = read(fd, header, sizeof(header));
        if (r < 0) {
                log_debug_errno(errno, "Unable to read '%s': %m", node);
                return false;
        }
        r = lseek(fd, offset, SEEK_SET);
        if (r < 0) {
                log_debug_errno(errno, "Unable to seek '%s': %m", node);
                return false;
        }

        /* match the signature */
        return memcmp(HIBERNATE_SIG, header->sig, 10) == 0;
}

static bool can_s2h(void) {
        int r;

        r = access("/sys/class/rtc/rtc0/wakealarm", W_OK);
        if (r < 0) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "/sys/class/rct/rct0/wakealarm is not writable %m");
                return false;
        }

        r = can_sleep("suspend");
        if (r < 0) {
                log_debug_errno(r, "Unable to suspend system.");
                return false;
        }

        r = can_sleep("hibernate");
        if (r < 0) {
                log_debug_errno(r, "Unable to hibernate system.");
                return false;
        }

        return true;
}

int can_sleep(const char *verb) {
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        int r;

        assert(STR_IN_SET(verb, "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate"));

        if (streq(verb, "suspend-then-hibernate"))
                return can_s2h();

        r = parse_sleep_config(verb, &modes, &states, NULL);
        if (r < 0)
                return false;

        if (!can_sleep_state(states) || !can_sleep_disk(modes))
                return false;

        return streq(verb, "suspend") || enough_memory_for_hibernation();
}
