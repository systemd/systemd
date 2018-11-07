/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2018 Dell Inc.
***/

#include <errno.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "bootspec.h"
#include "conf-parser.h"
#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "sleep-config.h"
#include "string-util.h"
#include "strv.h"

int parse_sleep_config(const char *verb, bool *ret_allow, char ***ret_modes, char ***ret_states, usec_t *ret_delay) {
        int allow_suspend = -1, allow_hibernate = -1,
            allow_s2h = -1, allow_hybrid_sleep = -1;
        bool allow;
        _cleanup_strv_free_ char
                **suspend_mode = NULL, **suspend_state = NULL,
                **hibernate_mode = NULL, **hibernate_state = NULL,
                **hybrid_mode = NULL, **hybrid_state = NULL;
        _cleanup_strv_free_ char **modes, **states; /* always initialized below */
        usec_t delay = 180 * USEC_PER_MINUTE;

        const ConfigTableItem items[] = {
                { "Sleep", "AllowSuspend",              config_parse_tristate, 0, &allow_suspend },
                { "Sleep", "AllowHibernation",          config_parse_tristate, 0, &allow_hibernate },
                { "Sleep", "AllowSuspendThenHibernate", config_parse_tristate, 0, &allow_s2h },
                { "Sleep", "AllowHybridSleep",          config_parse_tristate, 0, &allow_hybrid_sleep },

                { "Sleep", "SuspendMode",               config_parse_strv, 0, &suspend_mode  },
                { "Sleep", "SuspendState",              config_parse_strv, 0, &suspend_state },
                { "Sleep", "HibernateMode",             config_parse_strv, 0, &hibernate_mode  },
                { "Sleep", "HibernateState",            config_parse_strv, 0, &hibernate_state },
                { "Sleep", "HybridSleepMode",           config_parse_strv, 0, &hybrid_mode  },
                { "Sleep", "HybridSleepState",          config_parse_strv, 0, &hybrid_state },

                { "Sleep", "HibernateDelaySec",         config_parse_sec,  0, &delay},
                {}
        };

        (void) config_parse_many_nulstr(PKGSYSCONFDIR "/sleep.conf",
                                        CONF_PATHS_NULSTR("systemd/sleep.conf.d"),
                                        "Sleep\0", config_item_table_lookup, items,
                                        CONFIG_PARSE_WARN, NULL);

        if (streq(verb, "suspend")) {
                allow = allow_suspend != 0;

                /* empty by default */
                modes = TAKE_PTR(suspend_mode);

                if (suspend_state)
                        states = TAKE_PTR(suspend_state);
                else
                        states = strv_new("mem", "standby", "freeze");

        } else if (streq(verb, "hibernate")) {
                allow = allow_hibernate != 0;

                if (hibernate_mode)
                        modes = TAKE_PTR(hibernate_mode);
                else
                        modes = strv_new("platform", "shutdown");

                if (hibernate_state)
                        states = TAKE_PTR(hibernate_state);
                else
                        states = strv_new("disk");

        } else if (streq(verb, "hybrid-sleep")) {
                allow = allow_hybrid_sleep > 0 ||
                        (allow_suspend != 0 && allow_hibernate != 0);

                if (hybrid_mode)
                        modes = TAKE_PTR(hybrid_mode);
                else
                        modes = strv_new("suspend", "platform", "shutdown");

                if (hybrid_state)
                        states = TAKE_PTR(hybrid_state);
                else
                        states = strv_new("disk");

        } else if (streq(verb, "suspend-then-hibernate")) {
                allow = allow_s2h > 0 ||
                        (allow_suspend != 0 && allow_hibernate != 0);

                modes = states = NULL;
        } else
                assert_not_reached("what verb");

        if ((!modes && STR_IN_SET(verb, "hibernate", "hybrid-sleep")) ||
            (!states && !streq(verb, "suspend-then-hibernate")))
                return log_oom();

        if (ret_allow)
                *ret_allow = allow;
        if (ret_modes)
                *ret_modes = TAKE_PTR(modes);
        if (ret_states)
                *ret_states = TAKE_PTR(states);
        if (ret_delay)
                *ret_delay = delay;

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
        if (access("/sys/power/disk", W_OK) < 0) {
                log_debug_errno(errno, "/sys/power/disk is not writable: %m");
                return false;
        }

        r = read_one_line_file("/sys/power/disk", &p);
        if (r < 0) {
                log_debug_errno(r, "Couldn't read /sys/power/disk: %m");
                return false;
        }

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

int find_hibernate_location(char **device, char **type, size_t *size, size_t *used) {
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
                if (k == EOF)
                        break;
                if (k != 4) {
                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                if (streq(type_field, "file")) {

                        if (endswith(dev_field, "\\040(deleted)")) {
                                log_warning("Ignoring deleted swap file '%s'.", dev_field);
                                continue;
                        }

                } else if (streq(type_field, "partition")) {
                        const char *fn;

                        fn = path_startswith(dev_field, "/dev/");
                        if (fn && startswith(fn, "zram")) {
                                log_debug("Ignoring compressed RAM swap device '%s'.", dev_field);
                                continue;
                        }
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

static bool enough_swap_for_hibernation(void) {
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
                log_debug_errno(r, "Failed to retrieve Active(anon) from /proc/meminfo: %m");
                return false;
        }

        r = safe_atollu(active, &act);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse Active(anon) from /proc/meminfo: %s: %m", active);
                return false;
        }

        r = act <= (size - used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("%s swap for hibernation, Active(anon)=%llu kB, size=%zu kB, used=%zu kB, threshold=%.2g%%",
                  r ? "Enough" : "Not enough", act, size, used, 100*HIBERNATION_SWAP_THRESHOLD);

        return r;
}

static int check_resume_keys(const char *key, const char *value, void *data) {
        assert_se(key);
        assert_se(data);

        int *resume = data;

        if (*resume == 0)
                /* Exit if we already know we can't resume. */
                return 0;

        if (streq(key, "noresume")) {
                log_debug("Found \"noresume\" on the kernel command line, hibernation is disabled.");
                *resume = 0;

        } else if (streq(key, "resume")) {
                log_debug("Found resume= option on the kernel command line, hibernation is possible.");
                *resume = 1;
        }

        return 0;
}

static int resume_configured_in_options(const char *options) {
        int resume = -1, r;

        /* We don't use PROC_CMDLINE_STRIP_RD_PREFIX here, so rd.resume is *not* supported. */
        r = proc_cmdline_parse_given(options, check_resume_keys, &resume, 0);
        if (r < 0)
                return r;

        if (resume < 0)
                log_debug("Couldn't find resume= option, hibernation is disabled.");
        return resume > 0;
}

static int resume_configured(void) {
        _cleanup_(boot_config_free) BootConfig config = {};
        const BootEntry *e;
        int r;

        /* Check whether a valid resume= option is present. If possible, we query the boot options
         * for the default kernel. If the system is not using sd-boot, fall back to checking the
         * current kernel command line. This is not perfect, but should suffice for most cases. */

        r = find_default_boot_entry(NULL, NULL, &config, &e);
        if (r == -ENOKEY)
                log_debug_errno(r, "Cannot find the ESP partition mount point, falling back to other checks.");
        else if (r < 0)
                return log_debug_errno(r, "Cannot read boot configuration from ESP, assuming hibernation is not possible.");
        else {
                _cleanup_free_ char *options = NULL;

                options = strv_join(e->options, " ");
                if (!options)
                        return log_oom();

                r = resume_configured_in_options(options);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse kernel options in \"%s\": %m",
                                               strnull(e->path));
                return r;
        }

        /* If we can't figure out the default boot entry, let's fall back to current kernel cmdline */
        _cleanup_free_ char *line = NULL;
        r = proc_cmdline(&line);
        if (IN_SET(r, -EPERM, -EACCES, -ENOENT))
                log_debug_errno(r, "Cannot access /proc/cmdline: %m");
        else if (r < 0)
                return log_error_errno(r, "Failed to query /proc/cmdline: %m");
        else {
                r = resume_configured_in_options(line);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse kernel proc cmdline: %m");

                return r;
        }

        log_debug("Couldn't detect any resume mechanism, hibernation is disabled.");
        return false;
}

static int kernel_exists(void) {
        struct utsname u;
        sd_id128_t m;
        int i, r;

        /* Do some superficial checks whether the kernel we are currently running is still around. If it isn't we
         * shouldn't offer hibernation as we couldn't possible resume from hibernation again. Of course, this check is
         * very superficial, as the kernel's mere existance is hardly enough to know whether the hibernate/resume cycle
         * will succeed. However, the common case of kernel updates can be caught this way, and it's definitely worth
         * covering that. */

        for (i = 0;; i++) {
                _cleanup_free_ char *path = NULL;

                switch (i) {

                case 0:
                        /* First, let's look in /lib/modules/`uname -r`/vmlinuz. This is where current Fedora places
                         * its RPM-managed kernels. It's a good place, as it means compiled vendor code is monopolized
                         * in /usr, and then the kernel image is stored along with its modules in the same
                         * hierarchy. It's also what our 'kernel-install' script is written for. */
                        if (uname(&u) < 0)
                                return log_debug_errno(errno, "Failed to acquire kernel release: %m");

                        path = strjoin("/lib/modules/", u.release, "/vmlinuz");
                        break;

                case 1:
                        /* Secondly, let's look in /boot/vmlinuz-`uname -r`. This is where older Fedora and other
                         * distributions tend to place the kernel. */
                        path = strjoin("/boot/vmlinuz-", u.release);
                        break;

                case 2:
                        /* For the other cases, we look in the EFI/boot partition, at the place where our
                         * "kernel-install" script copies the kernel on install by default. */
                        r = sd_id128_get_machine(&m);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to read machine ID: %m");

                        (void) asprintf(&path, "/efi/" SD_ID128_FORMAT_STR "/%s/linux", SD_ID128_FORMAT_VAL(m), u.release);
                        break;
                case 3:
                        (void) asprintf(&path, "/boot/" SD_ID128_FORMAT_STR "/%s/linux", SD_ID128_FORMAT_VAL(m), u.release);
                        break;
                case 4:
                        (void) asprintf(&path, "/boot/efi/" SD_ID128_FORMAT_STR "/%s/linux", SD_ID128_FORMAT_VAL(m), u.release);
                        break;

                default:
                        return false;
                }

                if (!path)
                        return -ENOMEM;

                log_debug("Testing whether %s exists.", path);

                if (access(path, F_OK) >= 0)
                        return true;

                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to determine whether '%s' exists, ignoring: %m", path);
        }
}

int read_fiemap(int fd, struct fiemap **ret) {
        _cleanup_free_ struct fiemap *fiemap = NULL, *result_fiemap = NULL;
        struct stat statinfo;
        uint32_t result_extents = 0;
        uint64_t fiemap_start = 0, fiemap_length;
        const size_t n_extra = DIV_ROUND_UP(sizeof(struct fiemap), sizeof(struct fiemap_extent));
        size_t fiemap_allocated = n_extra, result_fiemap_allocated = n_extra;

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
                if (!greedy_realloc0((void**) &fiemap, &fiemap_allocated,
                                     n_extra + fiemap->fm_mapped_extents, sizeof(struct fiemap_extent)))
                        return -ENOMEM;

                fiemap->fm_extent_count = fiemap->fm_mapped_extents;
                fiemap->fm_mapped_extents = 0;

                if (ioctl(fd, FS_IOC_FIEMAP, fiemap) < 0)
                        return log_debug_errno(errno, "Failed to read extents: %m");

                /* Resize result_fiemap to allow us to copy in the extents */
                if (!greedy_realloc((void**) &result_fiemap, &result_fiemap_allocated,
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

static int can_sleep_internal(const char *verb, bool check_allowed);

static bool can_s2h(void) {
        const char *p;
        int r;

        r = access("/sys/class/rtc/rtc0/wakealarm", W_OK);
        if (r < 0) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "/sys/class/rct/rct0/wakealarm is not writable %m");
                return false;
        }

        FOREACH_STRING(p, "suspend", "hibernate") {
                r = can_sleep_internal(p, false);
                if (IN_SET(r, 0, -ENOSPC, -ENOMEDIUM, -EADV)) {
                        log_debug("Unable to %s system.", p);
                        return false;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to check if %s is possible: %m", p);
        }

        return true;
}

static int can_sleep_internal(const char *verb, bool check_allowed) {
        bool allow;
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        int r;

        assert(STR_IN_SET(verb, "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate"));

        r = parse_sleep_config(verb, &allow, &modes, &states, NULL);
        if (r < 0)
                return false;

        if (check_allowed && !allow) {
                log_debug("Sleep mode \"%s\" is disabled by configuration.", verb);
                return false;
        }

        if (streq(verb, "suspend-then-hibernate"))
                return can_s2h();

        if (!can_sleep_state(states) || !can_sleep_disk(modes))
                return false;

        if (streq(verb, "suspend"))
                return true;

        if (kernel_exists() <= 0) {
                log_debug_errno(errno, "Couldn't find kernel, not offering hibernation.");
                return -ENOMEDIUM;
        }

        if (!enough_swap_for_hibernation())
                return -ENOSPC;

        r = resume_configured();
        if (r <= 0)
                /* We squash all errors (e.g. EPERM) into a single value for reporting. */
                return -EADV;

        return true;
}

int can_sleep(const char *verb) {
        return can_sleep_internal(verb, true);
}
