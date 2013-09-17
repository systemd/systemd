/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>

#include "conf-parser.h"
#include "sleep-config.h"
#include "fileio.h"
#include "log.h"
#include "strv.h"
#include "util.h"

int parse_sleep_config(const char *verb, char ***modes, char ***states) {
        _cleanup_strv_free_ char
                **suspend_mode = NULL, **suspend_state = NULL,
                **hibernate_mode = NULL, **hibernate_state = NULL,
                **hybrid_mode = NULL, **hybrid_state = NULL;

        const ConfigTableItem items[] = {
                { "Sleep",   "SuspendMode",      config_parse_strv,  0, &suspend_mode  },
                { "Sleep",   "SuspendState",     config_parse_strv,  0, &suspend_state },
                { "Sleep",   "HibernateMode",    config_parse_strv,  0, &hibernate_mode  },
                { "Sleep",   "HibernateState",   config_parse_strv,  0, &hibernate_state },
                { "Sleep",   "HybridSleepMode",  config_parse_strv,  0, &hybrid_mode  },
                { "Sleep",   "HybridSleepState", config_parse_strv,  0, &hybrid_state },
                {}};

        int r;
        FILE _cleanup_fclose_ *f;

        f = fopen(PKGSYSCONFDIR "/sleep.conf", "re");
        if (!f)
                log_full(errno == ENOENT ? LOG_DEBUG: LOG_WARNING,
                         "Failed to open configuration file " PKGSYSCONFDIR "/sleep.conf: %m");
        else {
                r = config_parse(NULL, PKGSYSCONFDIR "/sleep.conf", f, "Sleep\0",
                                 config_item_table_lookup, (void*) items, false, false, NULL);
                if (r < 0)
                        log_warning("Failed to parse configuration file: %s", strerror(-r));
        }

        if (streq(verb, "suspend")) {
                /* empty by default */
                *modes = suspend_mode;

                if (suspend_state)
                        *states = suspend_state;
                else
                        *states = strv_split_nulstr("mem\0standby\0freeze\0");

                suspend_mode = suspend_state = NULL;
        } else if (streq(verb, "hibernate")) {
                if (hibernate_mode)
                        *modes = hibernate_mode;
                else
                        *modes = strv_split_nulstr("platform\0shutdown\0");

                if (hibernate_state)
                        *states = hibernate_state;
                else
                        *states = strv_split_nulstr("disk\0");

                hibernate_mode = hibernate_state = NULL;
        } else if (streq(verb, "hybrid-sleep")) {
                if (hybrid_mode)
                        *modes = hybrid_mode;
                else
                        *modes = strv_split_nulstr("suspend\0platform\0shutdown\0");

                if (hybrid_state)
                        *states = hybrid_state;
                else
                        *states = strv_split_nulstr("disk\0");

                hybrid_mode = hybrid_state = NULL;
        } else
                assert_not_reached("what verb");

        if (!modes || !states) {
                strv_free(*modes);
                strv_free(*states);
                return log_oom();
        }

        return 0;
}

int can_sleep_state(char **types) {
        char *w, *state, **type;
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
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(w, l, p, WHITESPACE, state)
                        if (l == k && memcmp(w, *type, l) == 0)
                                return true;
        }

        return false;
}

int can_sleep_disk(char **types) {
        char *w, *state, **type;
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
                size_t l, k;

                k = strlen(*type);
                FOREACH_WORD_SEPARATOR(w, l, p, WHITESPACE, state) {
                        if (l == k && memcmp(w, *type, l) == 0)
                                return true;

                        if (l == k + 2 && w[0] == '[' && memcmp(w + 1, *type, l - 2) == 0 && w[l-1] == ']')
                                return true;
                }
        }

        return false;
}

#define HIBERNATION_SWAP_THRESHOLD 0.98

static int hibernation_partition_size(size_t *size, size_t *used) {
        _cleanup_fclose_ FILE *f;
        int i;

        assert(size);
        assert(used);

        f = fopen("/proc/swaps", "r");
        if (!f) {
                log_full(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                         "Failed to retrieve open /proc/swaps: %m");
                assert(errno > 0);
                return -errno;
        }

        (void) fscanf(f, "%*s %*s %*s %*s %*s\n");

        for (i = 1;; i++) {
                _cleanup_free_ char *dev = NULL, *d = NULL, *type = NULL;
                size_t size_field, used_field;
                int k;

                k = fscanf(f,
                           "%ms "   /* device/file */
                           "%ms "   /* type of swap */
                           "%zd "   /* swap size */
                           "%zd "   /* used */
                           "%*i\n", /* priority */
                           &dev, &type, &size_field, &used_field);
                if (k != 4) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u", i);
                        continue;
                }

                d = cunescape(dev);
                if (!d)
                        return -ENOMEM;

                if (!streq(type, "partition")) {
                        log_debug("Partition %s has type %s, ignoring.", d, type);
                        continue;
                }

                *size = size_field;
                *used = used_field;
                return 0;
        }

        log_debug("No swap partitions were found.");
        return -ENOSYS;
}

static bool enough_memory_for_hibernation(void) {
        _cleanup_free_ char *active = NULL;
        unsigned long long act;
        size_t size, used;
        int r;

        r = hibernation_partition_size(&size, &used);
        if (r < 0)
                return false;

        r = get_status_field("/proc/meminfo", "\nActive(anon):", &active);
        if (r < 0) {
                log_error("Failed to retrieve Active(anon) from /proc/meminfo: %s", strerror(-r));
                return false;
        }

        r = safe_atollu(active, &act);
        if (r < 0) {
                log_error("Failed to parse Active(anon) from /proc/meminfo: %s: %s",
                          active, strerror(-r));
                return false;
        }

        r = act <= (size - used) * HIBERNATION_SWAP_THRESHOLD;
        log_debug("Hibernation is %spossible, Active(anon)=%llu kB, size=%zu kB, used=%zu kB, threshold=%.2g%%",
                  r ? "" : "im", act, size, used, 100*HIBERNATION_SWAP_THRESHOLD);

        return r;
}

int can_sleep(const char *verb) {
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        int r;

        assert(streq(verb, "suspend") ||
               streq(verb, "hibernate") ||
               streq(verb, "hybrid-sleep"));

        r = parse_sleep_config(verb, &modes, &states);
        if (r < 0)
                return false;

        if (!can_sleep_state(states) || !can_sleep_disk(modes))
                return false;

        return streq(verb, "suspend") || enough_memory_for_hibernation();
}
