/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include "alloc-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

int proc_cmdline(char **ret) {
        assert(ret);

        if (detect_container() > 0)
                return get_process_cmdline(1, 0, false, ret);
        else
                return read_one_line_file("/proc/cmdline", ret);
}

int parse_proc_cmdline(int (*parse_item)(const char *key, const char *value)) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(parse_item);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *value = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                value = strchr(word, '=');
                if (value)
                        *(value++) = 0;

                r = parse_item(word, value);
                if (r < 0)
                        return r;
        }

        return 0;
}

int get_proc_cmdline_key(const char *key, char **value) {
        _cleanup_free_ char *line = NULL, *ret = NULL;
        bool found = false;
        const char *p;
        int r;

        assert(key);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *e;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                if (value) {
                        e = startswith(word, key);
                        if (!e)
                                continue;

                        r = free_and_strdup(&ret, e);
                        if (r < 0)
                                return r;

                        found = true;
                } else {
                        if (streq(word, key))
                                found = true;
                }
        }

        if (value) {
                *value = ret;
                ret = NULL;
        }

        return found;

}

int shall_restore_state(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        r = get_proc_cmdline_key("systemd.restore_state=", &value);
        if (r < 0)
                return r;
        if (r == 0)
                return true;

        return parse_boolean(value);
}

static const char * const rlmap[] = {
        "emergency", SPECIAL_EMERGENCY_TARGET,
        "-b",        SPECIAL_EMERGENCY_TARGET,
        "rescue",    SPECIAL_RESCUE_TARGET,
        "single",    SPECIAL_RESCUE_TARGET,
        "-s",        SPECIAL_RESCUE_TARGET,
        "s",         SPECIAL_RESCUE_TARGET,
        "S",         SPECIAL_RESCUE_TARGET,
        "1",         SPECIAL_RESCUE_TARGET,
        "2",         SPECIAL_MULTI_USER_TARGET,
        "3",         SPECIAL_MULTI_USER_TARGET,
        "4",         SPECIAL_MULTI_USER_TARGET,
        "5",         SPECIAL_GRAPHICAL_TARGET,
};

const char* runlevel_to_target(const char *word) {
        size_t i;

        if (!word)
                return NULL;

        for (i = 0; i < ELEMENTSOF(rlmap); i += 2)
                if (streq(word, rlmap[i]))
                        return rlmap[i+1];

        return NULL;
}
