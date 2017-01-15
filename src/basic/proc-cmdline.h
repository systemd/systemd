#pragma once

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

#include <stdbool.h>

#include "log.h"

enum {
        PROC_CMDLINE_STRIP_RD_PREFIX = 1,
        PROC_CMDLINE_VALUE_OPTIONAL = 2,
};

typedef int (*proc_cmdline_parse_t)(const char *key, const char *value, void *data);

int proc_cmdline(char **ret);

int proc_cmdline_parse(const proc_cmdline_parse_t parse, void *userdata, unsigned flags);

int proc_cmdline_get_key(const char *parameter, unsigned flags, char **value);
int proc_cmdline_get_bool(const char *key, bool *ret);

char *proc_cmdline_key_startswith(const char *s, const char *prefix);
bool proc_cmdline_key_streq(const char *x, const char *y);

int shall_restore_state(void);
const char* runlevel_to_target(const char *rl);

/* A little helper call, to be used in proc_cmdline_parse_t callbacks */
static inline bool proc_cmdline_value_missing(const char *key, const char *value) {
        if (!value) {
                log_warning("Missing argument for %s= kernel command line switch, ignoring.", key);
                return true;
        }

        return false;
}
