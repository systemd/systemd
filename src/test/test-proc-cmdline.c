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
#include "log.h"
#include "macro.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "util.h"

static int parse_item(const char *key, const char *value) {
        assert_se(key);

        log_info("kernel cmdline option <%s> = <%s>", key, strna(value));
        return 0;
}

static void test_parse_proc_cmdline(void) {
        assert_se(parse_proc_cmdline(parse_item) >= 0);
}

static void test_runlevel_to_target(void) {
        in_initrd_force(false);
        assert_se(streq_ptr(runlevel_to_target(NULL), NULL));
        assert_se(streq_ptr(runlevel_to_target("unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("3"), SPECIAL_MULTI_USER_TARGET));
        assert_se(streq_ptr(runlevel_to_target("rd.rescue"), NULL));

        in_initrd_force(true);
        assert_se(streq_ptr(runlevel_to_target(NULL), NULL));
        assert_se(streq_ptr(runlevel_to_target("unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.unknown-runlevel"), NULL));
        assert_se(streq_ptr(runlevel_to_target("3"), NULL));
        assert_se(streq_ptr(runlevel_to_target("rd.rescue"), SPECIAL_RESCUE_TARGET));
}

int main(void) {
        log_parse_environment();
        log_open();

        test_parse_proc_cmdline();
        test_runlevel_to_target();

        return 0;
}
