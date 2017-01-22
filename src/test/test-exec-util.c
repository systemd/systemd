/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Thomas H.P. Andersen

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

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "def.h"
#include "exec-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "rm-rf.h"
#include "string-util.h"

static void test_execute_directory(void) {
        char template_lo[] = "/tmp/test-readlink_and_make_absolute-lo.XXXXXXX";
        char template_hi[] = "/tmp/test-readlink_and_make_absolute-hi.XXXXXXX";
        const char * dirs[] = {template_hi, template_lo, NULL};
        const char *name, *name2, *name3, *overridden, *override, *masked, *mask;

        assert_se(mkdtemp(template_lo));
        assert_se(mkdtemp(template_hi));

        name = strjoina(template_lo, "/script");
        name2 = strjoina(template_hi, "/script2");
        name3 = strjoina(template_lo, "/useless");
        overridden = strjoina(template_lo, "/overridden");
        override = strjoina(template_hi, "/overridden");
        masked = strjoina(template_lo, "/masked");
        mask = strjoina(template_hi, "/masked");

        assert_se(write_string_file(name, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(name2, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/it_works2", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(overridden, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(override, "#!/bin/sh\necho 'Executing '$0", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file(masked, "#!/bin/sh\necho 'Executing '$0\ntouch $(dirname $0)/failed", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(symlink("/dev/null", mask) == 0);
        assert_se(chmod(name, 0755) == 0);
        assert_se(chmod(name2, 0755) == 0);
        assert_se(chmod(overridden, 0755) == 0);
        assert_se(chmod(override, 0755) == 0);
        assert_se(chmod(masked, 0755) == 0);
        assert_se(touch(name3) >= 0);

        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL);

        assert_se(chdir(template_lo) == 0);
        assert_se(access("it_works", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);

        assert_se(chdir(template_hi) == 0);
        assert_se(access("it_works2", F_OK) >= 0);
        assert_se(access("failed", F_OK) < 0);

        (void) rm_rf(template_lo, REMOVE_ROOT|REMOVE_PHYSICAL);
        (void) rm_rf(template_hi, REMOVE_ROOT|REMOVE_PHYSICAL);
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_execute_directory();

        return 0;
}
