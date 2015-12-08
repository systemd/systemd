/***
  This file is part of systemd

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

#include <sys/resource.h>

#include "capability-util.h"
#include "macro.h"
#include "rlimit-util.h"
#include "string-util.h"
#include "util.h"

int main(int argc, char *argv[]) {
        struct rlimit old, new, high;
        struct rlimit err = {
                .rlim_cur = 10,
                .rlim_max = 5,
        };

        log_parse_environment();
        log_open();

        assert_se(drop_capability(CAP_SYS_RESOURCE) == 0);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        new.rlim_cur = MIN(5U, old.rlim_max);
        new.rlim_max = MIN(10U, old.rlim_max);
        assert_se(setrlimit(RLIMIT_NOFILE, &new) >= 0);

        assert_se(rlimit_from_string("LimitNOFILE") == RLIMIT_NOFILE);
        assert_se(rlimit_from_string("DefaultLimitNOFILE") == -1);

        assert_se(streq_ptr(rlimit_to_string(RLIMIT_NOFILE), "LimitNOFILE"));
        assert_se(rlimit_to_string(-1) == NULL);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &old) == 0);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(old.rlim_cur == new.rlim_cur);
        assert_se(old.rlim_max == new.rlim_max);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        high = RLIMIT_MAKE_CONST(old.rlim_max + 1);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &high) == 0);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(new.rlim_max == old.rlim_max);
        assert_se(new.rlim_cur == new.rlim_max);

        assert_se(getrlimit(RLIMIT_NOFILE, &old) == 0);
        assert_se(setrlimit_closest(RLIMIT_NOFILE, &err) == -EINVAL);
        assert_se(getrlimit(RLIMIT_NOFILE, &new) == 0);
        assert_se(old.rlim_cur == new.rlim_cur);
        assert_se(old.rlim_max == new.rlim_max);

        return 0;
}
