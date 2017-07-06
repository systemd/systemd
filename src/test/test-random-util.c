/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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

#include "hexdecoct.h"
#include "random-util.h"
#include "log.h"

static void test_acquire_random_bytes(bool high_quality_required) {
        uint8_t buf[16] = {};
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 1; i < sizeof buf; i++) {
                assert_se(acquire_random_bytes(buf, i, high_quality_required) == 0);
                if (i + 1 < sizeof buf)
                        assert_se(buf[i] == 0);

                hexdump(stdout, buf, i);
        }
}

static void test_pseudorandom_bytes(void) {
        uint8_t buf[16] = {};
        unsigned i;

        log_info("/* %s */", __func__);

        for (i = 1; i < sizeof buf; i++) {
                pseudorandom_bytes(buf, i);
                if (i + 1 < sizeof buf)
                        assert_se(buf[i] == 0);

                hexdump(stdout, buf, i);
        }
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_acquire_random_bytes(false);
        test_acquire_random_bytes(true);

        test_pseudorandom_bytes();

        return 0;
}
