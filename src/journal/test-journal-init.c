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

#include <systemd/sd-journal.h>

#include "log.h"
#include "util.h"

int main(int argc, char *argv[]) {
        sd_journal *j;
        int r, i, I = 100;
        char t[] = "/tmp/journal-stream-XXXXXX";

        log_set_max_level(LOG_DEBUG);

        if (argc >= 2)
                safe_atoi(argv[1], &I);
        log_info("Running %d loops", I);

        assert_se(mkdtemp(t));

        for (i = 0; i < I; i++) {
                r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
                assert_se(r == 0);

                sd_journal_close(j);

                r = sd_journal_open_directory(&j, t, 0);
                assert_se(r == 0);

                sd_journal_close(j);

                j = NULL;
                r = sd_journal_open_directory(&j, t, SD_JOURNAL_LOCAL_ONLY);
                assert_se(r == -EINVAL);
                assert_se(j == NULL);
        }

        assert_se(rm_rf_dangerous(t, false, true, false) >= 0);

        return 0;
}
