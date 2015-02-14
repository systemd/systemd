/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include "log.h"
#include "sd-journal.h"
#include "macro.h"
#include "journal-internal.h"

int main(int argc, char *argv[]) {
        unsigned n = 0;
        _cleanup_journal_close_ sd_journal*j = NULL;

        log_set_max_level(LOG_DEBUG);

        assert_se(sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY) >= 0);

        assert_se(sd_journal_add_match(j, "_TRANSPORT=syslog", 0) >= 0);
        assert_se(sd_journal_add_match(j, "_UID=0", 0) >= 0);

        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                const void *d;
                size_t l;

                assert_se(sd_journal_get_data(j, "MESSAGE", &d, &l) >= 0);

                printf("%.*s\n", (int) l, (char*) d);

                n ++;
                if (n >= 10)
                        break;
        }

        return 0;
}
