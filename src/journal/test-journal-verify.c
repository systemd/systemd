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
#include <unistd.h>
#include <fcntl.h>

#include "util.h"
#include "log.h"
#include "journal-file.h"
#include "journal-verify.h"

#define N_ENTRIES 6000
#define RANDOM_RANGE 77

int main(int argc, char *argv[]) {
        char t[] = "/tmp/journal-XXXXXX";
        unsigned n;
        JournalFile *f;
        const char *verification_key = argv[1];

        log_set_max_level(LOG_DEBUG);

        assert_se(mkdtemp(t));
        assert_se(chdir(t) >= 0);

        log_info("Generating...");

        assert_se(journal_file_open("test.journal", O_RDWR|O_CREAT, 0666, true, !!verification_key, NULL, NULL, NULL, &f) == 0);

        for (n = 0; n < N_ENTRIES; n++) {
                struct iovec iovec;
                struct dual_timestamp ts;
                char *test;

                dual_timestamp_get(&ts);

                assert_se(asprintf(&test, "RANDOM=%lu", random() % RANDOM_RANGE));

                iovec.iov_base = (void*) test;
                iovec.iov_len = strlen(test);

                assert_se(journal_file_append_entry(f, &ts, &iovec, 1, NULL, NULL, NULL) == 0);

                free(test);
        }

        journal_file_close(f);

        log_info("Verifying...");

        assert_se(journal_file_open("test.journal", O_RDONLY, 0666, false, false, NULL, NULL, NULL, &f) == 0);

        journal_file_print_header(f);

        assert_se(journal_file_verify(f, verification_key) >= 0);
        journal_file_close(f);

        log_info("Exiting...");

        assert_se(rm_rf_dangerous(t, false, true, false) >= 0);

        return 0;
}
