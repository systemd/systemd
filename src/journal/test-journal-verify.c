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
#include "rm-rf.h"
#include "journal-file.h"
#include "journal-verify.h"
#include "terminal-util.h"

#define N_ENTRIES 6000
#define RANDOM_RANGE 77

static void bit_toggle(const char *fn, uint64_t p) {
        uint8_t b;
        ssize_t r;
        int fd;

        fd = open(fn, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        r = pread(fd, &b, 1, p/8);
        assert_se(r == 1);

        b ^= 1 << (p % 8);

        r = pwrite(fd, &b, 1, p/8);
        assert_se(r == 1);

        safe_close(fd);
}

static int raw_verify(const char *fn, const char *verification_key) {
        JournalFile *f;
        int r;

        r = journal_file_open(fn, O_RDONLY, 0666, true, !!verification_key, NULL, NULL, NULL, &f);
        if (r < 0)
                return r;

        r = journal_file_verify(f, verification_key, NULL, NULL, NULL, false);
        journal_file_close(f);

        return r;
}

int main(int argc, char *argv[]) {
        char t[] = "/tmp/journal-XXXXXX";
        unsigned n;
        JournalFile *f;
        const char *verification_key = argv[1];
        usec_t from = 0, to = 0, total = 0;
        char a[FORMAT_TIMESTAMP_MAX];
        char b[FORMAT_TIMESTAMP_MAX];
        char c[FORMAT_TIMESPAN_MAX];
        struct stat st;
        uint64_t p;

        /* journal_file_open requires a valid machine id */
        if (access("/etc/machine-id", F_OK) != 0)
                return EXIT_TEST_SKIP;

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

        assert_se(journal_file_open("test.journal", O_RDONLY, 0666, true, !!verification_key, NULL, NULL, NULL, &f) == 0);
        /* journal_file_print_header(f); */
        journal_file_dump(f);

        assert_se(journal_file_verify(f, verification_key, &from, &to, &total, true) >= 0);

        if (verification_key && JOURNAL_HEADER_SEALED(f->header))
                log_info("=> Validated from %s to %s, %s missing",
                         format_timestamp(a, sizeof(a), from),
                         format_timestamp(b, sizeof(b), to),
                         format_timespan(c, sizeof(c), total > to ? total - to : 0, 0));

        journal_file_close(f);

        if (verification_key) {
                log_info("Toggling bits...");

                assert_se(stat("test.journal", &st) >= 0);

                for (p = 38448*8+0; p < ((uint64_t) st.st_size * 8); p ++) {
                        bit_toggle("test.journal", p);

                        log_info("[ %"PRIu64"+%"PRIu64"]", p / 8, p % 8);

                        if (raw_verify("test.journal", verification_key) >= 0)
                                log_notice(ANSI_HIGHLIGHT_RED ">>>> %"PRIu64" (bit %"PRIu64") can be toggled without detection." ANSI_NORMAL, p / 8, p % 8);

                        bit_toggle("test.journal", p);
                }
        }

        log_info("Exiting...");

        assert_se(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL) >= 0);

        return 0;
}
