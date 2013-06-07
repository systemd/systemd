/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Marius Vollmer

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

#include <unistd.h>
#include <fcntl.h>

#include <systemd/sd-journal.h>

#include "journal-file.h"
#include "journal-internal.h"
#include "util.h"
#include "log.h"

/* This program tests skipping around in a multi-file journal.
 */

static void log_assert_errno(const char *text, int eno, const char *file, int line, const char *func) {
        log_meta(LOG_CRIT, file, line, func,
                 "'%s' failed at %s:%u (%s): %s.",
                 text, file, line, func, strerror(eno));
        abort();
}

#define assert_ret(expr)                                                \
        do {                                                            \
                int _r_ = (expr);                                       \
                if (_unlikely_(_r_ < 0))                                \
                        log_assert_errno(#expr, -_r_, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
        } while (false)

static JournalFile *test_open (const char *name)
{
        JournalFile *f;
        assert_ret(journal_file_open(name, O_RDWR|O_CREAT, 0666, true, false, NULL, NULL, NULL, &f));
        return f;
}

static void test_close (JournalFile *f)
{
        journal_file_close (f);
}

static void test_append_number(JournalFile *f, int n)
{
        char *p;
        dual_timestamp ts;
        struct iovec iovec[1];

        dual_timestamp_get(&ts);

        assert_se(asprintf(&p, "NUMBER=%d", n) >= 0);
        iovec[0].iov_base = p;
        iovec[0].iov_len = strlen(p);
        assert_ret(journal_file_append_entry(f, &ts, iovec, 1, NULL, NULL, NULL));
        free (p);
}

static void test_check_number (sd_journal *j, int n)
{
        const void *d;
        char *k;
        size_t l;
        int x;

        assert_ret(sd_journal_get_data(j, "NUMBER", &d, &l));
        assert_se(k = strndup(d, l));
        printf("%s\n", k);

        assert_se(safe_atoi(k + 7, &x) >= 0);
        assert_se(n == x);
}

static void test_check_numbers_down (sd_journal *j, int count)
{
        for (int i = 1; i <= count; i++) {
                int r;
                test_check_number(j, i);
                assert_ret(r = sd_journal_next(j));
                if (i == count)
                        assert_se(r == 0);
                else
                        assert_se(r == 1);
        }

}

static void test_check_numbers_up (sd_journal *j, int count)
{
        for (int i = count; i >= 1; i--) {
                int r;
                test_check_number(j, i);
                assert_ret(r = sd_journal_previous(j));
                if (i == 1)
                        assert_se(r == 0);
                else
                        assert_se(r == 1);
        }

}

static void setup_sequential(void) {
        JournalFile *one, *two;
        one = test_open("one.journal");
        two = test_open("two.journal");
        test_append_number(one, 1);
        test_append_number(one, 2);
        test_append_number(two, 3);
        test_append_number(two, 4);
        test_close(one);
        test_close(two);
}

static void setup_interleaved(void) {
        JournalFile *one, *two;
        one = test_open("one.journal");
        two = test_open("two.journal");
        test_append_number(one, 1);
        test_append_number(two, 2);
        test_append_number(one, 3);
        test_append_number(two, 4);
        test_close(one);
        test_close(two);
}

static void test_skip(void (*setup)(void))
{
        char t[] = "/tmp/journal-skip-XXXXXX";
        sd_journal *j;
        int r;

        log_set_max_level(LOG_DEBUG);

        assert_se(mkdtemp(t));
        assert_se(chdir(t) >= 0);

        setup();

        /* Seek to head, iterate down.
         */
        assert_ret(sd_journal_open_directory(&j, t, 0));
        assert_ret(sd_journal_seek_head(j));
        assert_ret(sd_journal_next(j));
        test_check_numbers_down(j, 4);
        sd_journal_close(j);

        /* Seek to tail, iterate up.
         */
        assert_ret(sd_journal_open_directory(&j, t, 0));
        assert_ret(sd_journal_seek_tail(j));
        assert_ret(sd_journal_previous(j));
        test_check_numbers_up(j, 4);
        sd_journal_close(j);

        /* Seek to tail, skip to head, iterate down.
         */
        assert_ret(sd_journal_open_directory(&j, t, 0));
        assert_ret(sd_journal_seek_tail(j));
        assert_ret(r = sd_journal_previous_skip(j, 4));
        assert_se(r == 4);
        test_check_numbers_down(j, 4);
        sd_journal_close(j);

        /* Seek to head, skip to tail, iterate up.
         */
        assert_ret(sd_journal_open_directory(&j, t, 0));
        assert_ret(sd_journal_seek_head(j));
        assert_ret(r = sd_journal_next_skip(j, 4));
        assert_se(r == 4);
        test_check_numbers_up(j, 4);
        sd_journal_close(j);

        assert_ret(rm_rf_dangerous(t, false, true, false));
}

int main(int argc, char *argv[]) {
        test_skip(setup_sequential);
        test_skip(setup_interleaved);

        return 0;
}
