/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>

#include "journal-private.h"
#include "log.h"

int main(int argc, char *argv[]) {
        dual_timestamp ts;
        JournalFile *f;
        struct iovec iovec;
        static const char test[] = "test", test2[] = "test2";
        Object *o;

        log_set_max_level(LOG_DEBUG);

        assert_se(journal_file_open(NULL, "test", O_RDWR|O_CREAT, 0666, &f) == 0);

        dual_timestamp_get(&ts);

        iovec.iov_base = (void*) test;
        iovec.iov_len = strlen(test);
        assert_se(journal_file_append_entry(f, &ts, &iovec, 1, NULL, NULL) == 0);

        iovec.iov_base = (void*) test2;
        iovec.iov_len = strlen(test2);
        assert_se(journal_file_append_entry(f, &ts, &iovec, 1, NULL, NULL) == 0);

        iovec.iov_base = (void*) test;
        iovec.iov_len = strlen(test);
        assert_se(journal_file_append_entry(f, &ts, &iovec, 1, NULL, NULL) == 0);

        journal_file_dump(f);

        assert(journal_file_next_entry(f, NULL, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 1);

        assert(journal_file_next_entry(f, o, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 2);

        assert(journal_file_next_entry(f, o, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 3);

        assert(journal_file_next_entry(f, o, &o, NULL) == 0);

        assert(journal_file_find_first_entry(f, test, strlen(test), &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 1);

        assert(journal_file_find_last_entry(f, test, strlen(test), &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 3);

        assert(journal_file_find_last_entry(f, test2, strlen(test2), &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 2);

        assert(journal_file_find_first_entry(f, test2, strlen(test2), &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 2);

        assert(journal_file_find_first_entry(f, "quux", 4, &o, NULL) == 0);

        assert(journal_file_move_to_entry(f, 1, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 1);

        assert(journal_file_move_to_entry(f, 3, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 3);

        assert(journal_file_move_to_entry(f, 2, &o, NULL) == 1);
        assert(le64toh(o->entry.seqnum) == 2);

        assert(journal_file_move_to_entry(f, 10, &o, NULL) == 0);

        journal_file_close(f);

        return 0;
}
