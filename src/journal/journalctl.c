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
#include <errno.h>
#include <stddef.h>

#include "journal-file.h"

int main(int argc, char *argv[]) {
        int r;
        JournalFile *f;
        Object *o = NULL;

        log_parse_environment();
        log_open();

        r = journal_file_open("/var/log/journal/system.journal", O_RDONLY, 0644, &f);
        if (r == -ENOENT)
                r = journal_file_open("/run/log/journal/system.journal", O_RDONLY, 0644, &f);

        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        for (;;) {
                uint64_t offset;
                uint64_t n, i;

                r = journal_file_next_entry(f, o, &o, &offset);
                if (r < 0) {
                        log_error("Failed to read journal: %s", strerror(-r));
                        goto finish;
                }

                if (r == 0)
                        break;

                printf("entry: %llu\n", (unsigned long long) le64toh(o->entry.seqnum));

                n = journal_file_entry_n_items(o);
                for (i = 0; i < n; i++) {
                        uint64_t p, l;

                        p = le64toh(o->entry.items[i].object_offset);
                        r = journal_file_move_to_object(f, p, OBJECT_DATA, &o);
                        if (r < 0) {
                                log_error("Failed to move to data: %s", strerror(-r));
                                goto finish;
                        }

                        l = o->object.size - offsetof(Object, data.payload);
                        printf("\t[%.*s]\n", (int) l, o->data.payload);

                        r = journal_file_move_to_object(f, offset, OBJECT_ENTRY, &o);
                        if (r < 0) {
                                log_error("Failed to move back to entry: %s", strerror(-r));
                                goto finish;
                        }
                }
        }

finish:
        journal_file_close(f);

        return 0;
}
