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

#include "wjournal.h"
#include "journal-def.h"

struct WJournal {
        int fd;

        Header *header;
        HashItem *hash_table;
        uint64_t *bisect_table;
};

int wjournal_open(const char *fn, WJournal **ret) {
        assert(fn);
        assert(ret);
}

void wjournal_close(WJournal *j) {
        assert(j);

        if (j->fd >= 0)
                close_nointr_nofail(j->fd);

        if (j->header) {
                munmap(j->header, PAGE_ALIGN(sizeof(Header)));

        }

        free(j);
}

int wjournal_write_object_begin(WJournal *j, uint64_t type, uint64_t size, Object **ret);
int wjournal_write_object_finish(WJournal *j, Object *ret);

int wjournal_write_field(WJournal *j, const char *buffer, uint64_t size, Object **ret);
int wjournal_write_entry(WJournal *j, const Field *fields, unsigned n_fields, Object **ret);
int wjournal_write_eof(WJournal *j);
