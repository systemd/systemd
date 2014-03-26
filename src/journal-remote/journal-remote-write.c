/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

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

#include "journal-remote-write.h"

int iovw_put(struct iovec_wrapper *iovw, void* data, size_t len) {
        if (!GREEDY_REALLOC(iovw->iovec, iovw->size_bytes, iovw->count + 1))
                return log_oom();

        iovw->iovec[iovw->count++] = (struct iovec) {data, len};
        return 0;
}

void iovw_free_contents(struct iovec_wrapper *iovw) {
        for (size_t j = 0; j < iovw->count; j++)
                free(iovw->iovec[j].iov_base);
        free(iovw->iovec);
        iovw->iovec = NULL;
        iovw->size_bytes = iovw->count = 0;
}

size_t iovw_size(struct iovec_wrapper *iovw) {
        size_t n = 0, i;

        for(i = 0; i < iovw->count; i++)
                n += iovw->iovec[i].iov_len;

        return n;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int do_rotate(JournalFile **f, bool compress, bool seal) {
        int r = journal_file_rotate(f, compress, seal);
        if (r < 0) {
                if (*f)
                        log_error("Failed to rotate %s: %s", (*f)->path,
                                  strerror(-r));
                else
                        log_error("Failed to create rotated journal: %s",
                                  strerror(-r));
        }

        return r;
}

int writer_init(Writer *s) {
        assert(s);

        s->journal = NULL;

        memset(&s->metrics, 0xFF, sizeof(s->metrics));

        s->mmap = mmap_cache_new();
        if (!s->mmap)
                return log_oom();

        s->seqnum = 0;

        return 0;
}

int writer_close(Writer *s) {
        if (s->journal)
                journal_file_close(s->journal);
        if (s->mmap)
                mmap_cache_unref(s->mmap);
        return 0;
}

int writer_write(Writer *s,
                 struct iovec_wrapper *iovw,
                 dual_timestamp *ts,
                 bool compress,
                 bool seal) {
        int r;

        assert(s);
        assert(iovw);
        assert(iovw->count > 0);

        if (journal_file_rotate_suggested(s->journal, 0)) {
                log_info("%s: Journal header limits reached or header out-of-date, rotating",
                         s->journal->path);
                r = do_rotate(&s->journal, compress, seal);
                if (r < 0)
                        return r;
        }

        r = journal_file_append_entry(s->journal, ts, iovw->iovec, iovw->count,
                                      &s->seqnum, NULL, NULL);
        if (r >= 0)
                return 1;

        log_info("%s: Write failed, rotating", s->journal->path);
        r = do_rotate(&s->journal, compress, seal);
        if (r < 0)
                return r;

        log_debug("Retrying write.");
        r = journal_file_append_entry(s->journal, ts, iovw->iovec, iovw->count,
                                      &s->seqnum, NULL, NULL);
        return r < 0 ? r : 1;
}
