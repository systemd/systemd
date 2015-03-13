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

#include "journal-remote.h"

int iovw_put(struct iovec_wrapper *iovw, void* data, size_t len) {
        if (!GREEDY_REALLOC(iovw->iovec, iovw->size_bytes, iovw->count + 1))
                return log_oom();

        iovw->iovec[iovw->count++] = (struct iovec) {data, len};
        return 0;
}

void iovw_free_contents(struct iovec_wrapper *iovw) {
        free(iovw->iovec);
        iovw->iovec = NULL;
        iovw->size_bytes = iovw->count = 0;
}

size_t iovw_size(struct iovec_wrapper *iovw) {
        size_t n = 0, i;

        for (i = 0; i < iovw->count; i++)
                n += iovw->iovec[i].iov_len;

        return n;
}

void iovw_rebase(struct iovec_wrapper *iovw, char *old, char *new) {
        size_t i;

        for (i = 0; i < iovw->count; i++)
                iovw->iovec[i].iov_base = (char*) iovw->iovec[i].iov_base - old + new;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int do_rotate(JournalFile **f, bool compress, bool seal) {
        int r = journal_file_rotate(f, compress, seal);
        if (r < 0) {
                if (*f)
                        log_error_errno(r, "Failed to rotate %s: %m", (*f)->path);
                else
                        log_error_errno(r, "Failed to create rotated journal: %m");
        }

        return r;
}

Writer* writer_new(RemoteServer *server) {
        Writer *w;

        w = new0(Writer, 1);
        if (!w)
                return NULL;

        memset(&w->metrics, 0xFF, sizeof(w->metrics));

        w->mmap = mmap_cache_new();
        if (!w->mmap) {
                free(w);
                return NULL;
        }

        w->n_ref = 1;
        w->server = server;

        return w;
}

Writer* writer_free(Writer *w) {
        if (!w)
                return NULL;

        if (w->journal) {
                log_debug("Closing journal file %s.", w->journal->path);
                journal_file_close(w->journal);
        }

        if (w->server && w->hashmap_key)
                hashmap_remove(w->server->writers, w->hashmap_key);

        free(w->hashmap_key);

        if (w->mmap)
                mmap_cache_unref(w->mmap);

        free(w);

        return NULL;
}

Writer* writer_unref(Writer *w) {
        if (w && (-- w->n_ref <= 0))
                writer_free(w);

        return NULL;
}

Writer* writer_ref(Writer *w) {
        if (w)
                assert_se(++ w->n_ref >= 2);

        return w;
}

int writer_write(Writer *w,
                 struct iovec_wrapper *iovw,
                 dual_timestamp *ts,
                 bool compress,
                 bool seal) {
        int r;

        assert(w);
        assert(iovw);
        assert(iovw->count > 0);

        if (journal_file_rotate_suggested(w->journal, 0)) {
                log_info("%s: Journal header limits reached or header out-of-date, rotating",
                         w->journal->path);
                r = do_rotate(&w->journal, compress, seal);
                if (r < 0)
                        return r;
        }

        r = journal_file_append_entry(w->journal, ts, iovw->iovec, iovw->count,
                                      &w->seqnum, NULL, NULL);
        if (r >= 0) {
                if (w->server)
                        w->server->event_count += 1;
                return 1;
        }

        log_debug_errno(r, "%s: Write failed, rotating: %m", w->journal->path);
        r = do_rotate(&w->journal, compress, seal);
        if (r < 0)
                return r;
        else
                log_debug("%s: Successfully rotated journal", w->journal->path);

        log_debug("Retrying write.");
        r = journal_file_append_entry(w->journal, ts, iovw->iovec, iovw->count,
                                      &w->seqnum, NULL, NULL);
        if (r < 0)
                return r;

        if (w->server)
                w->server->event_count += 1;
        return 1;
}
