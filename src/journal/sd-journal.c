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

#include <errno.h>
#include <fcntl.h>

#include "sd-journal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "hashmap.h"
#include "list.h"

typedef struct Match Match;

struct Match {
        char *data;
        size_t size;
        uint64_t hash;

        LIST_FIELDS(Match, matches);
};

struct sd_journal {
        Hashmap *files;

        JournalFile *current_file;

        LIST_HEAD(Match, matches);
};

int sd_journal_add_match(sd_journal *j, const char *field, const void *data, size_t size) {
        Match *m;
        char *e;

        assert(j);
        assert(field);
        assert(data || size == 0);

        m = new0(Match, 1);
        if (!m)
                return -ENOMEM;

        m->size = strlen(field) + 1 + size;
        m->data = malloc(m->size);
        if (!m->data) {
                free(m);
                return -ENOMEM;
        }

        e = stpcpy(m->data, field);
        *(e++) = '=';
        memcpy(e, data, size);

        LIST_PREPEND(Match, matches, j->matches, m);
        return 0;
}

void sd_journal_flush_matches(sd_journal *j) {
        assert(j);

        while (j->matches) {
                Match *m = j->matches;

                LIST_REMOVE(Match, matches, j->matches, m);
                free(m->data);
                free(m);
        }
}

static int compare_order(JournalFile *af, Object *ao, uint64_t ap,
                            JournalFile *bf, Object *bo, uint64_t bp) {

        uint64_t a, b;

        if (sd_id128_equal(af->header->seqnum_id, bf->header->seqnum_id)) {

                /* If this is from the same seqnum source, compare
                 * seqnums */
                a = le64toh(ao->entry.seqnum);
                b = le64toh(bo->entry.seqnum);


        } else if (sd_id128_equal(ao->entry.boot_id, bo->entry.boot_id)) {

                /* If the boot id matches compare monotonic time */
                a = le64toh(ao->entry.monotonic);
                b = le64toh(bo->entry.monotonic);

        } else {

                /* Otherwise compare UTC time */
                a = le64toh(ao->entry.realtime);
                b = le64toh(ao->entry.realtime);
        }

        return
                a < b ? -1 :
                a > b ? +1 : 0;
}

int sd_journal_next(sd_journal *j) {
        JournalFile *f, *new_current = NULL;
        Iterator i;
        int r;
        uint64_t new_offset = 0;
        Object *new_entry = NULL;

        assert(j);

        HASHMAP_FOREACH(f, j->files, i) {
                Object *o;
                uint64_t p;

                if (f->current_offset > 0) {
                        r = journal_file_move_to_object(f, f->current_offset, OBJECT_ENTRY, &o);
                        if (r < 0)
                                return r;
                } else
                        o = NULL;

                r = journal_file_next_entry(f, o, &o, &p);
                if (r < 0)
                        return r;
                else if (r == 0)
                        continue;

                if (!new_current || compare_order(new_current, new_entry, new_offset, f, o, p) > 0) {
                        new_current = f;
                        new_entry = o;
                        new_offset = p;
                }
        }

        if (new_current) {
                j->current_file = new_current;
                f->current_offset = new_offset;
                return 1;
        }

        return 0;
}

int sd_journal_previous(sd_journal *j) {
        JournalFile *f, *new_current = NULL;
        Iterator i;
        int r;
        uint64_t new_offset = 0;
        Object *new_entry = NULL;

        assert(j);

        HASHMAP_FOREACH(f, j->files, i) {
                Object *o;
                uint64_t p;

                if (f->current_offset > 0) {
                        r = journal_file_move_to_object(f, f->current_offset, OBJECT_ENTRY, &o);
                        if (r < 0)
                                return r;
                } else
                        o = NULL;

                r = journal_file_prev_entry(f, o, &o, &p);
                if (r < 0)
                        return r;
                else if (r == 0)
                        continue;

                if (!new_current || compare_order(new_current, new_entry, new_offset, f, o, p) > 0) {
                        new_current = f;
                        new_entry = o;
                        new_offset = p;
                }
        }

        if (new_current) {
                j->current_file = new_current;
                f->current_offset = new_offset;
                return 1;
        }

        return 0;
}

int sd_journal_get_cursor(sd_journal *j, void **cursor, size_t *size) {
        JournalCursor *c;
        Object *o;
        int r;

        assert(j);
        assert(cursor);
        assert(size);

        if (!j->current_file || !j->current_file->current_offset <= 0)
                return 0;

        r = journal_file_move_to_object(j->current_file, j->current_file->current_offset, OBJECT_ENTRY, &o);
        if (r < 0)
                return r;

        c = new0(JournalCursor, 1);
        if (!c)
                return -ENOMEM;

        c->version = 1;
        c->seqnum = o->entry.seqnum;
        c->seqnum_id = j->current_file->header->seqnum_id;
        c->boot_id = o->entry.boot_id;
        c->monotonic = o->entry.monotonic;
        c->realtime = o->entry.realtime;
        c->xor_hash = o->entry.xor_hash;

        *cursor = c;
        *size = sizeof(JournalCursor);

        return 1;
}

int sd_journal_set_cursor(sd_journal *j, const void *cursor, size_t size) {
        return -EINVAL;
}

int sd_journal_open(sd_journal **ret) {
        sd_journal *j;
        char *fn;
        const char *p;
        int r = 0;
        const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";

        assert(ret);

        j = new0(sd_journal, 1);
        if (!j)
                return -ENOMEM;

        j->files = hashmap_new(string_hash_func, string_compare_func);
        if (!j->files)
                goto fail;

        NULSTR_FOREACH(p, search_paths) {
                DIR *d;

                d = opendir(p);
                if (!d) {
                        if (errno != ENOENT && r == 0)
                                r = -errno;

                        continue;
                }

                for (;;) {
                        struct dirent buf, *de;
                        int k;
                        JournalFile *f;

                        k = readdir_r(d, &buf, &de);
                        if (k != 0) {
                                if (r == 0)
                                        r = -k;

                                break;
                        }

                        if (!de)
                                break;

                        if (!dirent_is_file_with_suffix(de, ".journal"))
                                continue;

                        fn = join(p, "/", de->d_name, NULL);
                        if (!fn) {
                                r = -ENOMEM;
                                closedir(d);
                                goto fail;
                        }

                        k = journal_file_open(fn, O_RDONLY, 0, NULL, &f);
                        free(fn);

                        if (k < 0) {

                                if (r == 0)
                                        r = -k;
                        } else {
                                k = hashmap_put(j->files, f->path, f);
                                if (k < 0) {
                                        journal_file_close(f);
                                        closedir(d);

                                        r = k;
                                        goto fail;
                                }
                        }
                }
        }

        *ret = j;
        return 0;

fail:
        sd_journal_close(j);

        return r;
};

void sd_journal_close(sd_journal *j) {
        assert(j);

        if (j->files) {
                JournalFile *f;

                while ((f = hashmap_steal_first(j->files)))
                        journal_file_close(f);

                hashmap_free(j->files);
        }

        free(j);
}
