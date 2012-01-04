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
#include <stddef.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "sd-journal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "hashmap.h"
#include "list.h"
#include "lookup3.h"
#include "compress.h"
#include "journal-internal.h"

#define JOURNAL_FILES_MAX 1024

static void detach_location(sd_journal *j) {
        Iterator i;
        JournalFile *f;

        assert(j);

        j->current_file = NULL;
        j->current_field = 0;

        HASHMAP_FOREACH(f, j->files, i)
                f->current_offset = 0;
}

static void reset_location(sd_journal *j) {
        assert(j);

        detach_location(j);
        zero(j->current_location);
}

static void init_location(Location *l, JournalFile *f, Object *o) {
        assert(l);
        assert(f);
        assert(o->object.type == OBJECT_ENTRY);

        l->type = LOCATION_DISCRETE;
        l->seqnum = le64toh(o->entry.seqnum);
        l->seqnum_id = f->header->seqnum_id;
        l->realtime = le64toh(o->entry.realtime);
        l->monotonic = le64toh(o->entry.monotonic);
        l->boot_id = le64toh(o->entry.boot_id);
        l->xor_hash = le64toh(o->entry.xor_hash);

        l->seqnum_set = l->realtime_set = l->monotonic_set = l->xor_hash_set = true;
}

static void set_location(sd_journal *j, JournalFile *f, Object *o, uint64_t offset) {
        assert(j);
        assert(f);
        assert(o);

        init_location(&j->current_location, f, o);

        j->current_file = f;
        j->current_field = 0;

        f->current_offset = offset;
}

static int same_field(const void *_a, size_t s, const void *_b, size_t t) {
        const uint8_t *a = _a, *b = _b;
        size_t j;
        bool a_good = false, b_good = false, different = false;

        for (j = 0; j < s && j < t; j++) {

                if (a[j] == '=')
                        a_good = true;
                if (b[j] == '=')
                        b_good = true;
                if (a[j] != b[j])
                        different = true;

                if (a_good && b_good)
                        return different ? 0 : 1;
        }

        return -EINVAL;
}

_public_ int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        Match *m, *after = NULL;
        uint64_t le_hash;

        if (!j)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (size <= 0)
                return -EINVAL;

        le_hash = htole64(hash64(data, size));

        LIST_FOREACH(matches, m, j->matches) {
                int r;

                if (m->le_hash == le_hash &&
                    m->size == size &&
                    memcmp(m->data, data, size) == 0)
                        return 0;

                r = same_field(data, size, m->data, m->size);
                if (r < 0)
                        return r;
                else if (r > 0)
                        after = m;
        }

        m = new0(Match, 1);
        if (!m)
                return -ENOMEM;

        m->size = size;

        m->data = malloc(m->size);
        if (!m->data) {
                free(m);
                return -ENOMEM;
        }

        memcpy(m->data, data, size);
        m->le_hash = le_hash;

        /* Matches for the same fields we order adjacent to each
         * other */
        LIST_INSERT_AFTER(Match, matches, j->matches, after, m);
        j->n_matches ++;

        detach_location(j);

        return 0;
}

_public_ void sd_journal_flush_matches(sd_journal *j) {
        if (!j)
                return;

        while (j->matches) {
                Match *m = j->matches;

                LIST_REMOVE(Match, matches, j->matches, m);
                free(m->data);
                free(m);
        }

        j->n_matches = 0;

        detach_location(j);
}

static int compare_order(JournalFile *af, Object *ao,
                         JournalFile *bf, Object *bo) {

        uint64_t a, b;

        assert(af);
        assert(ao);
        assert(bf);
        assert(bo);

        /* We operate on two different files here, hence we can access
         * two objects at the same time, which we normally can't.
         *
         * If contents and timestamps match, these entries are
         * identical, even if the seqnum does not match */

        if (sd_id128_equal(ao->entry.boot_id, bo->entry.boot_id) &&
            ao->entry.monotonic == bo->entry.monotonic &&
            ao->entry.realtime == bo->entry.realtime &&
            ao->entry.xor_hash == bo->entry.xor_hash)
                return 0;

        if (sd_id128_equal(af->header->seqnum_id, bf->header->seqnum_id)) {

                /* If this is from the same seqnum source, compare
                 * seqnums */
                a = le64toh(ao->entry.seqnum);
                b = le64toh(bo->entry.seqnum);

                if (a < b)
                        return -1;
                if (a > b)
                        return 1;

                /* Wow! This is weird, different data but the same
                 * seqnums? Something is borked, but let's make the
                 * best of it and compare by time. */
        }

        if (sd_id128_equal(ao->entry.boot_id, bo->entry.boot_id)) {

                /* If the boot id matches compare monotonic time */
                a = le64toh(ao->entry.monotonic);
                b = le64toh(bo->entry.monotonic);

                if (a < b)
                        return -1;
                if (a > b)
                        return 1;
        }

        /* Otherwise compare UTC time */
        a = le64toh(ao->entry.realtime);
        b = le64toh(ao->entry.realtime);

        if (a < b)
                return -1;
        if (a > b)
                return 1;

        /* Finally, compare by contents */
        a = le64toh(ao->entry.xor_hash);
        b = le64toh(ao->entry.xor_hash);

        if (a < b)
                return -1;
        if (a > b)
                return 1;

        return 0;
}

static int compare_with_location(JournalFile *af, Object *ao, Location *l) {
        uint64_t a;

        assert(af);
        assert(ao);
        assert(l);
        assert(l->type == LOCATION_DISCRETE);

        if (l->monotonic_set &&
            sd_id128_equal(ao->entry.boot_id, l->boot_id) &&
            l->realtime_set &&
            le64toh(ao->entry.realtime) == l->realtime &&
            l->xor_hash_set &&
            le64toh(ao->entry.xor_hash) == l->xor_hash)
                return 0;

        if (l->seqnum_set &&
            sd_id128_equal(af->header->seqnum_id, l->seqnum_id)) {

                a = le64toh(ao->entry.seqnum);

                if (a < l->seqnum)
                        return -1;
                if (a > l->seqnum)
                        return 1;
        }

        if (l->monotonic_set &&
            sd_id128_equal(ao->entry.boot_id, l->boot_id)) {

                a = le64toh(ao->entry.monotonic);

                if (a < l->monotonic)
                        return -1;
                if (a > l->monotonic)
                        return 1;
        }

        if (l->realtime_set) {

                a = le64toh(ao->entry.realtime);

                if (a < l->realtime)
                        return -1;
                if (a > l->realtime)
                        return 1;
        }

        if (l->xor_hash_set) {
                a = le64toh(ao->entry.xor_hash);

                if (a < l->xor_hash)
                        return -1;
                if (a > l->xor_hash)
                        return 1;
        }

        return 0;
}

static int find_location(sd_journal *j, JournalFile *f, direction_t direction, Object **ret, uint64_t *offset) {
        Object *o = NULL;
        uint64_t p = 0;
        int r;

        assert(j);

        if (!j->matches) {
                /* No matches is simple */

                if (j->current_location.type == LOCATION_HEAD)
                        r = journal_file_next_entry(f, NULL, 0, DIRECTION_DOWN, &o, &p);
                else if (j->current_location.type == LOCATION_TAIL)
                        r = journal_file_next_entry(f, NULL, 0, DIRECTION_UP, &o, &p);
                else if (j->current_location.seqnum_set &&
                         sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        r = journal_file_move_to_entry_by_seqnum(f, j->current_location.seqnum, direction, &o, &p);
                else if (j->current_location.monotonic_set)
                        r = journal_file_move_to_entry_by_monotonic(f, j->current_location.boot_id, j->current_location.monotonic, direction, &o, &p);
                else if (j->current_location.realtime_set)
                        r = journal_file_move_to_entry_by_realtime(f, j->current_location.realtime, direction, &o, &p);
                else
                        r = journal_file_next_entry(f, NULL, 0, direction, &o, &p);

                if (r <= 0)
                        return r;

        } else  {
                Match *m, *term_match = NULL;
                Object *to = NULL;
                uint64_t tp = 0;

                /* We have matches, first, let's jump to the monotonic
                 * position if we have any, since it implies a
                 * match. */

                if (j->current_location.type == LOCATION_DISCRETE &&
                    j->current_location.monotonic_set) {

                        r = journal_file_move_to_entry_by_monotonic(f, j->current_location.boot_id, j->current_location.monotonic, direction, &o, &p);
                        if (r <= 0)
                                return r == -ENOENT ? 0 : r;
                }

                LIST_FOREACH(matches, m, j->matches) {
                        Object *c, *d;
                        uint64_t cp, dp;

                        r = journal_file_find_data_object_with_hash(f, m->data, m->size, m->le_hash, &d, &dp);
                        if (r <= 0)
                                return r;

                        if (j->current_location.type == LOCATION_HEAD)
                                r = journal_file_next_entry_for_data(f, NULL, 0, dp, DIRECTION_DOWN, &c, &cp);
                        else if (j->current_location.type == LOCATION_TAIL)
                                r = journal_file_next_entry_for_data(f, NULL, 0, dp, DIRECTION_UP, &c, &cp);
                        else if (j->current_location.seqnum_set &&
                                 sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                                r = journal_file_move_to_entry_by_seqnum_for_data(f, dp, j->current_location.seqnum, direction, &c, &cp);
                        else if (j->current_location.realtime_set)
                                r = journal_file_move_to_entry_by_realtime_for_data(f, dp, j->current_location.realtime, direction, &c, &cp);
                        else
                                r = journal_file_next_entry_for_data(f, NULL, 0, dp, direction, &c, &cp);

                        if (!term_match) {
                                term_match = m;

                                if (r > 0) {
                                        to = c;
                                        tp = cp;
                                }
                        } else if (same_field(term_match->data, term_match->size, m->data, m->size)) {

                                /* Same field as previous match... */
                                if (r > 0) {

                                        /* Find the earliest of the OR matches */

                                        if (!to ||
                                            (direction == DIRECTION_DOWN && cp < tp) ||
                                            (direction == DIRECTION_UP && cp > tp)) {
                                                to = c;
                                                tp = cp;
                                        }

                                }

                        } else {

                                /* Previous term is finished, did anything match? */
                                if (!to)
                                        return 0;

                                /* Find the last of the AND matches */
                                if (!o ||
                                    (direction == DIRECTION_DOWN && tp > p) ||
                                    (direction == DIRECTION_UP && tp < p)) {
                                        o = to;
                                        p = tp;
                                }

                                term_match = m;

                                if (r > 0) {
                                        to = c;
                                        tp = cp;
                                } else {
                                        to = NULL;
                                        tp = 0;
                                }
                        }
                }

                /* Last term is finished, did anything match? */
                if (!to)
                        return 0;

                if (!o ||
                    (direction == DIRECTION_DOWN && tp > p) ||
                    (direction == DIRECTION_UP && tp < p)) {
                        o = to;
                        p = tp;
                }

                if (!o)
                        return 0;
        }

        if (ret)
                *ret = o;

        if (offset)
                *offset = p;

        return 1;
}

static int next_with_matches(sd_journal *j, JournalFile *f, direction_t direction, Object **ret, uint64_t *offset) {
        int r;
        uint64_t cp;
        Object *c;

        assert(j);
        assert(f);
        assert(ret);
        assert(offset);

        c = *ret;
        cp = *offset;

        if (!j->matches) {
                /* No matches is easy */

                r = journal_file_next_entry(f, c, cp, direction, &c, &cp);
                if (r <= 0)
                        return r;

                if (ret)
                        *ret = c;
                if (offset)
                        *offset = cp;
                return 1;
        }

        /* So there are matches we have to adhere to, let's find the
         * first entry that matches all of them */

        for (;;) {
                uint64_t np, n;
                bool found, term_result = false;
                Match *m, *term_match = NULL;
                Object *npo = NULL;

                n = journal_file_entry_n_items(c);

                /* Make sure we don't match the entry we are starting
                 * from. */
                found = cp > *offset;

                np = 0;
                LIST_FOREACH(matches, m, j->matches) {
                        uint64_t q, k;
                        Object *qo = NULL;

                        /* Let's check if this is the beginning of a
                         * new term, i.e. has a different field prefix
                         * as the preceeding match. */
                        if (!term_match) {
                                term_match = m;
                                term_result = false;
                        } else if (!same_field(term_match->data, term_match->size, m->data, m->size)) {
                                if (!term_result)
                                        found = false;

                                term_match = m;
                                term_result = false;
                        }

                        for (k = 0; k < n; k++)
                                if (c->entry.items[k].hash == m->le_hash)
                                        break;

                        if (k >= n) {
                                /* Hmm, didn't find any field that
                                 * matched this rule, so ignore this
                                 * match. Go on with next match */
                                continue;
                        }

                        term_result = true;

                        /* Hmm, so, this field matched, let's remember
                         * where we'd have to try next, in case the other
                         * matches are not OK */

                        r = journal_file_next_entry_for_data(f, c, cp, le64toh(c->entry.items[k].object_offset), direction, &qo, &q);
                        if (r < 0)
                                return r;

                        if (r > 0) {

                                if (direction == DIRECTION_DOWN) {
                                        if (q > np) {
                                                np = q;
                                                npo = qo;
                                        }
                                } else {
                                        if (np == 0 || q < np) {
                                                np = q;
                                                npo = qo;
                                        }
                                }
                        }
                }

                /* Check the last term */
                if (term_match && !term_result)
                        found = false;

                /* Did this entry match against all matches? */
                if (found) {
                        if (ret)
                                *ret = c;
                        if (offset)
                                *offset = cp;
                        return 1;
                }

                /* Did we find a subsequent entry? */
                if (np == 0)
                        return 0;

                /* Hmm, ok, this entry only matched partially, so
                 * let's try another one */
                cp = np;
                c = npo;
        }
}

static int next_beyond_location(sd_journal *j, JournalFile *f, direction_t direction, Object **ret, uint64_t *offset) {
        Object *c;
        uint64_t cp;
        int compare_value, r;

        assert(j);
        assert(f);

        if (f->current_offset > 0) {
                cp = f->current_offset;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, cp, &c);
                if (r < 0)
                        return r;

                r = next_with_matches(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;

                compare_value = 1;
        } else {
                r = find_location(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;

                compare_value = 0;
        }

        for (;;) {
                bool found;

                if (j->current_location.type == LOCATION_DISCRETE) {
                        int k;

                        k = compare_with_location(f, c, &j->current_location);
                        if (direction == DIRECTION_DOWN)
                                found = k >= compare_value;
                        else
                                found = k <= -compare_value;
                } else
                        found = true;

                if (found) {
                        if (ret)
                                *ret = c;
                        if (offset)
                                *offset = cp;
                        return 1;
                }

                r = next_with_matches(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;
        }
}

static int real_journal_next(sd_journal *j, direction_t direction) {
        JournalFile *f, *new_current = NULL;
        Iterator i;
        int r;
        uint64_t new_offset = 0;
        Object *new_entry = NULL;

        if (!j)
                return -EINVAL;

        HASHMAP_FOREACH(f, j->files, i) {
                Object *o;
                uint64_t p;
                bool found;

                r = next_beyond_location(j, f, direction, &o, &p);
                if (r < 0)
                        return r;
                else if (r == 0)
                        continue;

                if (!new_current)
                        found = true;
                else {
                        int k;

                        k = compare_order(f, o, new_current, new_entry);

                        if (direction == DIRECTION_DOWN)
                                found = k < 0;
                        else
                                found = k > 0;
                }

                if (found) {
                        new_current = f;
                        new_entry = o;
                        new_offset = p;
                }
        }

        if (!new_current)
                return 0;

        set_location(j, new_current, new_entry, new_offset);

        return 1;
}

_public_ int sd_journal_next(sd_journal *j) {
        return real_journal_next(j, DIRECTION_DOWN);
}

_public_ int sd_journal_previous(sd_journal *j) {
        return real_journal_next(j, DIRECTION_UP);
}

_public_ int sd_journal_next_skip(sd_journal *j, uint64_t skip) {
        int c = 0, r;

        if (!j)
                return -EINVAL;

        while (skip > 0) {
                r = sd_journal_next(j);
                if (r < 0)
                        return r;

                if (r == 0)
                        return c;

                skip--;
                c++;
        }

        return c;
}

_public_ int sd_journal_previous_skip(sd_journal *j, uint64_t skip) {
        int c = 0, r;

        if (!j)
                return -EINVAL;

        while (skip > 0) {
                r = sd_journal_previous(j);
                if (r < 0)
                        return r;

                if (r == 0)
                        return c;

                skip--;
                c++;
        }

        return 1;
}

_public_ int sd_journal_get_cursor(sd_journal *j, char **cursor) {
        Object *o;
        int r;
        char bid[33], sid[33];

        if (!j)
                return -EINVAL;
        if (!cursor)
                return -EINVAL;

        if (!j->current_file || j->current_file->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(j->current_file, OBJECT_ENTRY, j->current_file->current_offset, &o);
        if (r < 0)
                return r;

        sd_id128_to_string(j->current_file->header->seqnum_id, sid);
        sd_id128_to_string(o->entry.boot_id, bid);

        if (asprintf(cursor,
                     "s=%s;i=%llx;b=%s;m=%llx;t=%llx;x=%llx;p=%s",
                     sid, (unsigned long long) le64toh(o->entry.seqnum),
                     bid, (unsigned long long) le64toh(o->entry.monotonic),
                     (unsigned long long) le64toh(o->entry.realtime),
                     (unsigned long long) le64toh(o->entry.xor_hash),
                     file_name_from_path(j->current_file->path)) < 0)
                return -ENOMEM;

        return 1;
}

_public_ int sd_journal_seek_cursor(sd_journal *j, const char *cursor) {
        char *w;
        size_t l;
        char *state;
        unsigned long long seqnum, monotonic, realtime, xor_hash;
        bool
                seqnum_id_set = false,
                seqnum_set = false,
                boot_id_set = false,
                monotonic_set = false,
                realtime_set = false,
                xor_hash_set = false;
        sd_id128_t seqnum_id, boot_id;

        if (!j)
                return -EINVAL;
        if (!cursor)
                return -EINVAL;

        FOREACH_WORD_SEPARATOR(w, l, cursor, ";", state) {
                char *item;
                int k = 0;

                if (l < 2 || w[1] != '=')
                        return -EINVAL;

                item = strndup(w, l);
                if (!item)
                        return -ENOMEM;

                switch (w[0]) {

                case 's':
                        seqnum_id_set = true;
                        k = sd_id128_from_string(w+2, &seqnum_id);
                        break;

                case 'i':
                        seqnum_set = true;
                        if (sscanf(w+2, "%llx", &seqnum) != 1)
                                k = -EINVAL;
                        break;

                case 'b':
                        boot_id_set = true;
                        k = sd_id128_from_string(w+2, &boot_id);
                        break;

                case 'm':
                        monotonic_set = true;
                        if (sscanf(w+2, "%llx", &monotonic) != 1)
                                k = -EINVAL;
                        break;

                case 't':
                        realtime_set = true;
                        if (sscanf(w+2, "%llx", &realtime) != 1)
                                k = -EINVAL;
                        break;

                case 'x':
                        xor_hash_set = true;
                        if (sscanf(w+2, "%llx", &xor_hash) != 1)
                                k = -EINVAL;
                        break;
                }

                free(item);

                if (k < 0)
                        return k;
        }

        if ((!seqnum_set || !seqnum_id_set) &&
            (!monotonic_set || !boot_id_set) &&
            !realtime_set)
                return -EINVAL;

        reset_location(j);

        j->current_location.type = LOCATION_DISCRETE;

        if (realtime_set) {
                j->current_location.realtime = (uint64_t) realtime;
                j->current_location.realtime_set = true;
        }

        if (seqnum_set && seqnum_id_set) {
                j->current_location.seqnum = (uint64_t) seqnum;
                j->current_location.seqnum_id = seqnum_id;
                j->current_location.seqnum_set = true;
        }

        if (monotonic_set && boot_id_set) {
                j->current_location.monotonic = (uint64_t) monotonic;
                j->current_location.boot_id = boot_id;
                j->current_location.monotonic_set = true;
        }

        if (xor_hash_set) {
                j->current_location.xor_hash = (uint64_t) xor_hash;
                j->current_location.xor_hash_set = true;
        }

        return 0;
}

_public_ int sd_journal_seek_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t usec) {
        if (!j)
                return -EINVAL;

        reset_location(j);
        j->current_location.type = LOCATION_DISCRETE;
        j->current_location.boot_id = boot_id;
        j->current_location.monotonic = usec;
        j->current_location.monotonic_set = true;

        return 0;
}

_public_ int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec) {
        if (!j)
                return -EINVAL;

        reset_location(j);
        j->current_location.type = LOCATION_DISCRETE;
        j->current_location.realtime = usec;
        j->current_location.realtime_set = true;

        return 0;
}

_public_ int sd_journal_seek_head(sd_journal *j) {
        if (!j)
                return -EINVAL;

        reset_location(j);
        j->current_location.type = LOCATION_HEAD;

        return 0;
}

_public_ int sd_journal_seek_tail(sd_journal *j) {
        if (!j)
                return -EINVAL;

        reset_location(j);
        j->current_location.type = LOCATION_TAIL;

        return 0;
}

static int add_file(sd_journal *j, const char *prefix, const char *dir, const char *filename) {
        char *fn;
        int r;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        if ((j->flags & SD_JOURNAL_SYSTEM_ONLY) &&
            !startswith(filename, "system.journal"))
                return 0;

        if (dir)
                fn = join(prefix, "/", dir, "/", filename, NULL);
        else
                fn = join(prefix, "/", filename, NULL);

        if (!fn)
                return -ENOMEM;

        if (hashmap_get(j->files, fn)) {
                free(fn);
                return 0;
        }

        if (hashmap_size(j->files) >= JOURNAL_FILES_MAX) {
                log_debug("Too many open journal files, not adding %s, ignoring.", fn);
                free(fn);
                return 0;
        }

        r = journal_file_open(fn, O_RDONLY, 0, NULL, &f);
        free(fn);

        if (r < 0) {
                if (errno == ENOENT)
                        return 0;

                return r;
        }

        /* journal_file_dump(f); */

        r = hashmap_put(j->files, f->path, f);
        if (r < 0) {
                journal_file_close(f);
                return r;
        }

        log_debug("File %s got added.", f->path);

        return 0;
}

static int remove_file(sd_journal *j, const char *prefix, const char *dir, const char *filename) {
        char *fn;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        if (dir)
                fn = join(prefix, "/", dir, "/", filename, NULL);
        else
                fn = join(prefix, "/", filename, NULL);

        if (!fn)
                return -ENOMEM;

        f = hashmap_get(j->files, fn);
        free(fn);

        if (!f)
                return 0;

        hashmap_remove(j->files, f->path);
        journal_file_close(f);

        log_debug("File %s got removed.", f->path);
        return 0;
}

static int add_directory(sd_journal *j, const char *prefix, const char *dir) {
        char *fn;
        int r;
        DIR *d;
        int wd;
        sd_id128_t id, mid;

        assert(j);
        assert(prefix);
        assert(dir);

        if ((j->flags & SD_JOURNAL_LOCAL_ONLY) &&
            (sd_id128_from_string(dir, &id) < 0 ||
             sd_id128_get_machine(&mid) < 0 ||
             !sd_id128_equal(id, mid)))
            return 0;

        fn = join(prefix, "/", dir, NULL);
        if (!fn)
                return -ENOMEM;

        d = opendir(fn);

        if (!d) {
                free(fn);
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        wd = inotify_add_watch(j->inotify_fd, fn,
                               IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                               IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT|
                               IN_DONT_FOLLOW|IN_ONLYDIR);
        if (wd > 0) {
                if (hashmap_put(j->inotify_wd_dirs, INT_TO_PTR(wd), fn) < 0)
                        inotify_rm_watch(j->inotify_fd, wd);
                else
                        fn = NULL;
        }

        free(fn);

        for (;;) {
                struct dirent buf, *de;

                r = readdir_r(d, &buf, &de);
                if (r != 0 || !de)
                        break;

                if (!dirent_is_file_with_suffix(de, ".journal"))
                        continue;

                r = add_file(j, prefix, dir, de->d_name);
                if (r < 0)
                        log_debug("Failed to add file %s/%s/%s: %s", prefix, dir, de->d_name, strerror(-r));
        }

        closedir(d);

        log_debug("Directory %s/%s got added.", prefix, dir);

        return 0;
}

static void remove_directory_wd(sd_journal *j, int wd) {
        char *p;

        assert(j);
        assert(wd > 0);

        if (j->inotify_fd >= 0)
                inotify_rm_watch(j->inotify_fd, wd);

        p = hashmap_remove(j->inotify_wd_dirs, INT_TO_PTR(wd));

        if (p) {
                log_debug("Directory %s got removed.", p);
                free(p);
        }
}

static void add_root_wd(sd_journal *j, const char *p) {
        int wd;
        char *k;

        assert(j);
        assert(p);

        wd = inotify_add_watch(j->inotify_fd, p,
                               IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                               IN_DONT_FOLLOW|IN_ONLYDIR);
        if (wd <= 0)
                return;

        k = strdup(p);
        if (!k || hashmap_put(j->inotify_wd_roots, INT_TO_PTR(wd), k) < 0) {
                inotify_rm_watch(j->inotify_fd, wd);
                free(k);
        }
}

static void remove_root_wd(sd_journal *j, int wd) {
        char *p;

        assert(j);
        assert(wd > 0);

        if (j->inotify_fd >= 0)
                inotify_rm_watch(j->inotify_fd, wd);

        p = hashmap_remove(j->inotify_wd_roots, INT_TO_PTR(wd));

        if (p) {
                log_debug("Root %s got removed.", p);
                free(p);
        }
}

_public_ int sd_journal_open(sd_journal **ret, int flags) {
        sd_journal *j;
        const char *p;
        const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";
        int r;

        if (!ret)
                return -EINVAL;

        if (flags & ~(SD_JOURNAL_LOCAL_ONLY|
                      SD_JOURNAL_RUNTIME_ONLY|
                      SD_JOURNAL_SYSTEM_ONLY))
                return -EINVAL;

        j = new0(sd_journal, 1);
        if (!j)
                return -ENOMEM;

        j->flags = flags;

        j->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (j->inotify_fd < 0) {
                r = -errno;
                goto fail;
        }

        j->files = hashmap_new(string_hash_func, string_compare_func);
        if (!j->files) {
                r = -ENOMEM;
                goto fail;
        }

        j->inotify_wd_dirs = hashmap_new(trivial_hash_func, trivial_compare_func);
        j->inotify_wd_roots = hashmap_new(trivial_hash_func, trivial_compare_func);

        if (!j->inotify_wd_dirs || !j->inotify_wd_roots) {
                r = -ENOMEM;
                goto fail;
        }

        /* We ignore most errors here, since the idea is to only open
         * what's actually accessible, and ignore the rest. */

        NULSTR_FOREACH(p, search_paths) {
                DIR *d;

                if ((flags & SD_JOURNAL_RUNTIME_ONLY) &&
                    !path_startswith(p, "/run"))
                        continue;

                d = opendir(p);
                if (!d) {
                        if (errno != ENOENT)
                                log_debug("Failed to open %s: %m", p);
                        continue;
                }

                add_root_wd(j, p);

                for (;;) {
                        struct dirent buf, *de;
                        sd_id128_t id;

                        r = readdir_r(d, &buf, &de);
                        if (r != 0 || !de)
                                break;

                        if (dirent_is_file_with_suffix(de, ".journal")) {
                                r = add_file(j, p, NULL, de->d_name);
                                if (r < 0)
                                        log_debug("Failed to add file %s/%s: %s", p, de->d_name, strerror(-r));

                        } else if ((de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) &&
                                   sd_id128_from_string(de->d_name, &id) >= 0) {

                                r = add_directory(j, p, de->d_name);
                                if (r < 0)
                                        log_debug("Failed to add directory %s/%s: %s", p, de->d_name, strerror(-r));
                        }
                }

                closedir(d);
        }

        *ret = j;
        return 0;

fail:
        sd_journal_close(j);

        return r;
};

_public_ void sd_journal_close(sd_journal *j) {
        if (!j)
                return;

        if (j->inotify_wd_dirs) {
                void *k;

                while ((k = hashmap_first_key(j->inotify_wd_dirs)))
                        remove_directory_wd(j, PTR_TO_INT(k));

                hashmap_free(j->inotify_wd_dirs);
        }

        if (j->inotify_wd_roots) {
                void *k;

                while ((k = hashmap_first_key(j->inotify_wd_roots)))
                        remove_root_wd(j, PTR_TO_INT(k));

                hashmap_free(j->inotify_wd_roots);
        }

        if (j->files) {
                JournalFile *f;

                while ((f = hashmap_steal_first(j->files)))
                        journal_file_close(f);

                hashmap_free(j->files);
        }

        sd_journal_flush_matches(j);

        if (j->inotify_fd >= 0)
                close_nointr_nofail(j->inotify_fd);

        free(j);
}

_public_ int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret) {
        Object *o;
        JournalFile *f;
        int r;

        if (!j)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;

        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        *ret = le64toh(o->entry.realtime);
        return 0;
}

_public_ int sd_journal_get_monotonic_usec(sd_journal *j, uint64_t *ret, sd_id128_t *ret_boot_id) {
        Object *o;
        JournalFile *f;
        int r;
        sd_id128_t id;

        if (!j)
                return -EINVAL;
        if (!ret)
                return -EINVAL;

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;

        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        if (ret_boot_id)
                *ret_boot_id = o->entry.boot_id;
        else {
                r = sd_id128_get_boot(&id);
                if (r < 0)
                        return r;

                if (!sd_id128_equal(id, o->entry.boot_id))
                        return -ENOENT;
        }

        *ret = le64toh(o->entry.monotonic);
        return 0;
}

_public_ int sd_journal_get_data(sd_journal *j, const char *field, const void **data, size_t *size) {
        JournalFile *f;
        uint64_t i, n;
        size_t field_length;
        int r;
        Object *o;

        if (!j)
                return -EINVAL;
        if (!field)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (!size)
                return -EINVAL;

        if (isempty(field) || strchr(field, '='))
                return -EINVAL;

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;

        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        field_length = strlen(field);

        n = journal_file_entry_n_items(o);
        for (i = 0; i < n; i++) {
                uint64_t p, l, le_hash;
                size_t t;

                p = le64toh(o->entry.items[i].object_offset);
                le_hash = o->entry.items[i].hash;
                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                if (le_hash != o->data.hash)
                        return -EBADMSG;

                l = le64toh(o->object.size) - offsetof(Object, data.payload);

                if (o->object.flags & OBJECT_COMPRESSED) {

#ifdef HAVE_XZ
                        if (uncompress_startswith(o->data.payload, l,
                                                  &f->compress_buffer, &f->compress_buffer_size,
                                                  field, field_length, '=')) {

                                uint64_t rsize;

                                if (!uncompress_blob(o->data.payload, l,
                                                     &f->compress_buffer, &f->compress_buffer_size, &rsize))
                                        return -EBADMSG;

                                *data = f->compress_buffer;
                                *size = (size_t) rsize;

                                return 0;
                        }
#else
                        return -EPROTONOSUPPORT;
#endif

                } else if (l >= field_length+1 &&
                           memcmp(o->data.payload, field, field_length) == 0 &&
                           o->data.payload[field_length] == '=') {

                        t = (size_t) l;

                        if ((uint64_t) t != l)
                                return -E2BIG;

                        *data = o->data.payload;
                        *size = t;

                        return 0;
                }

                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
                if (r < 0)
                        return r;
        }

        return -ENOENT;
}

_public_ int sd_journal_enumerate_data(sd_journal *j, const void **data, size_t *size) {
        JournalFile *f;
        uint64_t p, l, n, le_hash;
        int r;
        Object *o;
        size_t t;

        if (!j)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (!size)
                return -EINVAL;

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;

        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        n = journal_file_entry_n_items(o);
        if (j->current_field >= n)
                return 0;

        p = le64toh(o->entry.items[j->current_field].object_offset);
        le_hash = o->entry.items[j->current_field].hash;
        r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
        if (r < 0)
                return r;

        if (le_hash != o->data.hash)
                return -EBADMSG;

        l = le64toh(o->object.size) - offsetof(Object, data.payload);
        t = (size_t) l;

        /* We can't read objects larger than 4G on a 32bit machine */
        if ((uint64_t) t != l)
                return -E2BIG;

        if (o->object.flags & OBJECT_COMPRESSED) {
#ifdef HAVE_XZ
                uint64_t rsize;

                if (!uncompress_blob(o->data.payload, l, &f->compress_buffer, &f->compress_buffer_size, &rsize))
                        return -EBADMSG;

                *data = f->compress_buffer;
                *size = (size_t) rsize;
#else
                return -EPROTONOSUPPORT;
#endif
        } else {
                *data = o->data.payload;
                *size = t;
        }

        j->current_field ++;

        return 1;
}

_public_ void sd_journal_restart_data(sd_journal *j) {
        if (!j)
                return;

        j->current_field = 0;
}

_public_ int sd_journal_get_fd(sd_journal *j) {
        if (!j)
                return -EINVAL;

        return j->inotify_fd;
}

static void process_inotify_event(sd_journal *j, struct inotify_event *e) {
        char *p;
        int r;

        assert(j);
        assert(e);

        /* Is this a subdirectory we watch? */
        p = hashmap_get(j->inotify_wd_dirs, INT_TO_PTR(e->wd));
        if (p) {

                if (!(e->mask & IN_ISDIR) && e->len > 0 && endswith(e->name, ".journal")) {

                        /* Event for a journal file */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_file(j, p, NULL, e->name);
                                if (r < 0)
                                        log_debug("Failed to add file %s/%s: %s", p, e->name, strerror(-r));
                        } else if (e->mask & (IN_DELETE|IN_UNMOUNT)) {

                                r = remove_file(j, p, NULL, e->name);
                                if (r < 0)
                                        log_debug("Failed to remove file %s/%s: %s", p, e->name, strerror(-r));
                        }

                } else if (e->len == 0) {

                        /* Event for the directory itself */

                        if (e->mask & (IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT))
                                remove_directory_wd(j, e->wd);
                }

                return;
        }

        /* Must be the root directory then? */
        p = hashmap_get(j->inotify_wd_roots, INT_TO_PTR(e->wd));
        if (p) {
                sd_id128_t id;

                if (!(e->mask & IN_ISDIR) && e->len > 0 && endswith(e->name, ".journal")) {

                        /* Event for a journal file */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_file(j, p, NULL, e->name);
                                if (r < 0)
                                        log_debug("Failed to add file %s/%s: %s", p, e->name, strerror(-r));
                        } else if (e->mask & (IN_DELETE|IN_UNMOUNT)) {

                                r = remove_file(j, p, NULL, e->name);
                                if (r < 0)
                                        log_debug("Failed to remove file %s/%s: %s", p, e->name, strerror(-r));
                        }

                } else if ((e->mask & IN_ISDIR) && e->len > 0 && sd_id128_from_string(e->name, &id) >= 0) {

                        /* Event for subdirectory */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {

                                r = add_directory(j, p, e->name);
                                if (r < 0)
                                        log_debug("Failed to add directory %s/%s: %s", p, e->name, strerror(-r));
                        }
                }

                return;
        }

        if (e->mask & IN_IGNORED)
                return;

        log_warning("Unknown inotify event.");
}

_public_ int sd_journal_process(sd_journal *j) {
        uint8_t buffer[sizeof(struct inotify_event) + FILENAME_MAX];

        if (!j)
                return -EINVAL;

        for (;;) {
                struct inotify_event *e;
                ssize_t l;

                l = read(j->inotify_fd, buffer, sizeof(buffer));
                if (l < 0) {
                        if (errno == EINTR || errno == EAGAIN)
                                return 0;

                        return -errno;
                }

                e = (struct inotify_event*) buffer;
                while (l > 0) {
                        size_t step;

                        process_inotify_event(j, e);

                        step = sizeof(struct inotify_event) + e->len;
                        assert(step <= (size_t) l);

                        e = (struct inotify_event*) ((uint8_t*) e + step);
                        l -= step;
                }
        }
}

_public_ int sd_journal_query_unique(sd_journal *j, const char *field) {
        if (!j)
                return -EINVAL;
        if (!field)
                return -EINVAL;

        return -ENOTSUP;
}

_public_ int sd_journal_enumerate_unique(sd_journal *j, const void **data, size_t *l) {
        if (!j)
                return -EINVAL;
        if (!data)
                return -EINVAL;
        if (!l)
                return -EINVAL;

        return -ENOTSUP;
}

_public_ void sd_journal_restart_unique(sd_journal *j) {
        if (!j)
                return;
}
