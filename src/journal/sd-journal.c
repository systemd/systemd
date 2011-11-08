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

#include "sd-journal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "hashmap.h"
#include "list.h"
#include "lookup3.h"

typedef struct Match Match;

struct Match {
        char *data;
        size_t size;
        uint64_t le_hash;

        LIST_FIELDS(Match, matches);
};

typedef enum location_type {
        LOCATION_HEAD,
        LOCATION_TAIL,
        LOCATION_DISCRETE
} location_type_t;

typedef struct Location {
        location_type_t type;

        uint64_t seqnum;
        sd_id128_t seqnum_id;
        bool seqnum_set;

        uint64_t realtime;
        bool realtime_set;

        uint64_t monotonic;
        sd_id128_t boot_id;
        bool monotonic_set;

        uint64_t xor_hash;
        bool xor_hash_set;
} Location;

struct sd_journal {
        Hashmap *files;

        Location current_location;
        JournalFile *current_file;
        uint64_t current_field;

        LIST_HEAD(Match, matches);
        unsigned n_matches;
};

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

int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        Match *m, *after = NULL;
        uint64_t le_hash;

        assert(j);

        if (size <= 0)
                return -EINVAL;

        assert(data);

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

void sd_journal_flush_matches(sd_journal *j) {
        assert(j);

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
                                return r;
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
                                                tp = tp;
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

                n = journal_file_entry_n_items(c);

                /* Make sure we don't match the entry we are starting
                 * from. */
                found = cp > *offset;

                np = 0;
                LIST_FOREACH(matches, m, j->matches) {
                        uint64_t q, k;

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

                        r = journal_file_next_entry_for_data(f, c, cp, le64toh(c->entry.items[k].object_offset), direction, NULL, &q);
                        if (r > 0) {

                                if (direction == DIRECTION_DOWN) {
                                        if (q > np)
                                                np = q;
                                } else {
                                        if (np == 0 || q < np)
                                                np = q;
                                }
                        }
                }

                /* Check the last term */
                if (term_match && term_result)
                        found = true;

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
        }
}

static int next_beyond_location(sd_journal *j, JournalFile *f, direction_t direction, Object **ret, uint64_t *offset) {
        Object *c;
        uint64_t cp;
        int compare_value, r;

        assert(j);
        assert(f);

        if (f->current_offset > 0) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &c);
                if (r < 0)
                        return r;

                cp = f->current_offset;

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

        assert(j);

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

int sd_journal_next(sd_journal *j) {
        return real_journal_next(j, DIRECTION_DOWN);
}

int sd_journal_previous(sd_journal *j) {
        return real_journal_next(j, DIRECTION_UP);
}

int sd_journal_next_skip(sd_journal *j, uint64_t skip) {
        int c = 0, r;

        assert(j);

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

int sd_journal_previous_skip(sd_journal *j, uint64_t skip) {
        int c = 0, r;

        assert(j);

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

int sd_journal_get_cursor(sd_journal *j, char **cursor) {
        Object *o;
        int r;
        char bid[33], sid[33];

        assert(j);
        assert(cursor);

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

int sd_journal_seek_cursor(sd_journal *j, const char *cursor) {
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

        assert(j);
        assert(cursor);

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

int sd_journal_seek_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t usec) {
        assert(j);

        reset_location(j);
        j->current_location.type = LOCATION_DISCRETE;
        j->current_location.boot_id = boot_id;
        j->current_location.monotonic = usec;
        j->current_location.monotonic_set = true;

        return 0;
}

int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec) {
        assert(j);

        reset_location(j);
        j->current_location.type = LOCATION_DISCRETE;
        j->current_location.realtime = usec;
        j->current_location.realtime_set = true;

        return 0;
}

int sd_journal_seek_head(sd_journal *j) {
        assert(j);

        reset_location(j);
        j->current_location.type = LOCATION_HEAD;

        return 0;
}

int sd_journal_seek_tail(sd_journal *j) {
        assert(j);

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

        if (dir)
                fn = join(prefix, "/", dir, "/", filename, NULL);
        else
                fn = join(prefix, "/", filename, NULL);

        if (!fn)
                return -ENOMEM;

        r = journal_file_open(fn, O_RDONLY, 0, NULL, &f);
        free(fn);

        if (r < 0) {
                if (errno == ENOENT)
                        return 0;

                return r;
        }

        journal_file_dump(f);


        r = hashmap_put(j->files, f->path, f);
        if (r < 0) {
                journal_file_close(f);
                return r;
        }

        return 0;
}

static int add_directory(sd_journal *j, const char *prefix, const char *dir) {
        char *fn;
        int r;
        DIR *d;

        assert(j);
        assert(prefix);
        assert(dir);

        fn = join(prefix, "/", dir, NULL);
        if (!fn)
                return -ENOMEM;

        d = opendir(fn);
        free(fn);

        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

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

        return 0;
}

int sd_journal_open(sd_journal **ret) {
        sd_journal *j;
        const char *p;
        const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";
        int r;

        assert(ret);

        j = new0(sd_journal, 1);
        if (!j)
                return -ENOMEM;

        j->files = hashmap_new(string_hash_func, string_compare_func);
        if (!j->files) {
                r = -ENOMEM;
                goto fail;
        }

        /* We ignore most errors here, since the idea is to only open
         * what's actually accessible, and ignore the rest. */

        NULSTR_FOREACH(p, search_paths) {
                DIR *d;

                d = opendir(p);
                if (!d) {
                        if (errno != ENOENT)
                                log_debug("Failed to open %s: %m", p);
                        continue;
                }

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

void sd_journal_close(sd_journal *j) {
        assert(j);

        if (j->files) {
                JournalFile *f;

                while ((f = hashmap_steal_first(j->files)))
                        journal_file_close(f);

                hashmap_free(j->files);
        }

        sd_journal_flush_matches(j);

        free(j);
}

int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret) {
        Object *o;
        JournalFile *f;
        int r;

        assert(j);
        assert(ret);

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

int sd_journal_get_monotonic_usec(sd_journal *j, uint64_t *ret, sd_id128_t *ret_boot_id) {
        Object *o;
        JournalFile *f;
        int r;
        sd_id128_t id;

        assert(j);
        assert(ret);

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

int sd_journal_get_data(sd_journal *j, const char *field, const void **data, size_t *size) {
        JournalFile *f;
        uint64_t i, n;
        size_t field_length;
        int r;
        Object *o;

        assert(j);
        assert(field);
        assert(data);
        assert(size);

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
                le_hash = o->entry.items[j->current_field].hash;
                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                if (le_hash != o->data.hash)
                        return -EBADMSG;

                l = le64toh(o->object.size) - offsetof(Object, data.payload);

                if (l >= field_length+1 &&
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

int sd_journal_enumerate_data(sd_journal *j, const void **data, size_t *size) {
        JournalFile *f;
        uint64_t p, l, n, le_hash;
        int r;
        Object *o;
        size_t t;

        assert(j);
        assert(data);
        assert(size);

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

        *data = o->data.payload;
        *size = t;

        j->current_field ++;

        return 1;
}

void sd_journal_restart_data(sd_journal *j) {
        assert(j);

        j->current_field = 0;
}
