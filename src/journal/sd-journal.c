/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/poll.h>

#include "sd-journal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "hashmap.h"
#include "list.h"
#include "path-util.h"
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
        l->boot_id = o->entry.boot_id;
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

static int match_is_valid(const void *data, size_t size) {
        const char *b, *p;

        assert(data);

        if (size < 2)
                return false;

        if (startswith(data, "__"))
                return false;

        b = data;
        for (p = b; p < b + size; p++) {

                if (*p == '=')
                        return p > b;

                if (*p == '_')
                        continue;

                if (*p >= 'A' && *p <= 'Z')
                        continue;

                if (*p >= '0' && *p <= '9')
                        continue;

                return false;
        }

        return false;
}

static bool same_field(const void *_a, size_t s, const void *_b, size_t t) {
        const uint8_t *a = _a, *b = _b;
        size_t j;

        for (j = 0; j < s && j < t; j++) {

                if (a[j] != b[j])
                        return false;

                if (a[j] == '=')
                        return true;
        }

        return true;
}

static Match *match_new(Match *p, MatchType t) {
        Match *m;

        m = new0(Match, 1);
        if (!m)
                return NULL;

        m->type = t;

        if (p) {
                m->parent = p;
                LIST_PREPEND(Match, matches, p->matches, m);
        }

        return m;
}

static void match_free(Match *m) {
        assert(m);

        while (m->matches)
                match_free(m->matches);

        if (m->parent)
                LIST_REMOVE(Match, matches, m->parent->matches, m);

        free(m->data);
        free(m);
}

static void match_free_if_empty(Match *m) {
        assert(m);

        if (m->matches)
                return;

        match_free(m);
}

_public_ int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        Match *l2, *l3, *add_here = NULL, *m;
        le64_t le_hash;

        if (!j)
                return -EINVAL;

        if (!data)
                return -EINVAL;

        if (size == 0)
                size = strlen(data);

        if (!match_is_valid(data, size))
                return -EINVAL;

        /* level 0: OR term
         * level 1: AND terms
         * level 2: OR terms
         * level 3: concrete matches */

        if (!j->level0) {
                j->level0 = match_new(NULL, MATCH_OR_TERM);
                if (!j->level0)
                        return -ENOMEM;
        }

        if (!j->level1) {
                j->level1 = match_new(j->level0, MATCH_AND_TERM);
                if (!j->level1)
                        return -ENOMEM;
        }

        assert(j->level0->type == MATCH_OR_TERM);
        assert(j->level1->type == MATCH_AND_TERM);

        le_hash = htole64(hash64(data, size));

        LIST_FOREACH(matches, l2, j->level1->matches) {
                assert(l2->type == MATCH_OR_TERM);

                LIST_FOREACH(matches, l3, l2->matches) {
                        assert(l3->type == MATCH_DISCRETE);

                        /* Exactly the same match already? Then ignore
                         * this addition */
                        if (l3->le_hash == le_hash &&
                            l3->size == size &&
                            memcmp(l3->data, data, size) == 0)
                                return 0;

                        /* Same field? Then let's add this to this OR term */
                        if (same_field(data, size, l3->data, l3->size)) {
                                add_here = l2;
                                break;
                        }
                }

                if (add_here)
                        break;
        }

        if (!add_here) {
                add_here = match_new(j->level1, MATCH_OR_TERM);
                if (!add_here)
                        goto fail;
        }

        m = match_new(add_here, MATCH_DISCRETE);
        if (!m)
                goto fail;

        m->le_hash = le_hash;
        m->size = size;
        m->data = memdup(data, size);
        if (!m->data)
                goto fail;

        detach_location(j);

        return 0;

fail:
        if (add_here)
                match_free_if_empty(add_here);

        if (j->level1)
                match_free_if_empty(j->level1);

        if (j->level0)
                match_free_if_empty(j->level0);

        return -ENOMEM;
}

_public_ int sd_journal_add_disjunction(sd_journal *j) {
        Match *m;

        assert(j);

        if (!j->level0)
                return 0;

        if (!j->level1)
                return 0;

        if (!j->level1->matches)
                return 0;

        m = match_new(j->level0, MATCH_AND_TERM);
        if (!m)
                return -ENOMEM;

        j->level1 = m;
        return 0;
}

static char *match_make_string(Match *m) {
        char *p, *r;
        Match *i;
        bool enclose = false;

        if (!m)
                return strdup("");

        if (m->type == MATCH_DISCRETE)
                return strndup(m->data, m->size);

        p = NULL;
        LIST_FOREACH(matches, i, m->matches) {
                char *t, *k;

                t = match_make_string(i);
                if (!t) {
                        free(p);
                        return NULL;
                }

                if (p) {
                        k = strjoin(p, m->type == MATCH_OR_TERM ? " OR " : " AND ", t, NULL);
                        free(p);
                        free(t);

                        if (!k)
                                return NULL;

                        p = k;

                        enclose = true;
                } else {
                        free(p);
                        p = t;
                }
        }

        if (enclose) {
                r = strjoin("(", p, ")", NULL);
                free(p);
                return r;
        }

        return p;
}

char *journal_make_match_string(sd_journal *j) {
        assert(j);

        return match_make_string(j->level0);
}

_public_ void sd_journal_flush_matches(sd_journal *j) {

        if (!j)
                return;

        if (j->level0)
                match_free(j->level0);

        j->level0 = j->level1 = NULL;

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
        b = le64toh(bo->entry.realtime);

        if (a < b)
                return -1;
        if (a > b)
                return 1;

        /* Finally, compare by contents */
        a = le64toh(ao->entry.xor_hash);
        b = le64toh(bo->entry.xor_hash);

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

static int next_for_match(
                sd_journal *j,
                Match *m,
                JournalFile *f,
                uint64_t after_offset,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        int r;
        uint64_t np = 0;
        Object *n;

        assert(j);
        assert(m);
        assert(f);

        if (m->type == MATCH_DISCRETE) {
                uint64_t dp;

                r = journal_file_find_data_object_with_hash(f, m->data, m->size, le64toh(m->le_hash), NULL, &dp);
                if (r <= 0)
                        return r;

                return journal_file_move_to_entry_by_offset_for_data(f, dp, after_offset, direction, ret, offset);

        } else if (m->type == MATCH_OR_TERM) {
                Match *i;

                /* Find the earliest match beyond after_offset */

                LIST_FOREACH(matches, i, m->matches) {
                        uint64_t cp;

                        r = next_for_match(j, i, f, after_offset, direction, NULL, &cp);
                        if (r < 0)
                                return r;
                        else if (r > 0) {
                                if (np == 0 || (direction == DIRECTION_DOWN ? np > cp : np < cp))
                                        np = cp;
                        }
                }

        } else if (m->type == MATCH_AND_TERM) {
                Match *i;
                bool continue_looking;

                /* Always jump to the next matching entry and repeat
                 * this until we fine and offset that matches for all
                 * matches. */

                if (!m->matches)
                        return 0;

                np = 0;
                do {
                        continue_looking = false;

                        LIST_FOREACH(matches, i, m->matches) {
                                uint64_t cp, limit;

                                if (np == 0)
                                        limit = after_offset;
                                else if (direction == DIRECTION_DOWN)
                                        limit = MAX(np, after_offset);
                                else
                                        limit = MIN(np, after_offset);

                                r = next_for_match(j, i, f, limit, direction, NULL, &cp);
                                if (r <= 0)
                                        return r;

                                if ((direction == DIRECTION_DOWN ? cp >= after_offset : cp <= after_offset) &&
                                    (np == 0 || (direction == DIRECTION_DOWN ? cp > np : np < cp))) {
                                        np = cp;
                                        continue_looking = true;
                                }
                        }

                } while (continue_looking);
        }

        if (np == 0)
                return 0;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, np, &n);
        if (r < 0)
                return r;

        if (ret)
                *ret = n;
        if (offset)
                *offset = np;

        return 1;
}

static int find_location_for_match(
                sd_journal *j,
                Match *m,
                JournalFile *f,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        int r;

        assert(j);
        assert(m);
        assert(f);

        if (m->type == MATCH_DISCRETE) {
                uint64_t dp;

                r = journal_file_find_data_object_with_hash(f, m->data, m->size, le64toh(m->le_hash), NULL, &dp);
                if (r <= 0)
                        return r;

                /* FIXME: missing: find by monotonic */

                if (j->current_location.type == LOCATION_HEAD)
                        return journal_file_next_entry_for_data(f, NULL, 0, dp, DIRECTION_DOWN, ret, offset);
                if (j->current_location.type == LOCATION_TAIL)
                        return journal_file_next_entry_for_data(f, NULL, 0, dp, DIRECTION_UP, ret, offset);
                if (j->current_location.seqnum_set && sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        return journal_file_move_to_entry_by_seqnum_for_data(f, dp, j->current_location.seqnum, direction, ret, offset);
                if (j->current_location.monotonic_set) {
                        r = journal_file_move_to_entry_by_monotonic_for_data(f, dp, j->current_location.boot_id, j->current_location.monotonic, direction, ret, offset);
                        if (r != -ENOENT)
                                return r;
                }
                if (j->current_location.realtime_set)
                        return journal_file_move_to_entry_by_realtime_for_data(f, dp, j->current_location.realtime, direction, ret, offset);

                return journal_file_next_entry_for_data(f, NULL, 0, dp, direction, ret, offset);

        } else if (m->type == MATCH_OR_TERM) {
                uint64_t np = 0;
                Object *n;
                Match *i;

                /* Find the earliest match */

                LIST_FOREACH(matches, i, m->matches) {
                        uint64_t cp;

                        r = find_location_for_match(j, i, f, direction, NULL, &cp);
                        if (r < 0)
                                return r;
                        else if (r > 0) {
                                if (np == 0 || (direction == DIRECTION_DOWN ? np > cp : np < cp))
                                        np = cp;
                        }
                }

                if (np == 0)
                        return 0;

                r = journal_file_move_to_object(f, OBJECT_ENTRY, np, &n);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = n;
                if (offset)
                        *offset = np;

                return 1;

        } else {
                Match *i;
                uint64_t np = 0;

                assert(m->type == MATCH_AND_TERM);

                /* First jump to the last match, and then find the
                 * next one where all matches match */

                if (!m->matches)
                        return 0;

                LIST_FOREACH(matches, i, m->matches) {
                        uint64_t cp;

                        r = find_location_for_match(j, i, f, direction, NULL, &cp);
                        if (r <= 0)
                                return r;

                        if (np == 0 || (direction == DIRECTION_DOWN ? np < cp : np > cp))
                                np = cp;
                }

                return next_for_match(j, m, f, np, direction, ret, offset);
        }
}

static int find_location_with_matches(
                sd_journal *j,
                JournalFile *f,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        int r;

        assert(j);
        assert(f);
        assert(ret);
        assert(offset);

        if (!j->level0) {
                /* No matches is simple */

                if (j->current_location.type == LOCATION_HEAD)
                        return journal_file_next_entry(f, NULL, 0, DIRECTION_DOWN, ret, offset);
                if (j->current_location.type == LOCATION_TAIL)
                        return journal_file_next_entry(f, NULL, 0, DIRECTION_UP, ret, offset);
                if (j->current_location.seqnum_set && sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        return journal_file_move_to_entry_by_seqnum(f, j->current_location.seqnum, direction, ret, offset);
                if (j->current_location.monotonic_set) {
                        r = journal_file_move_to_entry_by_monotonic(f, j->current_location.boot_id, j->current_location.monotonic, direction, ret, offset);
                        if (r != -ENOENT)
                                return r;
                }
                if (j->current_location.realtime_set)
                        return journal_file_move_to_entry_by_realtime(f, j->current_location.realtime, direction, ret, offset);

                return journal_file_next_entry(f, NULL, 0, direction, ret, offset);
        } else
                return find_location_for_match(j, j->level0, f, direction, ret, offset);
}

static int next_with_matches(
                sd_journal *j,
                JournalFile *f,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        Object *c;
        uint64_t cp;

        assert(j);
        assert(f);
        assert(ret);
        assert(offset);

        c = *ret;
        cp = *offset;

        /* No matches is easy. We simple advance the file
         * pointer by one. */
        if (!j->level0)
                return journal_file_next_entry(f, c, cp, direction, ret, offset);

        /* If we have a match then we look for the next matching entry
         * with an offset at least one step larger */
        return next_for_match(j, j->level0, f, direction == DIRECTION_DOWN ? cp+1 : cp-1, direction, ret, offset);
}

static int next_beyond_location(sd_journal *j, JournalFile *f, direction_t direction, Object **ret, uint64_t *offset) {
        Object *c;
        uint64_t cp;
        int r;

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
        } else {
                r = find_location_with_matches(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;
        }

        /* OK, we found the spot, now let's advance until to an entry
         * that is actually different from what we were previously
         * looking at. This is necessary to handle entries which exist
         * in two (or more) journal files, and which shall all be
         * suppressed but one. */

        for (;;) {
                bool found;

                if (j->current_location.type == LOCATION_DISCRETE) {
                        int k;

                        k = compare_with_location(f, c, &j->current_location);
                        if (direction == DIRECTION_DOWN)
                                found = k > 0;
                        else
                                found = k < 0;
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
                if (r < 0) {
                        log_debug("Can't iterate through %s, ignoring: %s", f->path, strerror(-r));
                        continue;
                } else if (r == 0)
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

static int real_journal_next_skip(sd_journal *j, direction_t direction, uint64_t skip) {
        int c = 0, r;

        if (!j)
                return -EINVAL;

        if (skip == 0) {
                /* If this is not a discrete skip, then at least
                 * resolve the current location */
                if (j->current_location.type != LOCATION_DISCRETE)
                        return real_journal_next(j, direction);

                return 0;
        }

        do {
                r = real_journal_next(j, direction);
                if (r < 0)
                        return r;

                if (r == 0)
                        return c;

                skip--;
                c++;
        } while (skip > 0);

        return c;
}

_public_ int sd_journal_next_skip(sd_journal *j, uint64_t skip) {
        return real_journal_next_skip(j, DIRECTION_DOWN, skip);
}

_public_ int sd_journal_previous_skip(sd_journal *j, uint64_t skip) {
        return real_journal_next_skip(j, DIRECTION_UP, skip);
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
                     path_get_file_name(j->current_file->path)) < 0)
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

static int add_file(sd_journal *j, const char *prefix, const char *filename) {
        char *path;
        int r;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        if ((j->flags & SD_JOURNAL_SYSTEM_ONLY) &&
            !(streq(filename, "system.journal") ||
             (startswith(filename, "system@") && endswith(filename, ".journal"))))
                return 0;

        path = strjoin(prefix, "/", filename, NULL);
        if (!path)
                return -ENOMEM;

        if (hashmap_get(j->files, path)) {
                free(path);
                return 0;
        }

        if (hashmap_size(j->files) >= JOURNAL_FILES_MAX) {
                log_debug("Too many open journal files, not adding %s, ignoring.", path);
                free(path);
                return 0;
        }

        r = journal_file_open(path, O_RDONLY, 0, NULL, NULL, &f);
        free(path);

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

        j->current_invalidate_counter ++;

        log_debug("File %s got added.", f->path);

        return 0;
}

static int remove_file(sd_journal *j, const char *prefix, const char *filename) {
        char *path;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        path = strjoin(prefix, "/", filename, NULL);
        if (!path)
                return -ENOMEM;

        f = hashmap_get(j->files, path);
        free(path);
        if (!f)
                return 0;

        hashmap_remove(j->files, f->path);
        journal_file_close(f);

        j->current_invalidate_counter ++;

        log_debug("File %s got removed.", f->path);
        return 0;
}

static int add_directory(sd_journal *j, const char *prefix, const char *dirname) {
        char *path;
        int r;
        DIR *d;
        sd_id128_t id, mid;
        Directory *m;

        assert(j);
        assert(prefix);
        assert(dirname);

        if ((j->flags & SD_JOURNAL_LOCAL_ONLY) &&
            (sd_id128_from_string(dirname, &id) < 0 ||
             sd_id128_get_machine(&mid) < 0 ||
             !sd_id128_equal(id, mid)))
            return 0;

        path = strjoin(prefix, "/", dirname, NULL);
        if (!path)
                return -ENOMEM;

        d = opendir(path);
        if (!d) {
                log_debug("Failed to open %s: %m", path);
                free(path);

                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        m = hashmap_get(j->directories_by_path, path);
        if (!m) {
                m = new0(Directory, 1);
                if (!m) {
                        closedir(d);
                        free(path);
                        return -ENOMEM;
                }

                m->is_root = false;
                m->path = path;

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        closedir(d);
                        free(m->path);
                        free(m);
                        return -ENOMEM;
                }

                j->current_invalidate_counter ++;

                log_debug("Directory %s got added.", m->path);

        } else if (m->is_root) {
                free (path);
                closedir(d);
                return 0;
        }  else
                free(path);

        if (m->wd <= 0 && j->inotify_fd >= 0) {

                m->wd = inotify_add_watch(j->inotify_fd, m->path,
                                          IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                                          IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT|
                                          IN_DONT_FOLLOW|IN_ONLYDIR);

                if (m->wd > 0 && hashmap_put(j->directories_by_wd, INT_TO_PTR(m->wd), m) < 0)
                        inotify_rm_watch(j->inotify_fd, m->wd);
        }

        for (;;) {
                struct dirent buf, *de;

                r = readdir_r(d, &buf, &de);
                if (r != 0 || !de)
                        break;

                if (dirent_is_file_with_suffix(de, ".journal")) {
                        r = add_file(j, m->path, de->d_name);
                        if (r < 0)
                                log_debug("Failed to add file %s/%s: %s", m->path, de->d_name, strerror(-r));
                }
        }

        closedir(d);

        return 0;
}

static int add_root_directory(sd_journal *j, const char *p) {
        DIR *d;
        Directory *m;
        int r;

        assert(j);
        assert(p);

        if ((j->flags & SD_JOURNAL_RUNTIME_ONLY) &&
            !path_startswith(p, "/run"))
                return -EINVAL;

        d = opendir(p);
        if (!d)
                return -errno;

        m = hashmap_get(j->directories_by_path, p);
        if (!m) {
                m = new0(Directory, 1);
                if (!m) {
                        closedir(d);
                        return -ENOMEM;
                }

                m->is_root = true;
                m->path = strdup(p);
                if (!m->path) {
                        closedir(d);
                        free(m);
                        return -ENOMEM;
                }

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        closedir(d);
                        free(m->path);
                        free(m);
                        return -ENOMEM;
                }

                j->current_invalidate_counter ++;

                log_debug("Root directory %s got added.", m->path);

        } else if (!m->is_root) {
                closedir(d);
                return 0;
        }

        if (m->wd <= 0 && j->inotify_fd >= 0) {

                m->wd = inotify_add_watch(j->inotify_fd, m->path,
                                          IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                                          IN_DONT_FOLLOW|IN_ONLYDIR);

                if (m->wd > 0 && hashmap_put(j->directories_by_wd, INT_TO_PTR(m->wd), m) < 0)
                        inotify_rm_watch(j->inotify_fd, m->wd);
        }

        for (;;) {
                struct dirent buf, *de;
                sd_id128_t id;

                r = readdir_r(d, &buf, &de);
                if (r != 0 || !de)
                        break;

                if (dirent_is_file_with_suffix(de, ".journal")) {
                        r = add_file(j, m->path, de->d_name);
                        if (r < 0)
                                log_debug("Failed to add file %s/%s: %s", m->path, de->d_name, strerror(-r));

                } else if ((de->d_type == DT_DIR || de->d_type == DT_LNK || de->d_type == DT_UNKNOWN) &&
                           sd_id128_from_string(de->d_name, &id) >= 0) {

                        r = add_directory(j, m->path, de->d_name);
                        if (r < 0)
                                log_debug("Failed to add directory %s/%s: %s", m->path, de->d_name, strerror(-r));
                }
        }

        closedir(d);

        return 0;
}

static int remove_directory(sd_journal *j, Directory *d) {
        assert(j);

        if (d->wd > 0) {
                hashmap_remove(j->directories_by_wd, INT_TO_PTR(d->wd));

                if (j->inotify_fd >= 0)
                        inotify_rm_watch(j->inotify_fd, d->wd);
        }

        hashmap_remove(j->directories_by_path, d->path);

        if (d->is_root)
                log_debug("Root directory %s got removed.", d->path);
        else
                log_debug("Directory %s got removed.", d->path);

        free(d->path);
        free(d);

        return 0;
}

static int add_search_paths(sd_journal *j) {

        const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";
        const char *p;

        assert(j);

        /* We ignore most errors here, since the idea is to only open
         * what's actually accessible, and ignore the rest. */

        NULSTR_FOREACH(p, search_paths)
                add_root_directory(j, p);

        return 0;
}

static int allocate_inotify(sd_journal *j) {
        assert(j);

        if (j->inotify_fd < 0) {
                j->inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
                if (j->inotify_fd < 0)
                        return -errno;
        }

        if (!j->directories_by_wd) {
                j->directories_by_wd = hashmap_new(trivial_hash_func, trivial_compare_func);
                if (!j->directories_by_wd)
                        return -ENOMEM;
        }

        return 0;
}

static sd_journal *journal_new(int flags) {
        sd_journal *j;

        j = new0(sd_journal, 1);
        if (!j)
                return NULL;

        j->inotify_fd = -1;
        j->flags = flags;

        j->files = hashmap_new(string_hash_func, string_compare_func);
        if (!j->files) {
                free(j);
                return NULL;
        }

        j->directories_by_path = hashmap_new(string_hash_func, string_compare_func);
        if (!j->directories_by_path) {
                hashmap_free(j->files);
                free(j);
                return NULL;
        }

        return j;
}

_public_ int sd_journal_open(sd_journal **ret, int flags) {
        sd_journal *j;
        int r;

        if (!ret)
                return -EINVAL;

        if (flags & ~(SD_JOURNAL_LOCAL_ONLY|
                      SD_JOURNAL_RUNTIME_ONLY|
                      SD_JOURNAL_SYSTEM_ONLY))
                return -EINVAL;

        j = journal_new(flags);
        if (!j)
                return -ENOMEM;

        r = add_search_paths(j);
        if (r < 0)
                goto fail;

        *ret = j;
        return 0;

fail:
        sd_journal_close(j);

        return r;
}

_public_ int sd_journal_open_directory(sd_journal **ret, const char *path, int flags) {
        sd_journal *j;
        int r;

        if (!ret)
                return -EINVAL;

        if (!path || !path_is_absolute(path))
                return -EINVAL;

        if (flags != 0)
                return -EINVAL;

        j = journal_new(flags);
        if (!j)
                return -ENOMEM;

        r = add_root_directory(j, path);
        if (r < 0)
                goto fail;

        *ret = j;
        return 0;

fail:
        sd_journal_close(j);

        return r;
}

_public_ void sd_journal_close(sd_journal *j) {
        Directory *d;
        JournalFile *f;

        if (!j)
                return;

        while ((f = hashmap_steal_first(j->files)))
                journal_file_close(f);

        hashmap_free(j->files);

        while ((d = hashmap_first(j->directories_by_path)))
                remove_directory(j, d);

        while ((d = hashmap_first(j->directories_by_wd)))
                remove_directory(j, d);

        hashmap_free(j->directories_by_path);
        hashmap_free(j->directories_by_wd);

        if (j->inotify_fd >= 0)
                close_nointr_nofail(j->inotify_fd);

        sd_journal_flush_matches(j);

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
                        return -ESTALE;
        }

        if (ret)
                *ret = le64toh(o->entry.monotonic);

        return 0;
}

static bool field_is_valid(const char *field) {
        const char *p;

        assert(field);

        if (isempty(field))
                return false;

        if (startswith(field, "__"))
                return false;

        for (p = field; *p; p++) {

                if (*p == '_')
                        continue;

                if (*p >= 'A' && *p <= 'Z')
                        continue;

                if (*p >= '0' && *p <= '9')
                        continue;

                return false;
        }

        return true;
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

        if (!field_is_valid(field))
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
                uint64_t p, l;
                le64_t le_hash;
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
        uint64_t p, l, n;
        le64_t le_hash;
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
        int r;

        if (!j)
                return -EINVAL;

        if (j->inotify_fd >= 0)
                return j->inotify_fd;

        r = allocate_inotify(j);
        if (r < 0)
                return r;

        /* Iterate through all dirs again, to add them to the
         * inotify */
        r = add_search_paths(j);
        if (r < 0)
                return r;

        return j->inotify_fd;
}

static void process_inotify_event(sd_journal *j, struct inotify_event *e) {
        Directory *d;
        int r;

        assert(j);
        assert(e);

        /* Is this a subdirectory we watch? */
        d = hashmap_get(j->directories_by_wd, INT_TO_PTR(e->wd));
        if (d) {
                sd_id128_t id;

                if (!(e->mask & IN_ISDIR) && e->len > 0 && endswith(e->name, ".journal")) {

                        /* Event for a journal file */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_file(j, d->path, e->name);
                                if (r < 0)
                                        log_debug("Failed to add file %s/%s: %s", d->path, e->name, strerror(-r));

                        } else if (e->mask & (IN_DELETE|IN_UNMOUNT)) {

                                r = remove_file(j, d->path, e->name);
                                if (r < 0)
                                        log_debug("Failed to remove file %s/%s: %s", d->path, e->name, strerror(-r));
                        }

                } else if (!d->is_root && e->len == 0) {

                        /* Event for a subdirectory */

                        if (e->mask & (IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT)) {
                                r = remove_directory(j, d);
                                if (r < 0)
                                        log_debug("Failed to remove directory %s: %s", d->path, strerror(-r));
                        }


                } else if (d->is_root && (e->mask & IN_ISDIR) && e->len > 0 && sd_id128_from_string(e->name, &id) >= 0) {

                        /* Event for root directory */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_directory(j, d->path, e->name);
                                if (r < 0)
                                        log_debug("Failed to add directory %s/%s: %s", d->path, e->name, strerror(-r));
                        }
                }

                return;
        }

        if (e->mask & IN_IGNORED)
                return;

        log_warning("Unknown inotify event.");
}

static int determine_change(sd_journal *j) {
        bool b;

        assert(j);

        b = j->current_invalidate_counter != j->last_invalidate_counter;
        j->last_invalidate_counter = j->current_invalidate_counter;

        return b ? SD_JOURNAL_INVALIDATE : SD_JOURNAL_APPEND;
}

_public_ int sd_journal_process(sd_journal *j) {
        uint8_t buffer[sizeof(struct inotify_event) + FILENAME_MAX] _alignas_(struct inotify_event);
        bool got_something = false;

        if (!j)
                return -EINVAL;

        for (;;) {
                struct inotify_event *e;
                ssize_t l;

                l = read(j->inotify_fd, buffer, sizeof(buffer));
                if (l < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                return got_something ? determine_change(j) : SD_JOURNAL_NOP;

                        return -errno;
                }

                got_something = true;

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

        return determine_change(j);
}

_public_ int sd_journal_wait(sd_journal *j, uint64_t timeout_usec) {
        int r;

        assert(j);

        if (j->inotify_fd < 0) {

                /* This is the first invocation, hence create the
                 * inotify watch */
                r = sd_journal_get_fd(j);
                if (r < 0)
                        return r;

                /* The journal might have changed since the context
                 * object was created and we weren't watching before,
                 * hence don't wait for anything, and return
                 * immediately. */
                return determine_change(j);
        }

        do {
                r = fd_wait_for_event(j->inotify_fd, POLLIN, timeout_usec);
        } while (r == -EINTR);

        if (r < 0)
                return r;

        return sd_journal_process(j);
}

_public_ int sd_journal_get_cutoff_realtime_usec(sd_journal *j, uint64_t *from, uint64_t *to) {
        Iterator i;
        JournalFile *f;
        bool first = true;
        int r;

        if (!j)
                return -EINVAL;
        if (!from && !to)
                return -EINVAL;

        HASHMAP_FOREACH(f, j->files, i) {
                usec_t fr, t;

                r = journal_file_get_cutoff_realtime_usec(f, &fr, &t);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (first) {
                        if (from)
                                *from = fr;
                        if (to)
                                *to = t;
                        first = false;
                } else {
                        if (from)
                                *from = MIN(fr, *from);
                        if (to)
                                *to = MIN(t, *to);
                }
        }

        return first ? 0 : 1;
}

_public_ int sd_journal_get_cutoff_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t *from, uint64_t *to) {
        Iterator i;
        JournalFile *f;
        bool first = true;
        int r;

        if (!j)
                return -EINVAL;
        if (!from && !to)
                return -EINVAL;

        HASHMAP_FOREACH(f, j->files, i) {
                usec_t fr, t;

                r = journal_file_get_cutoff_monotonic_usec(f, boot_id, &fr, &t);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (first) {
                        if (from)
                                *from = fr;
                        if (to)
                                *to = t;
                        first = false;
                } else {
                        if (from)
                                *from = MIN(fr, *from);
                        if (to)
                                *to = MIN(t, *to);
                }
        }

        return first ? 0 : 1;
}

void journal_print_header(sd_journal *j) {
        Iterator i;
        JournalFile *f;
        bool newline = false;

        assert(j);

        HASHMAP_FOREACH(f, j->files, i) {
                if (newline)
                        putchar('\n');
                else
                        newline = true;

                journal_file_print_header(f);
        }
}

/* _public_ int sd_journal_query_unique(sd_journal *j, const char *field) { */
/*         if (!j) */
/*                 return -EINVAL; */
/*         if (!field) */
/*                 return -EINVAL; */

/*         return -ENOTSUP; */
/* } */

/* _public_ int sd_journal_enumerate_unique(sd_journal *j, const void **data, size_t *l) { */
/*         if (!j) */
/*                 return -EINVAL; */
/*         if (!data) */
/*                 return -EINVAL; */
/*         if (!l) */
/*                 return -EINVAL; */

/*         return -ENOTSUP; */
/* } */

/* _public_ void sd_journal_restart_unique(sd_journal *j) { */
/*         if (!j) */
/*                 return; */
/* } */
