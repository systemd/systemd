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
#include <poll.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "sd-journal.h"
#include "journal-def.h"
#include "journal-file.h"
#include "hashmap.h"
#include "list.h"
#include "strv.h"
#include "path-util.h"
#include "lookup3.h"
#include "compress.h"
#include "journal-internal.h"
#include "missing.h"
#include "catalog.h"
#include "replace-var.h"
#include "fileio.h"
#include "formats-util.h"

#define JOURNAL_FILES_MAX 7168

#define JOURNAL_FILES_RECHECK_USEC (2 * USEC_PER_SEC)

#define REPLACE_VAR_MAX 256

#define DEFAULT_DATA_THRESHOLD (64*1024)

static void remove_file_real(sd_journal *j, JournalFile *f);

static bool journal_pid_changed(sd_journal *j) {
        assert(j);

        /* We don't support people creating a journal object and
         * keeping it around over a fork(). Let's complain. */

        return j->original_pid != getpid();
}

/* We return an error here only if we didn't manage to
   memorize the real error. */
static int set_put_error(sd_journal *j, int r) {
        int k;

        if (r >= 0)
                return r;

        k = set_ensure_allocated(&j->errors, NULL);
        if (k < 0)
                return k;

        return set_put(j->errors, INT_TO_PTR(r));
}

static void detach_location(sd_journal *j) {
        Iterator i;
        JournalFile *f;

        assert(j);

        j->current_file = NULL;
        j->current_field = 0;

        ORDERED_HASHMAP_FOREACH(f, j->files, i)
                journal_file_reset_location(f);
}

static void reset_location(sd_journal *j) {
        assert(j);

        detach_location(j);
        zero(j->current_location);
}

static void init_location(Location *l, LocationType type, JournalFile *f, Object *o) {
        assert(l);
        assert(type == LOCATION_DISCRETE || type == LOCATION_SEEK);
        assert(f);
        assert(o->object.type == OBJECT_ENTRY);

        l->type = type;
        l->seqnum = le64toh(o->entry.seqnum);
        l->seqnum_id = f->header->seqnum_id;
        l->realtime = le64toh(o->entry.realtime);
        l->monotonic = le64toh(o->entry.monotonic);
        l->boot_id = o->entry.boot_id;
        l->xor_hash = le64toh(o->entry.xor_hash);

        l->seqnum_set = l->realtime_set = l->monotonic_set = l->xor_hash_set = true;
}

static void set_location(sd_journal *j, JournalFile *f, Object *o) {
        assert(j);
        assert(f);
        assert(o);

        init_location(&j->current_location, LOCATION_DISCRETE, f, o);

        j->current_file = f;
        j->current_field = 0;

        /* Let f know its candidate entry was picked. */
        assert(f->location_type == LOCATION_SEEK);
        f->location_type = LOCATION_DISCRETE;
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

        assert_not_reached("\"=\" not found");
}

static Match *match_new(Match *p, MatchType t) {
        Match *m;

        m = new0(Match, 1);
        if (!m)
                return NULL;

        m->type = t;

        if (p) {
                m->parent = p;
                LIST_PREPEND(matches, p->matches, m);
        }

        return m;
}

static void match_free(Match *m) {
        assert(m);

        while (m->matches)
                match_free(m->matches);

        if (m->parent)
                LIST_REMOVE(matches, m->parent->matches, m);

        free(m->data);
        free(m);
}

static void match_free_if_empty(Match *m) {
        if (!m || m->matches)
                return;

        match_free(m);
}

_public_ int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        Match *l3, *l4, *add_here = NULL, *m;
        le64_t le_hash;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(data, -EINVAL);

        if (size == 0)
                size = strlen(data);

        assert_return(match_is_valid(data, size), -EINVAL);

        /* level 0: AND term
         * level 1: OR terms
         * level 2: AND terms
         * level 3: OR terms
         * level 4: concrete matches */

        if (!j->level0) {
                j->level0 = match_new(NULL, MATCH_AND_TERM);
                if (!j->level0)
                        return -ENOMEM;
        }

        if (!j->level1) {
                j->level1 = match_new(j->level0, MATCH_OR_TERM);
                if (!j->level1)
                        return -ENOMEM;
        }

        if (!j->level2) {
                j->level2 = match_new(j->level1, MATCH_AND_TERM);
                if (!j->level2)
                        return -ENOMEM;
        }

        assert(j->level0->type == MATCH_AND_TERM);
        assert(j->level1->type == MATCH_OR_TERM);
        assert(j->level2->type == MATCH_AND_TERM);

        le_hash = htole64(hash64(data, size));

        LIST_FOREACH(matches, l3, j->level2->matches) {
                assert(l3->type == MATCH_OR_TERM);

                LIST_FOREACH(matches, l4, l3->matches) {
                        assert(l4->type == MATCH_DISCRETE);

                        /* Exactly the same match already? Then ignore
                         * this addition */
                        if (l4->le_hash == le_hash &&
                            l4->size == size &&
                            memcmp(l4->data, data, size) == 0)
                                return 0;

                        /* Same field? Then let's add this to this OR term */
                        if (same_field(data, size, l4->data, l4->size)) {
                                add_here = l3;
                                break;
                        }
                }

                if (add_here)
                        break;
        }

        if (!add_here) {
                add_here = match_new(j->level2, MATCH_OR_TERM);
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
        match_free_if_empty(add_here);
        match_free_if_empty(j->level2);
        match_free_if_empty(j->level1);
        match_free_if_empty(j->level0);

        return -ENOMEM;
}

_public_ int sd_journal_add_conjunction(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        if (!j->level0)
                return 0;

        if (!j->level1)
                return 0;

        if (!j->level1->matches)
                return 0;

        j->level1 = NULL;
        j->level2 = NULL;

        return 0;
}

_public_ int sd_journal_add_disjunction(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        if (!j->level0)
                return 0;

        if (!j->level1)
                return 0;

        if (!j->level2)
                return 0;

        if (!j->level2->matches)
                return 0;

        j->level2 = NULL;
        return 0;
}

static char *match_make_string(Match *m) {
        char *p, *r;
        Match *i;
        bool enclose = false;

        if (!m)
                return strdup("none");

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
                } else
                        p = t;
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

        j->level0 = j->level1 = j->level2 = NULL;

        detach_location(j);
}

_pure_ static int compare_with_location(JournalFile *f, Location *l) {
        assert(f);
        assert(l);
        assert(f->location_type == LOCATION_SEEK);
        assert(l->type == LOCATION_DISCRETE || l->type == LOCATION_SEEK);

        if (l->monotonic_set &&
            sd_id128_equal(f->current_boot_id, l->boot_id) &&
            l->realtime_set &&
            f->current_realtime == l->realtime &&
            l->xor_hash_set &&
            f->current_xor_hash == l->xor_hash)
                return 0;

        if (l->seqnum_set &&
            sd_id128_equal(f->header->seqnum_id, l->seqnum_id)) {

                if (f->current_seqnum < l->seqnum)
                        return -1;
                if (f->current_seqnum > l->seqnum)
                        return 1;
        }

        if (l->monotonic_set &&
            sd_id128_equal(f->current_boot_id, l->boot_id)) {

                if (f->current_monotonic < l->monotonic)
                        return -1;
                if (f->current_monotonic > l->monotonic)
                        return 1;
        }

        if (l->realtime_set) {

                if (f->current_realtime < l->realtime)
                        return -1;
                if (f->current_realtime > l->realtime)
                        return 1;
        }

        if (l->xor_hash_set) {

                if (f->current_xor_hash < l->xor_hash)
                        return -1;
                if (f->current_xor_hash > l->xor_hash)
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
                                if (np == 0 || (direction == DIRECTION_DOWN ? cp < np : cp > np))
                                        np = cp;
                        }
                }

                if (np == 0)
                        return 0;

        } else if (m->type == MATCH_AND_TERM) {
                Match *i, *last_moved;

                /* Always jump to the next matching entry and repeat
                 * this until we find an offset that matches for all
                 * matches. */

                if (!m->matches)
                        return 0;

                r = next_for_match(j, m->matches, f, after_offset, direction, NULL, &np);
                if (r <= 0)
                        return r;

                assert(direction == DIRECTION_DOWN ? np >= after_offset : np <= after_offset);
                last_moved = m->matches;

                LIST_LOOP_BUT_ONE(matches, i, m->matches, last_moved) {
                        uint64_t cp;

                        r = next_for_match(j, i, f, np, direction, NULL, &cp);
                        if (r <= 0)
                                return r;

                        assert(direction == DIRECTION_DOWN ? cp >= np : cp <= np);
                        if (direction == DIRECTION_DOWN ? cp > np : cp < np) {
                                np = cp;
                                last_moved = i;
                        }
                }
        }

        assert(np > 0);

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

                        if (np == 0 || (direction == DIRECTION_DOWN ? cp > np : cp < np))
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
                        return journal_file_next_entry(f, 0, DIRECTION_DOWN, ret, offset);
                if (j->current_location.type == LOCATION_TAIL)
                        return journal_file_next_entry(f, 0, DIRECTION_UP, ret, offset);
                if (j->current_location.seqnum_set && sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        return journal_file_move_to_entry_by_seqnum(f, j->current_location.seqnum, direction, ret, offset);
                if (j->current_location.monotonic_set) {
                        r = journal_file_move_to_entry_by_monotonic(f, j->current_location.boot_id, j->current_location.monotonic, direction, ret, offset);
                        if (r != -ENOENT)
                                return r;
                }
                if (j->current_location.realtime_set)
                        return journal_file_move_to_entry_by_realtime(f, j->current_location.realtime, direction, ret, offset);

                return journal_file_next_entry(f, 0, direction, ret, offset);
        } else
                return find_location_for_match(j, j->level0, f, direction, ret, offset);
}

static int next_with_matches(
                sd_journal *j,
                JournalFile *f,
                direction_t direction,
                Object **ret,
                uint64_t *offset) {

        assert(j);
        assert(f);
        assert(ret);
        assert(offset);

        /* No matches is easy. We simple advance the file
         * pointer by one. */
        if (!j->level0)
                return journal_file_next_entry(f, f->current_offset, direction, ret, offset);

        /* If we have a match then we look for the next matching entry
         * with an offset at least one step larger */
        return next_for_match(j, j->level0, f,
                              direction == DIRECTION_DOWN ? f->current_offset + 1
                                                          : f->current_offset - 1,
                              direction, ret, offset);
}

static int next_beyond_location(sd_journal *j, JournalFile *f, direction_t direction) {
        Object *c;
        uint64_t cp, n_entries;
        int r;

        assert(j);
        assert(f);

        n_entries = le64toh(f->header->n_entries);

        /* If we hit EOF before, we don't need to look into this file again
         * unless direction changed or new entries appeared. */
        if (f->last_direction == direction && f->location_type == LOCATION_TAIL &&
            n_entries == f->last_n_entries)
                return 0;

        f->last_n_entries = n_entries;

        if (f->last_direction == direction && f->current_offset > 0) {
                /* LOCATION_SEEK here means we did the work in a previous
                 * iteration and the current location already points to a
                 * candidate entry. */
                if (f->location_type != LOCATION_SEEK) {
                        r = next_with_matches(j, f, direction, &c, &cp);
                        if (r <= 0)
                                return r;

                        journal_file_save_location(f, c, cp);
                }
        } else {
                f->last_direction = direction;

                r = find_location_with_matches(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;

                journal_file_save_location(f, c, cp);
        }

        /* OK, we found the spot, now let's advance until an entry
         * that is actually different from what we were previously
         * looking at. This is necessary to handle entries which exist
         * in two (or more) journal files, and which shall all be
         * suppressed but one. */

        for (;;) {
                bool found;

                if (j->current_location.type == LOCATION_DISCRETE) {
                        int k;

                        k = compare_with_location(f, &j->current_location);

                        found = direction == DIRECTION_DOWN ? k > 0 : k < 0;
                } else
                        found = true;

                if (found)
                        return 1;

                r = next_with_matches(j, f, direction, &c, &cp);
                if (r <= 0)
                        return r;

                journal_file_save_location(f, c, cp);
        }
}

static int real_journal_next(sd_journal *j, direction_t direction) {
        JournalFile *f, *new_file = NULL;
        Iterator i;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                bool found;

                r = next_beyond_location(j, f, direction);
                if (r < 0) {
                        log_debug_errno(r, "Can't iterate through %s, ignoring: %m", f->path);
                        remove_file_real(j, f);
                        continue;
                } else if (r == 0) {
                        f->location_type = LOCATION_TAIL;
                        continue;
                }

                if (!new_file)
                        found = true;
                else {
                        int k;

                        k = journal_file_compare_locations(f, new_file);

                        found = direction == DIRECTION_DOWN ? k < 0 : k > 0;
                }

                if (found)
                        new_file = f;
        }

        if (!new_file)
                return 0;

        r = journal_file_move_to_object(new_file, OBJECT_ENTRY, new_file->current_offset, &o);
        if (r < 0)
                return r;

        set_location(j, new_file, o);

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

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

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

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(cursor, -EINVAL);

        if (!j->current_file || j->current_file->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(j->current_file, OBJECT_ENTRY, j->current_file->current_offset, &o);
        if (r < 0)
                return r;

        sd_id128_to_string(j->current_file->header->seqnum_id, sid);
        sd_id128_to_string(o->entry.boot_id, bid);

        if (asprintf(cursor,
                     "s=%s;i=%"PRIx64";b=%s;m=%"PRIx64";t=%"PRIx64";x=%"PRIx64,
                     sid, le64toh(o->entry.seqnum),
                     bid, le64toh(o->entry.monotonic),
                     le64toh(o->entry.realtime),
                     le64toh(o->entry.xor_hash)) < 0)
                return -ENOMEM;

        return 0;
}

_public_ int sd_journal_seek_cursor(sd_journal *j, const char *cursor) {
        const char *word, *state;
        size_t l;
        unsigned long long seqnum, monotonic, realtime, xor_hash;
        bool
                seqnum_id_set = false,
                seqnum_set = false,
                boot_id_set = false,
                monotonic_set = false,
                realtime_set = false,
                xor_hash_set = false;
        sd_id128_t seqnum_id, boot_id;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(!isempty(cursor), -EINVAL);

        FOREACH_WORD_SEPARATOR(word, l, cursor, ";", state) {
                char *item;
                int k = 0;

                if (l < 2 || word[1] != '=')
                        return -EINVAL;

                item = strndup(word, l);
                if (!item)
                        return -ENOMEM;

                switch (word[0]) {

                case 's':
                        seqnum_id_set = true;
                        k = sd_id128_from_string(item+2, &seqnum_id);
                        break;

                case 'i':
                        seqnum_set = true;
                        if (sscanf(item+2, "%llx", &seqnum) != 1)
                                k = -EINVAL;
                        break;

                case 'b':
                        boot_id_set = true;
                        k = sd_id128_from_string(item+2, &boot_id);
                        break;

                case 'm':
                        monotonic_set = true;
                        if (sscanf(item+2, "%llx", &monotonic) != 1)
                                k = -EINVAL;
                        break;

                case 't':
                        realtime_set = true;
                        if (sscanf(item+2, "%llx", &realtime) != 1)
                                k = -EINVAL;
                        break;

                case 'x':
                        xor_hash_set = true;
                        if (sscanf(item+2, "%llx", &xor_hash) != 1)
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

        j->current_location.type = LOCATION_SEEK;

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

_public_ int sd_journal_test_cursor(sd_journal *j, const char *cursor) {
        int r;
        const char *word, *state;
        size_t l;
        Object *o;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(!isempty(cursor), -EINVAL);

        if (!j->current_file || j->current_file->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(j->current_file, OBJECT_ENTRY, j->current_file->current_offset, &o);
        if (r < 0)
                return r;

        FOREACH_WORD_SEPARATOR(word, l, cursor, ";", state) {
                _cleanup_free_ char *item = NULL;
                sd_id128_t id;
                unsigned long long ll;
                int k = 0;

                if (l < 2 || word[1] != '=')
                        return -EINVAL;

                item = strndup(word, l);
                if (!item)
                        return -ENOMEM;

                switch (word[0]) {

                case 's':
                        k = sd_id128_from_string(item+2, &id);
                        if (k < 0)
                                return k;
                        if (!sd_id128_equal(id, j->current_file->header->seqnum_id))
                                return 0;
                        break;

                case 'i':
                        if (sscanf(item+2, "%llx", &ll) != 1)
                                return -EINVAL;
                        if (ll != le64toh(o->entry.seqnum))
                                return 0;
                        break;

                case 'b':
                        k = sd_id128_from_string(item+2, &id);
                        if (k < 0)
                                return k;
                        if (!sd_id128_equal(id, o->entry.boot_id))
                                return 0;
                        break;

                case 'm':
                        if (sscanf(item+2, "%llx", &ll) != 1)
                                return -EINVAL;
                        if (ll != le64toh(o->entry.monotonic))
                                return 0;
                        break;

                case 't':
                        if (sscanf(item+2, "%llx", &ll) != 1)
                                return -EINVAL;
                        if (ll != le64toh(o->entry.realtime))
                                return 0;
                        break;

                case 'x':
                        if (sscanf(item+2, "%llx", &ll) != 1)
                                return -EINVAL;
                        if (ll != le64toh(o->entry.xor_hash))
                                return 0;
                        break;
                }
        }

        return 1;
}


_public_ int sd_journal_seek_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t usec) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        reset_location(j);
        j->current_location.type = LOCATION_SEEK;
        j->current_location.boot_id = boot_id;
        j->current_location.monotonic = usec;
        j->current_location.monotonic_set = true;

        return 0;
}

_public_ int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        reset_location(j);
        j->current_location.type = LOCATION_SEEK;
        j->current_location.realtime = usec;
        j->current_location.realtime_set = true;

        return 0;
}

_public_ int sd_journal_seek_head(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        reset_location(j);
        j->current_location.type = LOCATION_HEAD;

        return 0;
}

_public_ int sd_journal_seek_tail(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        reset_location(j);
        j->current_location.type = LOCATION_TAIL;

        return 0;
}

static void check_network(sd_journal *j, int fd) {
        struct statfs sfs;

        assert(j);

        if (j->on_network)
                return;

        if (fstatfs(fd, &sfs) < 0)
                return;

        j->on_network =
                F_TYPE_EQUAL(sfs.f_type, CIFS_MAGIC_NUMBER) ||
                F_TYPE_EQUAL(sfs.f_type, CODA_SUPER_MAGIC) ||
                F_TYPE_EQUAL(sfs.f_type, NCP_SUPER_MAGIC) ||
                F_TYPE_EQUAL(sfs.f_type, NFS_SUPER_MAGIC) ||
                F_TYPE_EQUAL(sfs.f_type, SMB_SUPER_MAGIC);
}

static bool file_has_type_prefix(const char *prefix, const char *filename) {
        const char *full, *tilded, *atted;

        full = strjoina(prefix, ".journal");
        tilded = strjoina(full, "~");
        atted = strjoina(prefix, "@");

        return streq(filename, full) ||
               streq(filename, tilded) ||
               startswith(filename, atted);
}

static bool file_type_wanted(int flags, const char *filename) {
        if (!endswith(filename, ".journal") && !endswith(filename, ".journal~"))
                return false;

        /* no flags set → every type is OK */
        if (!(flags & (SD_JOURNAL_SYSTEM | SD_JOURNAL_CURRENT_USER)))
                return true;

        if (flags & SD_JOURNAL_SYSTEM && file_has_type_prefix("system", filename))
                return true;

        if (flags & SD_JOURNAL_CURRENT_USER) {
                char prefix[5 + DECIMAL_STR_MAX(uid_t) + 1];

                xsprintf(prefix, "user-"UID_FMT, getuid());

                if (file_has_type_prefix(prefix, filename))
                        return true;
        }

        return false;
}

static int add_any_file(sd_journal *j, const char *path) {
        JournalFile *f = NULL;
        int r;

        assert(j);
        assert(path);

        if (ordered_hashmap_get(j->files, path))
                return 0;

        if (ordered_hashmap_size(j->files) >= JOURNAL_FILES_MAX) {
                log_warning("Too many open journal files, not adding %s.", path);
                return set_put_error(j, -ETOOMANYREFS);
        }

        r = journal_file_open(path, O_RDONLY, 0, false, false, NULL, j->mmap, NULL, &f);
        if (r < 0)
                return r;

        /* journal_file_dump(f); */

        r = ordered_hashmap_put(j->files, f->path, f);
        if (r < 0) {
                journal_file_close(f);
                return r;
        }

        log_debug("File %s added.", f->path);

        check_network(j, f->fd);

        j->current_invalidate_counter ++;

        return 0;
}

static int add_file(sd_journal *j, const char *prefix, const char *filename) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(j);
        assert(prefix);
        assert(filename);

        if (j->no_new_files ||
            !file_type_wanted(j->flags, filename))
                return 0;

        path = strjoin(prefix, "/", filename, NULL);
        if (!path)
                return -ENOMEM;

        r = add_any_file(j, path);
        if (r == -ENOENT)
                return 0;
        return r;
}

static int remove_file(sd_journal *j, const char *prefix, const char *filename) {
        _cleanup_free_ char *path;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        path = strjoin(prefix, "/", filename, NULL);
        if (!path)
                return -ENOMEM;

        f = ordered_hashmap_get(j->files, path);
        if (!f)
                return 0;

        remove_file_real(j, f);
        return 0;
}

static void remove_file_real(sd_journal *j, JournalFile *f) {
        assert(j);
        assert(f);

        ordered_hashmap_remove(j->files, f->path);

        log_debug("File %s removed.", f->path);

        if (j->current_file == f) {
                j->current_file = NULL;
                j->current_field = 0;
        }

        if (j->unique_file == f) {
                /* Jump to the next unique_file or NULL if that one was last */
                j->unique_file = ordered_hashmap_next(j->files, j->unique_file->path);
                j->unique_offset = 0;
                if (!j->unique_file)
                        j->unique_file_lost = true;
        }

        journal_file_close(f);

        j->current_invalidate_counter ++;
}

static int add_directory(sd_journal *j, const char *prefix, const char *dirname) {
        _cleanup_free_ char *path = NULL;
        int r;
        _cleanup_closedir_ DIR *d = NULL;
        sd_id128_t id, mid;
        Directory *m;

        assert(j);
        assert(prefix);
        assert(dirname);

        log_debug("Considering %s/%s.", prefix, dirname);

        if ((j->flags & SD_JOURNAL_LOCAL_ONLY) &&
            (sd_id128_from_string(dirname, &id) < 0 ||
             sd_id128_get_machine(&mid) < 0 ||
             !(sd_id128_equal(id, mid) || path_startswith(prefix, "/run"))))
            return 0;

        path = strjoin(prefix, "/", dirname, NULL);
        if (!path)
                return -ENOMEM;

        d = opendir(path);
        if (!d) {
                log_debug_errno(errno, "Failed to open %s: %m", path);
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        m = hashmap_get(j->directories_by_path, path);
        if (!m) {
                m = new0(Directory, 1);
                if (!m)
                        return -ENOMEM;

                m->is_root = false;
                m->path = path;

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        free(m);
                        return -ENOMEM;
                }

                path = NULL; /* avoid freeing in cleanup */
                j->current_invalidate_counter ++;

                log_debug("Directory %s added.", m->path);

        } else if (m->is_root)
                return 0;

        if (m->wd <= 0 && j->inotify_fd >= 0) {

                m->wd = inotify_add_watch(j->inotify_fd, m->path,
                                          IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                                          IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT|IN_MOVED_FROM|
                                          IN_ONLYDIR);

                if (m->wd > 0 && hashmap_put(j->directories_by_wd, INT_TO_PTR(m->wd), m) < 0)
                        inotify_rm_watch(j->inotify_fd, m->wd);
        }

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0) {
                        r = -errno;
                        log_debug_errno(errno, "Failed to read directory %s: %m", m->path);
                        return r;
                }
                if (!de)
                        break;

                if (dirent_is_file_with_suffix(de, ".journal") ||
                    dirent_is_file_with_suffix(de, ".journal~")) {
                        r = add_file(j, m->path, de->d_name);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add file %s/%s: %m",
                                                m->path, de->d_name);
                                r = set_put_error(j, r);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        check_network(j, dirfd(d));

        return 0;
}

static int add_root_directory(sd_journal *j, const char *p) {
        _cleanup_closedir_ DIR *d = NULL;
        Directory *m;
        int r;

        assert(j);
        assert(p);

        if ((j->flags & SD_JOURNAL_RUNTIME_ONLY) &&
            !path_startswith(p, "/run"))
                return -EINVAL;

        if (j->prefix)
                p = strjoina(j->prefix, p);

        d = opendir(p);
        if (!d)
                return -errno;

        m = hashmap_get(j->directories_by_path, p);
        if (!m) {
                m = new0(Directory, 1);
                if (!m)
                        return -ENOMEM;

                m->is_root = true;
                m->path = strdup(p);
                if (!m->path) {
                        free(m);
                        return -ENOMEM;
                }

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        free(m->path);
                        free(m);
                        return -ENOMEM;
                }

                j->current_invalidate_counter ++;

                log_debug("Root directory %s added.", m->path);

        } else if (!m->is_root)
                return 0;

        if (m->wd <= 0 && j->inotify_fd >= 0) {

                m->wd = inotify_add_watch(j->inotify_fd, m->path,
                                          IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                                          IN_ONLYDIR);

                if (m->wd > 0 && hashmap_put(j->directories_by_wd, INT_TO_PTR(m->wd), m) < 0)
                        inotify_rm_watch(j->inotify_fd, m->wd);
        }

        if (j->no_new_files)
                return 0;

        for (;;) {
                struct dirent *de;
                sd_id128_t id;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0) {
                        r = -errno;
                        log_debug_errno(errno, "Failed to read directory %s: %m", m->path);
                        return r;
                }
                if (!de)
                        break;

                if (dirent_is_file_with_suffix(de, ".journal") ||
                    dirent_is_file_with_suffix(de, ".journal~")) {
                        r = add_file(j, m->path, de->d_name);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to add file %s/%s: %m",
                                                m->path, de->d_name);
                                r = set_put_error(j, r);
                                if (r < 0)
                                        return r;
                        }
                } else if ((de->d_type == DT_DIR || de->d_type == DT_LNK || de->d_type == DT_UNKNOWN) &&
                           sd_id128_from_string(de->d_name, &id) >= 0) {

                        r = add_directory(j, m->path, de->d_name);
                        if (r < 0)
                                log_debug_errno(r, "Failed to add directory %s/%s: %m", m->path, de->d_name);
                }
        }

        check_network(j, dirfd(d));

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
                log_debug("Root directory %s removed.", d->path);
        else
                log_debug("Directory %s removed.", d->path);

        free(d->path);
        free(d);

        return 0;
}

static int add_search_paths(sd_journal *j) {
        int r;
        const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";
        const char *p;

        assert(j);

        /* We ignore most errors here, since the idea is to only open
         * what's actually accessible, and ignore the rest. */

        NULSTR_FOREACH(p, search_paths) {
                r = add_root_directory(j, p);
                if (r < 0 && r != -ENOENT) {
                        r = set_put_error(j, r);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int add_current_paths(sd_journal *j) {
        Iterator i;
        JournalFile *f;

        assert(j);
        assert(j->no_new_files);

        /* Simply adds all directories for files we have open as
         * "root" directories. We don't expect errors here, so we
         * treat them as fatal. */

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                _cleanup_free_ char *dir;
                int r;

                dir = dirname_malloc(f->path);
                if (!dir)
                        return -ENOMEM;

                r = add_root_directory(j, dir);
                if (r < 0) {
                        set_put_error(j, r);
                        return r;
                }
        }

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
                j->directories_by_wd = hashmap_new(NULL);
                if (!j->directories_by_wd)
                        return -ENOMEM;
        }

        return 0;
}

static sd_journal *journal_new(int flags, const char *path) {
        sd_journal *j;

        j = new0(sd_journal, 1);
        if (!j)
                return NULL;

        j->original_pid = getpid();
        j->inotify_fd = -1;
        j->flags = flags;
        j->data_threshold = DEFAULT_DATA_THRESHOLD;

        if (path) {
                j->path = strdup(path);
                if (!j->path)
                        goto fail;
        }

        j->files = ordered_hashmap_new(&string_hash_ops);
        j->directories_by_path = hashmap_new(&string_hash_ops);
        j->mmap = mmap_cache_new();
        if (!j->files || !j->directories_by_path || !j->mmap)
                goto fail;

        return j;

fail:
        sd_journal_close(j);
        return NULL;
}

_public_ int sd_journal_open(sd_journal **ret, int flags) {
        sd_journal *j;
        int r;

        assert_return(ret, -EINVAL);
        assert_return((flags & ~(SD_JOURNAL_LOCAL_ONLY|SD_JOURNAL_RUNTIME_ONLY|SD_JOURNAL_SYSTEM|SD_JOURNAL_CURRENT_USER)) == 0, -EINVAL);

        j = journal_new(flags, NULL);
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

_public_ int sd_journal_open_container(sd_journal **ret, const char *machine, int flags) {
        _cleanup_free_ char *root = NULL, *class = NULL;
        sd_journal *j;
        char *p;
        int r;

        assert_return(machine, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return((flags & ~(SD_JOURNAL_LOCAL_ONLY|SD_JOURNAL_SYSTEM)) == 0, -EINVAL);
        assert_return(machine_name_is_valid(machine), -EINVAL);

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(p, NEWLINE, "ROOT", &root, "CLASS", &class, NULL);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!root)
                return -ENODATA;

        if (!streq_ptr(class, "container"))
                return -EIO;

        j = journal_new(flags, NULL);
        if (!j)
                return -ENOMEM;

        j->prefix = root;
        root = NULL;

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

        assert_return(ret, -EINVAL);
        assert_return(path, -EINVAL);
        assert_return(flags == 0, -EINVAL);

        j = journal_new(flags, path);
        if (!j)
                return -ENOMEM;

        r = add_root_directory(j, path);
        if (r < 0) {
                set_put_error(j, r);
                goto fail;
        }

        *ret = j;
        return 0;

fail:
        sd_journal_close(j);

        return r;
}

_public_ int sd_journal_open_files(sd_journal **ret, const char **paths, int flags) {
        sd_journal *j;
        const char **path;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(flags == 0, -EINVAL);

        j = journal_new(flags, NULL);
        if (!j)
                return -ENOMEM;

        STRV_FOREACH(path, paths) {
                r = add_any_file(j, *path);
                if (r < 0) {
                        log_error_errno(r, "Failed to open %s: %m", *path);
                        goto fail;
                }
        }

        j->no_new_files = true;

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

        sd_journal_flush_matches(j);

        while ((f = ordered_hashmap_steal_first(j->files)))
                journal_file_close(f);

        ordered_hashmap_free(j->files);

        while ((d = hashmap_first(j->directories_by_path)))
                remove_directory(j, d);

        while ((d = hashmap_first(j->directories_by_wd)))
                remove_directory(j, d);

        hashmap_free(j->directories_by_path);
        hashmap_free(j->directories_by_wd);

        safe_close(j->inotify_fd);

        if (j->mmap) {
                log_debug("mmap cache statistics: %u hit, %u miss", mmap_cache_get_hit(j->mmap), mmap_cache_get_missed(j->mmap));
                mmap_cache_unref(j->mmap);
        }

        free(j->path);
        free(j->prefix);
        free(j->unique_field);
        set_free(j->errors);
        free(j);
}

_public_ int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret) {
        Object *o;
        JournalFile *f;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(ret, -EINVAL);

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

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

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

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(field, -EINVAL);
        assert_return(data, -EINVAL);
        assert_return(size, -EINVAL);
        assert_return(field_is_valid(field), -EINVAL);

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
                int compression;

                p = le64toh(o->entry.items[i].object_offset);
                le_hash = o->entry.items[i].hash;
                r = journal_file_move_to_object(f, OBJECT_DATA, p, &o);
                if (r < 0)
                        return r;

                if (le_hash != o->data.hash)
                        return -EBADMSG;

                l = le64toh(o->object.size) - offsetof(Object, data.payload);

                compression = o->object.flags & OBJECT_COMPRESSION_MASK;
                if (compression) {
#if defined(HAVE_XZ) || defined(HAVE_LZ4)
                        if (decompress_startswith(compression,
                                                  o->data.payload, l,
                                                  &f->compress_buffer, &f->compress_buffer_size,
                                                  field, field_length, '=')) {

                                size_t rsize;

                                r = decompress_blob(compression,
                                                    o->data.payload, l,
                                                    &f->compress_buffer, &f->compress_buffer_size, &rsize,
                                                    j->data_threshold);
                                if (r < 0)
                                        return r;

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

static int return_data(sd_journal *j, JournalFile *f, Object *o, const void **data, size_t *size) {
        size_t t;
        uint64_t l;
        int compression;

        l = le64toh(o->object.size) - offsetof(Object, data.payload);
        t = (size_t) l;

        /* We can't read objects larger than 4G on a 32bit machine */
        if ((uint64_t) t != l)
                return -E2BIG;

        compression = o->object.flags & OBJECT_COMPRESSION_MASK;
        if (compression) {
#if defined(HAVE_XZ) || defined(HAVE_LZ4)
                size_t rsize;
                int r;

                r = decompress_blob(compression,
                                    o->data.payload, l, &f->compress_buffer,
                                    &f->compress_buffer_size, &rsize, j->data_threshold);
                if (r < 0)
                        return r;

                *data = f->compress_buffer;
                *size = (size_t) rsize;
#else
                return -EPROTONOSUPPORT;
#endif
        } else {
                *data = o->data.payload;
                *size = t;
        }

        return 0;
}

_public_ int sd_journal_enumerate_data(sd_journal *j, const void **data, size_t *size) {
        JournalFile *f;
        uint64_t p, n;
        le64_t le_hash;
        int r;
        Object *o;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(data, -EINVAL);
        assert_return(size, -EINVAL);

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

        r = return_data(j, f, o, data, size);
        if (r < 0)
                return r;

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

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        if (j->inotify_fd >= 0)
                return j->inotify_fd;

        r = allocate_inotify(j);
        if (r < 0)
                return r;

        /* Iterate through all dirs again, to add them to the
         * inotify */
        if (j->no_new_files)
                r = add_current_paths(j);
        else if (j->path)
                r = add_root_directory(j, j->path);
        else
                r = add_search_paths(j);
        if (r < 0)
                return r;

        return j->inotify_fd;
}

_public_ int sd_journal_get_events(sd_journal *j) {
        int fd;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        fd = sd_journal_get_fd(j);
        if (fd < 0)
                return fd;

        return POLLIN;
}

_public_ int sd_journal_get_timeout(sd_journal *j, uint64_t *timeout_usec) {
        int fd;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(timeout_usec, -EINVAL);

        fd = sd_journal_get_fd(j);
        if (fd < 0)
                return fd;

        if (!j->on_network) {
                *timeout_usec = (uint64_t) -1;
                return 0;
        }

        /* If we are on the network we need to regularly check for
         * changes manually */

        *timeout_usec = j->last_process_usec + JOURNAL_FILES_RECHECK_USEC;
        return 1;
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

                if (!(e->mask & IN_ISDIR) && e->len > 0 &&
                    (endswith(e->name, ".journal") ||
                     endswith(e->name, ".journal~"))) {

                        /* Event for a journal file */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_file(j, d->path, e->name);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to add file %s/%s: %m",
                                                        d->path, e->name);
                                        set_put_error(j, r);
                                }

                        } else if (e->mask & (IN_DELETE|IN_MOVED_FROM|IN_UNMOUNT)) {

                                r = remove_file(j, d->path, e->name);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to remove file %s/%s: %m", d->path, e->name);
                        }

                } else if (!d->is_root && e->len == 0) {

                        /* Event for a subdirectory */

                        if (e->mask & (IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT)) {
                                r = remove_directory(j, d);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to remove directory %s: %m", d->path);
                        }


                } else if (d->is_root && (e->mask & IN_ISDIR) && e->len > 0 && sd_id128_from_string(e->name, &id) >= 0) {

                        /* Event for root directory */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB)) {
                                r = add_directory(j, d->path, e->name);
                                if (r < 0)
                                        log_debug_errno(r, "Failed to add directory %s/%s: %m", d->path, e->name);
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
        bool got_something = false;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        j->last_process_usec = now(CLOCK_MONOTONIC);

        for (;;) {
                union inotify_event_buffer buffer;
                struct inotify_event *e;
                ssize_t l;

                l = read(j->inotify_fd, &buffer, sizeof(buffer));
                if (l < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                return got_something ? determine_change(j) : SD_JOURNAL_NOP;

                        return -errno;
                }

                got_something = true;

                FOREACH_INOTIFY_EVENT(e, buffer, l)
                        process_inotify_event(j, e);
        }
}

_public_ int sd_journal_wait(sd_journal *j, uint64_t timeout_usec) {
        int r;
        uint64_t t;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

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

        r = sd_journal_get_timeout(j, &t);
        if (r < 0)
                return r;

        if (t != (uint64_t) -1) {
                usec_t n;

                n = now(CLOCK_MONOTONIC);
                t = t > n ? t - n : 0;

                if (timeout_usec == (uint64_t) -1 || timeout_usec > t)
                        timeout_usec = t;
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
        uint64_t fmin = 0, tmax = 0;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(from || to, -EINVAL);
        assert_return(from != to, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                usec_t fr, t;

                r = journal_file_get_cutoff_realtime_usec(f, &fr, &t);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (first) {
                        fmin = fr;
                        tmax = t;
                        first = false;
                } else {
                        fmin = MIN(fr, fmin);
                        tmax = MAX(t, tmax);
                }
        }

        if (from)
                *from = fmin;
        if (to)
                *to = tmax;

        return first ? 0 : 1;
}

_public_ int sd_journal_get_cutoff_monotonic_usec(sd_journal *j, sd_id128_t boot_id, uint64_t *from, uint64_t *to) {
        Iterator i;
        JournalFile *f;
        bool found = false;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(from || to, -EINVAL);
        assert_return(from != to, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                usec_t fr, t;

                r = journal_file_get_cutoff_monotonic_usec(f, boot_id, &fr, &t);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (found) {
                        if (from)
                                *from = MIN(fr, *from);
                        if (to)
                                *to = MAX(t, *to);
                } else {
                        if (from)
                                *from = fr;
                        if (to)
                                *to = t;
                        found = true;
                }
        }

        return found;
}

void journal_print_header(sd_journal *j) {
        Iterator i;
        JournalFile *f;
        bool newline = false;

        assert(j);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                if (newline)
                        putchar('\n');
                else
                        newline = true;

                journal_file_print_header(f);
        }
}

_public_ int sd_journal_get_usage(sd_journal *j, uint64_t *bytes) {
        Iterator i;
        JournalFile *f;
        uint64_t sum = 0;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(bytes, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files, i) {
                struct stat st;

                if (fstat(f->fd, &st) < 0)
                        return -errno;

                sum += (uint64_t) st.st_blocks * 512ULL;
        }

        *bytes = sum;
        return 0;
}

_public_ int sd_journal_query_unique(sd_journal *j, const char *field) {
        char *f;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(!isempty(field), -EINVAL);
        assert_return(field_is_valid(field), -EINVAL);

        f = strdup(field);
        if (!f)
                return -ENOMEM;

        free(j->unique_field);
        j->unique_field = f;
        j->unique_file = NULL;
        j->unique_offset = 0;
        j->unique_file_lost = false;

        return 0;
}

_public_ int sd_journal_enumerate_unique(sd_journal *j, const void **data, size_t *l) {
        size_t k;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(data, -EINVAL);
        assert_return(l, -EINVAL);
        assert_return(j->unique_field, -EINVAL);

        k = strlen(j->unique_field);

        if (!j->unique_file) {
                if (j->unique_file_lost)
                        return 0;

                j->unique_file = ordered_hashmap_first(j->files);
                if (!j->unique_file)
                        return 0;

                j->unique_offset = 0;
        }

        for (;;) {
                JournalFile *of;
                Iterator i;
                Object *o;
                const void *odata;
                size_t ol;
                bool found;
                int r;

                /* Proceed to next data object in the field's linked list */
                if (j->unique_offset == 0) {
                        r = journal_file_find_field_object(j->unique_file, j->unique_field, k, &o, NULL);
                        if (r < 0)
                                return r;

                        j->unique_offset = r > 0 ? le64toh(o->field.head_data_offset) : 0;
                } else {
                        r = journal_file_move_to_object(j->unique_file, OBJECT_DATA, j->unique_offset, &o);
                        if (r < 0)
                                return r;

                        j->unique_offset = le64toh(o->data.next_field_offset);
                }

                /* We reached the end of the list? Then start again, with the next file */
                if (j->unique_offset == 0) {
                        j->unique_file = ordered_hashmap_next(j->files, j->unique_file->path);
                        if (!j->unique_file)
                                return 0;

                        continue;
                }

                /* We do not use OBJECT_DATA context here, but OBJECT_UNUSED
                 * instead, so that we can look at this data object at the same
                 * time as one on another file */
                r = journal_file_move_to_object(j->unique_file, OBJECT_UNUSED, j->unique_offset, &o);
                if (r < 0)
                        return r;

                /* Let's do the type check by hand, since we used 0 context above. */
                if (o->object.type != OBJECT_DATA) {
                        log_debug("%s:offset " OFSfmt ": object has type %d, expected %d",
                                  j->unique_file->path, j->unique_offset,
                                  o->object.type, OBJECT_DATA);
                        return -EBADMSG;
                }

                r = return_data(j, j->unique_file, o, &odata, &ol);
                if (r < 0)
                        return r;

                /* Check if we have at least the field name and "=". */
                if (ol <= k) {
                        log_debug("%s:offset " OFSfmt ": object has size %zu, expected at least %zu",
                                  j->unique_file->path, j->unique_offset,
                                  ol, k + 1);
                        return -EBADMSG;
                }

                if (memcmp(odata, j->unique_field, k) || ((const char*) odata)[k] != '=') {
                        log_debug("%s:offset " OFSfmt ": object does not start with \"%s=\"",
                                  j->unique_file->path, j->unique_offset,
                                  j->unique_field);
                        return -EBADMSG;
                }

                /* OK, now let's see if we already returned this data
                 * object by checking if it exists in the earlier
                 * traversed files. */
                found = false;
                ORDERED_HASHMAP_FOREACH(of, j->files, i) {
                        Object *oo;
                        uint64_t op;

                        if (of == j->unique_file)
                                break;

                        /* Skip this file it didn't have any fields
                         * indexed */
                        if (JOURNAL_HEADER_CONTAINS(of->header, n_fields) &&
                            le64toh(of->header->n_fields) <= 0)
                                continue;

                        r = journal_file_find_data_object_with_hash(of, odata, ol, le64toh(o->data.hash), &oo, &op);
                        if (r < 0)
                                return r;

                        if (r > 0)
                                found = true;
                }

                if (found)
                        continue;

                r = return_data(j, j->unique_file, o, data, l);
                if (r < 0)
                        return r;

                return 1;
        }
}

_public_ void sd_journal_restart_unique(sd_journal *j) {
        if (!j)
                return;

        j->unique_file = NULL;
        j->unique_offset = 0;
        j->unique_file_lost = false;
}

_public_ int sd_journal_reliable_fd(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        return !j->on_network;
}

static char *lookup_field(const char *field, void *userdata) {
        sd_journal *j = userdata;
        const void *data;
        size_t size, d;
        int r;

        assert(field);
        assert(j);

        r = sd_journal_get_data(j, field, &data, &size);
        if (r < 0 ||
            size > REPLACE_VAR_MAX)
                return strdup(field);

        d = strlen(field) + 1;

        return strndup((const char*) data + d, size - d);
}

_public_ int sd_journal_get_catalog(sd_journal *j, char **ret) {
        const void *data;
        size_t size;
        sd_id128_t id;
        _cleanup_free_ char *text = NULL, *cid = NULL;
        char *t;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(ret, -EINVAL);

        r = sd_journal_get_data(j, "MESSAGE_ID", &data, &size);
        if (r < 0)
                return r;

        cid = strndup((const char*) data + 11, size - 11);
        if (!cid)
                return -ENOMEM;

        r = sd_id128_from_string(cid, &id);
        if (r < 0)
                return r;

        r = catalog_get(CATALOG_DATABASE, id, &text);
        if (r < 0)
                return r;

        t = replace_var(text, lookup_field, j);
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

_public_ int sd_journal_get_catalog_for_message_id(sd_id128_t id, char **ret) {
        assert_return(ret, -EINVAL);

        return catalog_get(CATALOG_DATABASE, id, ret);
}

_public_ int sd_journal_set_data_threshold(sd_journal *j, size_t sz) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);

        j->data_threshold = sz;
        return 0;
}

_public_ int sd_journal_get_data_threshold(sd_journal *j, size_t *sz) {
        assert_return(j, -EINVAL);
        assert_return(!journal_pid_changed(j), -ECHILD);
        assert_return(sz, -EINVAL);

        *sz = j->data_threshold;
        return 0;
}
