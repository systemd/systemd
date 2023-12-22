/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <poll.h>
#include <stddef.h>
#include <sys/inotify.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "catalog.h"
#include "compress.h"
#include "dirent-util.h"
#include "env-file.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "inotify-util.h"
#include "io-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-internal.h"
#include "list.h"
#include "lookup3.h"
#include "nulstr-util.h"
#include "origin-id.h"
#include "path-util.h"
#include "prioq.h"
#include "process-util.h"
#include "replace-var.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "uid-alloc-range.h"

#define JOURNAL_FILES_RECHECK_USEC (2 * USEC_PER_SEC)

/* The maximum size of variable values we'll expand in catalog entries. We bind this to PATH_MAX for now, as
 * we want to be able to show all officially valid paths at least */
#define REPLACE_VAR_MAX PATH_MAX

#define DEFAULT_DATA_THRESHOLD (64*1024)

DEFINE_PRIVATE_ORIGIN_ID_HELPERS(sd_journal, journal);

static void remove_file_real(sd_journal *j, JournalFile *f);
static int journal_file_read_tail_timestamp(sd_journal *j, JournalFile *f);
static void journal_file_unlink_newest_by_boot_id(sd_journal *j, JournalFile *f);

static int journal_put_error(sd_journal *j, int r, const char *path) {
        _cleanup_free_ char *copy = NULL;
        int k;

        /* Memorize an error we encountered, and store which
         * file/directory it was generated from. Note that we store
         * only *one* path per error code, as the error code is the
         * key into the hashmap, and the path is the value. This means
         * we keep track only of all error kinds, but not of all error
         * locations. This has the benefit that the hashmap cannot
         * grow beyond bounds.
         *
         * We return an error here only if we didn't manage to
         * memorize the real error. */

        if (r >= 0)
                return r;

        if (path) {
                copy = strdup(path);
                if (!copy)
                        return -ENOMEM;
        }

        k = hashmap_ensure_put(&j->errors, NULL, INT_TO_PTR(r), copy);
        if (k < 0) {
                if (k == -EEXIST)
                        return 0;

                return k;
        }

        TAKE_PTR(copy);
        return 0;
}

static void detach_location(sd_journal *j) {
        JournalFile *f;

        assert(j);

        j->current_file = NULL;
        j->current_field = 0;

        ORDERED_HASHMAP_FOREACH(f, j->files)
                journal_file_reset_location(f);
}

static void init_location(Location *l, LocationType type, JournalFile *f, Object *o) {
        assert(l);
        assert(IN_SET(type, LOCATION_DISCRETE, LOCATION_SEEK));
        assert(f);

        *l = (Location) {
                .type = type,
                .seqnum = le64toh(o->entry.seqnum),
                .seqnum_id = f->header->seqnum_id,
                .realtime = le64toh(o->entry.realtime),
                .monotonic = le64toh(o->entry.monotonic),
                .boot_id = o->entry.boot_id,
                .xor_hash = le64toh(o->entry.xor_hash),
                .seqnum_set = true,
                .realtime_set = true,
                .monotonic_set = true,
                .xor_hash_set = true,
        };
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
        const char *b = ASSERT_PTR(data);

        if (size < 2)
                return false;

        if (((char*) data)[0] == '_' && ((char*) data)[1] == '_')
                return false;

        for (const char *p = b; p < b + size; p++) {

                if (*p == '=')
                        return p > b;

                if (*p == '_')
                        continue;

                if (*p >= 'A' && *p <= 'Z')
                        continue;

                if (ascii_isdigit(*p))
                        continue;

                return false;
        }

        return false;
}

static bool same_field(const void *_a, size_t s, const void *_b, size_t t) {
        const uint8_t *a = _a, *b = _b;

        for (size_t j = 0; j < s && j < t; j++) {

                if (a[j] != b[j])
                        return false;

                if (a[j] == '=')
                        return true;
        }

        assert_not_reached();
}

static Match *match_new(Match *p, MatchType t) {
        Match *m;

        m = new(Match, 1);
        if (!m)
                return NULL;

        *m = (Match) {
                .type = t,
                .parent = p,
        };

        if (p)
                LIST_PREPEND(matches, p->matches, m);

        return m;
}

static Match *match_free(Match *m) {
        assert(m);

        while (m->matches)
                match_free(m->matches);

        if (m->parent)
                LIST_REMOVE(matches, m->parent->matches, m);

        free(m->data);
        return mfree(m);
}

static Match *match_free_if_empty(Match *m) {
        if (!m || m->matches)
                return m;

        return match_free(m);
}

_public_ int sd_journal_add_match(sd_journal *j, const void *data, size_t size) {
        Match *add_here = NULL, *m = NULL;
        uint64_t hash;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(data, -EINVAL);

        if (size == 0)
                size = strlen(data);

        if (!match_is_valid(data, size))
                return -EINVAL;

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

        /* Old-style Jenkins (unkeyed) hashing only here. We do not cover new-style siphash (keyed) hashing
         * here, since it's different for each file, and thus can't be pre-calculated in the Match object. */
        hash = jenkins_hash64(data, size);

        LIST_FOREACH(matches, l3, j->level2->matches) {
                assert(l3->type == MATCH_OR_TERM);

                LIST_FOREACH(matches, l4, l3->matches) {
                        assert(l4->type == MATCH_DISCRETE);

                        /* Exactly the same match already? Then ignore
                         * this addition */
                        if (l4->hash == hash &&
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

        m->hash = hash;
        m->size = size;
        m->data = memdup(data, size);
        if (!m->data)
                goto fail;

        detach_location(j);

        return 0;

fail:
        match_free(m);
        match_free_if_empty(add_here);
        j->level2 = match_free_if_empty(j->level2);
        j->level1 = match_free_if_empty(j->level1);
        j->level0 = match_free_if_empty(j->level0);

        return -ENOMEM;
}

_public_ int sd_journal_add_conjunction(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

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
        assert_return(!journal_origin_changed(j), -ECHILD);

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
        _cleanup_free_ char *p = NULL;
        bool enclose = false;

        if (!m)
                return strdup("none");

        if (m->type == MATCH_DISCRETE)
                return cescape_length(m->data, m->size);

        LIST_FOREACH(matches, i, m->matches) {
                _cleanup_free_ char *t = NULL;

                t = match_make_string(i);
                if (!t)
                        return NULL;

                if (p) {
                        if (!strextend(&p, m->type == MATCH_OR_TERM ? " OR " : " AND ", t))
                                return NULL;

                        enclose = true;
                } else
                        p = TAKE_PTR(t);
        }

        if (enclose)
                return strjoin("(", p, ")");

        return TAKE_PTR(p);
}

char *journal_make_match_string(sd_journal *j) {
        assert(j);

        return match_make_string(j->level0);
}

_public_ void sd_journal_flush_matches(sd_journal *j) {
        if (!j || journal_origin_changed(j))
                return;

        if (j->level0)
                match_free(j->level0);

        j->level0 = j->level1 = j->level2 = NULL;

        detach_location(j);
}

static int newest_by_boot_id_compare(const NewestByBootId *a, const NewestByBootId *b) {
        return id128_compare_func(&a->boot_id, &b->boot_id);
}

static void journal_file_unlink_newest_by_boot_id(sd_journal *j, JournalFile *f) {
        NewestByBootId *found;

        assert(j);
        assert(f);

        if (f->newest_boot_id_prioq_idx == PRIOQ_IDX_NULL) /* not linked currently, hence this is a NOP */
                return;

        found = typesafe_bsearch(&(NewestByBootId) { .boot_id = f->newest_boot_id },
                                 j->newest_by_boot_id, j->n_newest_by_boot_id, newest_by_boot_id_compare);
        assert(found);

        assert_se(prioq_remove(found->prioq, f, &f->newest_boot_id_prioq_idx) > 0);
        f->newest_boot_id_prioq_idx = PRIOQ_IDX_NULL;

        /* The prioq may be empty, but that should not cause any issue. Let's keep it. */
}

static void journal_clear_newest_by_boot_id(sd_journal *j) {
        FOREACH_ARRAY(i, j->newest_by_boot_id, j->n_newest_by_boot_id) {
                JournalFile *f;

                while ((f = prioq_peek(i->prioq)))
                        journal_file_unlink_newest_by_boot_id(j, f);

                prioq_free(i->prioq);
        }

        j->newest_by_boot_id = mfree(j->newest_by_boot_id);
        j->n_newest_by_boot_id = 0;
}

static int journal_file_newest_monotonic_compare(const void *a, const void *b) {
        const JournalFile *x = a, *y = b;

        return -CMP(x->newest_monotonic_usec, y->newest_monotonic_usec); /* Invert order, we want newest first! */
}

static int journal_file_reshuffle_newest_by_boot_id(sd_journal *j, JournalFile *f) {
        NewestByBootId *found;
        int r;

        assert(j);
        assert(f);

        found = typesafe_bsearch(&(NewestByBootId) { .boot_id = f->newest_boot_id },
                                 j->newest_by_boot_id, j->n_newest_by_boot_id, newest_by_boot_id_compare);
        if (found) {
                /* There's already a priority queue for this boot ID */

                if (f->newest_boot_id_prioq_idx == PRIOQ_IDX_NULL) {
                        r = prioq_put(found->prioq, f, &f->newest_boot_id_prioq_idx); /* Insert if we aren't in there yet */
                        if (r < 0)
                                return r;
                } else
                        prioq_reshuffle(found->prioq, f, &f->newest_boot_id_prioq_idx); /* Reshuffle otherwise */

        } else {
                _cleanup_(prioq_freep) Prioq *q = NULL;

                /* No priority queue yet, then allocate one */

                assert(f->newest_boot_id_prioq_idx == PRIOQ_IDX_NULL); /* we can't be a member either */

                q = prioq_new(journal_file_newest_monotonic_compare);
                if (!q)
                        return -ENOMEM;

                r = prioq_put(q, f, &f->newest_boot_id_prioq_idx);
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(j->newest_by_boot_id, j->n_newest_by_boot_id + 1)) {
                        f->newest_boot_id_prioq_idx = PRIOQ_IDX_NULL;
                        return -ENOMEM;
                }

                j->newest_by_boot_id[j->n_newest_by_boot_id++] = (NewestByBootId) {
                        .boot_id = f->newest_boot_id,
                        .prioq = TAKE_PTR(q),
                };

                typesafe_qsort(j->newest_by_boot_id, j->n_newest_by_boot_id, newest_by_boot_id_compare);
        }

        return 0;
}

static int journal_file_find_newest_for_boot_id(
                sd_journal *j,
                sd_id128_t id,
                JournalFile **ret) {

        JournalFile *prev = NULL;
        int r;

        assert(j);
        assert(ret);

        /* Before we use it, let's refresh the timestamp from the header, and reshuffle our prioq
         * accordingly. We do this only a bunch of times, to not be caught in some update loop. */
        for (unsigned n_tries = 0;; n_tries++) {
                NewestByBootId *found;
                JournalFile *f;

                found = typesafe_bsearch(&(NewestByBootId) { .boot_id = id },
                                         j->newest_by_boot_id, j->n_newest_by_boot_id, newest_by_boot_id_compare);

                f = found ? prioq_peek(found->prioq) : NULL;
                if (!f)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA),
                                               "Requested delta for boot ID %s, but we have no information about that boot ID.", SD_ID128_TO_STRING(id));

                if (f == prev || n_tries >= 5 || FLAGS_SET(j->flags, SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)) {
                        /* This was already the best answer in the previous run, or we tried too often, use it */
                        *ret = f;
                        return 0;
                }

                prev = f;

                /* Let's read the journal file's current timestamp once, before we return it, maybe it has changed. */
                r = journal_file_read_tail_timestamp(j, f);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read tail timestamp while trying to find newest journal file for boot ID %s.", SD_ID128_TO_STRING(id));
                if (r == 0) {
                        /* No new entry found. */
                        *ret = f;
                        return 0;
                }

                /* Refreshing the timestamp we read might have reshuffled the prioq, hence let's check the
                 * prioq again and only use the information once we reached an equilibrium or hit a limit */
        }
}

static int compare_boot_ids(sd_journal *j, sd_id128_t a, sd_id128_t b) {
        JournalFile *x, *y;

        assert(j);

        /* Try to find the newest open journal file for the two boot ids */
        if (journal_file_find_newest_for_boot_id(j, a, &x) < 0 ||
            journal_file_find_newest_for_boot_id(j, b, &y) < 0)
                return 0;

        /* Only compare the boot id timestamps if they originate from the same machine. If they are from
         * different machines, then we timestamps of the boot ids might be as off as the timestamps on the
         * entries and hence not useful for comparing. */
        if (!sd_id128_equal(x->newest_machine_id, y->newest_machine_id))
                return 0;

        return CMP(x->newest_realtime_usec, y->newest_realtime_usec);
}

static int compare_with_location(
                sd_journal *j,
                const JournalFile *f,
                const Location *l,
                const JournalFile *current_file) {
        int r;

        assert(j);
        assert(f);
        assert(l);
        assert(f->location_type == LOCATION_SEEK);
        assert(IN_SET(l->type, LOCATION_DISCRETE, LOCATION_SEEK));

        if (l->monotonic_set &&
            sd_id128_equal(f->current_boot_id, l->boot_id) &&
            l->realtime_set &&
            f->current_realtime == l->realtime &&
            l->xor_hash_set &&
            f->current_xor_hash == l->xor_hash &&
            l->seqnum_set &&
            sd_id128_equal(f->header->seqnum_id, l->seqnum_id) &&
            f->current_seqnum == l->seqnum &&
            f != current_file)
                return 0;

        if (l->seqnum_set &&
            sd_id128_equal(f->header->seqnum_id, l->seqnum_id)) {
                r = CMP(f->current_seqnum, l->seqnum);
                if (r != 0)
                        return r;
        }

        if (l->monotonic_set) {
                /* If both arguments have the same boot ID, then we can compare the monotonic timestamps. If
                 * they are distinct, then we might able to lookup the timestamps of those boot IDs (if they
                 * are from the same machine) and order by that. */
                if (sd_id128_equal(f->current_boot_id, l->boot_id))
                        r = CMP(f->current_monotonic, l->monotonic);
                else
                        r = compare_boot_ids(j, f->current_boot_id, l->boot_id);
                if (r != 0)
                        return r;
        }

        if (l->realtime_set) {
                r = CMP(f->current_realtime, l->realtime);
                if (r != 0)
                        return r;
        }

        if (l->xor_hash_set) {
                r = CMP(f->current_xor_hash, l->xor_hash);
                if (r != 0)
                        return r;
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

        assert(j);
        assert(m);
        assert(f);

        if (m->type == MATCH_DISCRETE) {
                Object *d;
                uint64_t hash;

                /* If the keyed hash logic is used, we need to calculate the hash fresh per file. Otherwise
                 * we can use what we pre-calculated. */
                if (JOURNAL_HEADER_KEYED_HASH(f->header))
                        hash = journal_file_hash_data(f, m->data, m->size);
                else
                        hash = m->hash;

                r = journal_file_find_data_object_with_hash(f, m->data, m->size, hash, &d, NULL);
                if (r <= 0)
                        return r;

                return journal_file_move_to_entry_by_offset_for_data(f, d, after_offset, direction, ret, offset);

        } else if (m->type == MATCH_OR_TERM) {

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
                Match *last_moved;

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

        if (ret) {
                r = journal_file_move_to_object(f, OBJECT_ENTRY, np, ret);
                if (r < 0)
                        return r;
        }

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
                Object *d;
                uint64_t dp, hash;

                if (JOURNAL_HEADER_KEYED_HASH(f->header))
                        hash = journal_file_hash_data(f, m->data, m->size);
                else
                        hash = m->hash;

                r = journal_file_find_data_object_with_hash(f, m->data, m->size, hash, &d, &dp);
                if (r <= 0)
                        return r;

                /* FIXME: missing: find by monotonic */

                if (j->current_location.type == LOCATION_HEAD)
                        return direction == DIRECTION_DOWN ? journal_file_move_to_entry_for_data(f, d, DIRECTION_DOWN, ret, offset) : 0;
                if (j->current_location.type == LOCATION_TAIL)
                        return direction == DIRECTION_UP ? journal_file_move_to_entry_for_data(f, d, DIRECTION_UP, ret, offset) : 0;
                if (j->current_location.seqnum_set && sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        return journal_file_move_to_entry_by_seqnum_for_data(f, d, j->current_location.seqnum, direction, ret, offset);
                if (j->current_location.monotonic_set) {
                        r = journal_file_move_to_entry_by_monotonic_for_data(f, d, j->current_location.boot_id, j->current_location.monotonic, direction, ret, offset);
                        if (r != 0)
                                return r;

                        /* The data object might have been invalidated. */
                        r = journal_file_move_to_object(f, OBJECT_DATA, dp, &d);
                        if (r < 0)
                                return r;
                }
                if (j->current_location.realtime_set)
                        return journal_file_move_to_entry_by_realtime_for_data(f, d, j->current_location.realtime, direction, ret, offset);

                return journal_file_move_to_entry_for_data(f, d, direction, ret, offset);

        } else if (m->type == MATCH_OR_TERM) {
                uint64_t np = 0;

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

                if (ret) {
                        r = journal_file_move_to_object(f, OBJECT_ENTRY, np, ret);
                        if (r < 0)
                                return r;
                }

                if (offset)
                        *offset = np;

                return 1;

        } else {
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
                        return direction == DIRECTION_DOWN ? journal_file_next_entry(f, 0, DIRECTION_DOWN, ret, offset) : 0;
                if (j->current_location.type == LOCATION_TAIL)
                        return direction == DIRECTION_UP ? journal_file_next_entry(f, 0, DIRECTION_UP, ret, offset) : 0;
                if (j->current_location.seqnum_set && sd_id128_equal(j->current_location.seqnum_id, f->header->seqnum_id))
                        return journal_file_move_to_entry_by_seqnum(f, j->current_location.seqnum, direction, ret, offset);
                if (j->current_location.monotonic_set) {
                        r = journal_file_move_to_entry_by_monotonic(f, j->current_location.boot_id, j->current_location.monotonic, direction, ret, offset);
                        if (r != 0)
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

        if (!FLAGS_SET(j->flags, SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE))
                (void) journal_file_read_tail_timestamp(j, f);

        n_entries = le64toh(f->header->n_entries);

        /* If we hit EOF before, we don't need to look into this file again
         * unless direction changed or new entries appeared. */
        if (f->last_direction == direction &&
            f->location_type == (direction == DIRECTION_DOWN ? LOCATION_TAIL : LOCATION_HEAD) &&
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

                        k = compare_with_location(j, f, &j->current_location, j->current_file);

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

static int compare_locations(sd_journal *j, JournalFile *af, JournalFile *bf) {
        int r;

        assert(j);
        assert(af);
        assert(af->header);
        assert(bf);
        assert(bf->header);
        assert(af->location_type == LOCATION_SEEK);
        assert(bf->location_type == LOCATION_SEEK);

        /* If contents, timestamps and seqnum match, these entries are identical. */
        if (sd_id128_equal(af->current_boot_id, bf->current_boot_id) &&
            af->current_monotonic == bf->current_monotonic &&
            af->current_realtime == bf->current_realtime &&
            af->current_xor_hash == bf->current_xor_hash &&
            sd_id128_equal(af->header->seqnum_id, bf->header->seqnum_id) &&
            af->current_seqnum == bf->current_seqnum)
                return 0;

        if (sd_id128_equal(af->header->seqnum_id, bf->header->seqnum_id)) {
                /* If this is from the same seqnum source, compare seqnums */
                r = CMP(af->current_seqnum, bf->current_seqnum);
                if (r != 0)
                        return r;

                /* Wow! This is weird, different data but the same seqnums? Something is borked, but let's
                 * make the best of it and compare by time. */
        }

        if (sd_id128_equal(af->current_boot_id, bf->current_boot_id))
                /* If the boot id matches, compare monotonic time */
                r = CMP(af->current_monotonic, bf->current_monotonic);
        else
                /* If they don't match try to compare boot IDs */
                r = compare_boot_ids(j, af->current_boot_id, bf->current_boot_id);
        if (r != 0)
                return r;

        /* Otherwise, compare UTC time */
        r = CMP(af->current_realtime, bf->current_realtime);
        if (r != 0)
                return r;

        /* Finally, compare by contents */
        return CMP(af->current_xor_hash, bf->current_xor_hash);
}

static int real_journal_next(sd_journal *j, direction_t direction) {
        JournalFile *new_file = NULL;
        unsigned n_files;
        const void **files;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        r = iterated_cache_get(j->files_cache, NULL, &files, &n_files);
        if (r < 0)
                return r;

        FOREACH_ARRAY(_f, files, n_files) {
                JournalFile *f = (JournalFile*) *_f;
                bool found;

                r = next_beyond_location(j, f, direction);
                if (r < 0) {
                        log_debug_errno(r, "Can't iterate through %s, ignoring: %m", f->path);
                        remove_file_real(j, f);
                        continue;
                } else if (r == 0) {
                        f->location_type = direction == DIRECTION_DOWN ? LOCATION_TAIL : LOCATION_HEAD;
                        continue;
                }

                if (!new_file)
                        found = true;
                else {
                        int k;

                        k = compare_locations(j, f, new_file);

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

_public_ int sd_journal_step_one(sd_journal *j, int advanced) {
        assert_return(j, -EINVAL);

        if (j->current_location.type == LOCATION_HEAD)
                return sd_journal_next(j);
        if (j->current_location.type == LOCATION_TAIL)
                return sd_journal_previous(j);
        return real_journal_next(j, advanced ? DIRECTION_DOWN : DIRECTION_UP);
}

static int real_journal_next_skip(sd_journal *j, direction_t direction, uint64_t skip) {
        int c = 0, r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(skip <= INT_MAX, -ERANGE);

        if (skip == 0) {
                /* If this is not a discrete skip, then at least
                 * resolve the current location */
                if (j->current_location.type != LOCATION_DISCRETE) {
                        r = real_journal_next(j, direction);
                        if (r < 0)
                                return r;
                }

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

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(cursor, -EINVAL);

        if (!j->current_file || j->current_file->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(j->current_file, OBJECT_ENTRY, j->current_file->current_offset, &o);
        if (r < 0)
                return r;

        if (asprintf(cursor,
                     "s=%s;i=%"PRIx64";b=%s;m=%"PRIx64";t=%"PRIx64";x=%"PRIx64,
                     SD_ID128_TO_STRING(j->current_file->header->seqnum_id), le64toh(o->entry.seqnum),
                     SD_ID128_TO_STRING(o->entry.boot_id), le64toh(o->entry.monotonic),
                     le64toh(o->entry.realtime),
                     le64toh(o->entry.xor_hash)) < 0)
                return -ENOMEM;

        return 0;
}

_public_ int sd_journal_seek_cursor(sd_journal *j, const char *cursor) {
        unsigned long long seqnum, monotonic, realtime, xor_hash;
        bool seqnum_id_set = false,
             seqnum_set = false,
             boot_id_set = false,
             monotonic_set = false,
             realtime_set = false,
             xor_hash_set = false;
        sd_id128_t seqnum_id, boot_id;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(!isempty(cursor), -EINVAL);

        for (const char *p = cursor;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ";", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (word[0] == '\0' || word[1] != '=')
                        return -EINVAL;

                switch (word[0]) {
                case 's':
                        seqnum_id_set = true;
                        r = sd_id128_from_string(word + 2, &seqnum_id);
                        if (r < 0)
                                return r;
                        break;

                case 'i':
                        seqnum_set = true;
                        if (sscanf(word + 2, "%llx", &seqnum) != 1)
                                return -EINVAL;
                        break;

                case 'b':
                        boot_id_set = true;
                        r = sd_id128_from_string(word + 2, &boot_id);
                        if (r < 0)
                                return r;
                        break;

                case 'm':
                        monotonic_set = true;
                        if (sscanf(word + 2, "%llx", &monotonic) != 1)
                                return -EINVAL;
                        break;

                case 't':
                        realtime_set = true;
                        if (sscanf(word + 2, "%llx", &realtime) != 1)
                                return -EINVAL;
                        break;

                case 'x':
                        xor_hash_set = true;
                        if (sscanf(word + 2, "%llx", &xor_hash) != 1)
                                return -EINVAL;
                        break;
                }
        }

        if ((!seqnum_set || !seqnum_id_set) &&
            (!monotonic_set || !boot_id_set) &&
            !realtime_set)
                return -EINVAL;

        detach_location(j);
        j->current_location = (Location) {
                .type = LOCATION_SEEK,
        };

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
        Object *o;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(!isempty(cursor), -EINVAL);

        if (!j->current_file || j->current_file->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(j->current_file, OBJECT_ENTRY, j->current_file->current_offset, &o);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *item = NULL;
                unsigned long long ll;
                sd_id128_t id;
                int k = 0;

                r = extract_first_word(&cursor, &item, ";", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;

                if (r == 0)
                        break;

                if (strlen(item) < 2 || item[1] != '=')
                        return -EINVAL;

                switch (item[0]) {

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
        assert_return(!journal_origin_changed(j), -ECHILD);

        detach_location(j);

        j->current_location = (Location) {
                .type = LOCATION_SEEK,
                .boot_id = boot_id,
                .monotonic = usec,
                .monotonic_set = true,
        };

        return 0;
}

_public_ int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        detach_location(j);

        j->current_location = (Location) {
                .type = LOCATION_SEEK,
                .realtime = usec,
                .realtime_set = true,
        };

        return 0;
}

_public_ int sd_journal_seek_head(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        detach_location(j);

        j->current_location = (Location) {
                .type = LOCATION_HEAD,
        };

        return 0;
}

_public_ int sd_journal_seek_tail(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        detach_location(j);

        j->current_location = (Location) {
                .type = LOCATION_TAIL,
        };

        return 0;
}

static void check_network(sd_journal *j, int fd) {
        assert(j);

        if (j->on_network)
                return;

        j->on_network = fd_is_network_fs(fd);
}

static bool file_has_type_prefix(const char *prefix, const char *filename) {
        const char *full, *tilded, *atted;

        full = strjoina(prefix, ".journal");
        tilded = strjoina(full, "~");
        atted = strjoina(prefix, "@");

        return STR_IN_SET(filename, full, tilded) ||
               startswith(filename, atted);
}

static bool file_type_wanted(int flags, const char *filename) {
        assert(filename);

        if (!ENDSWITH_SET(filename, ".journal", ".journal~"))
                return false;

        /* no flags set → every type is OK */
        if (!(flags & (SD_JOURNAL_SYSTEM | SD_JOURNAL_CURRENT_USER)))
                return true;

        if (FLAGS_SET(flags, SD_JOURNAL_CURRENT_USER)) {
                char prefix[5 + DECIMAL_STR_MAX(uid_t) + 1];

                xsprintf(prefix, "user-" UID_FMT, getuid());

                if (file_has_type_prefix(prefix, filename))
                        return true;

                /* If SD_JOURNAL_CURRENT_USER is specified and we are invoked under a system UID, then
                 * automatically enable SD_JOURNAL_SYSTEM too, because journald will actually put system user
                 * data into the system journal. */

                if (uid_for_system_journal(getuid()))
                        flags |= SD_JOURNAL_SYSTEM;
        }

        if (FLAGS_SET(flags, SD_JOURNAL_SYSTEM) && file_has_type_prefix("system", filename))
                return true;

        return false;
}

static bool path_has_prefix(sd_journal *j, const char *path, const char *prefix) {
        assert(j);
        assert(path);
        assert(prefix);

        if (j->toplevel_fd >= 0)
                return false;

        return path_startswith(path, prefix);
}

static void track_file_disposition(sd_journal *j, JournalFile *f) {
        assert(j);
        assert(f);

        if (!j->has_runtime_files && path_has_prefix(j, f->path, "/run"))
                j->has_runtime_files = true;
        else if (!j->has_persistent_files && path_has_prefix(j, f->path, "/var"))
                j->has_persistent_files = true;
}

static const char *skip_slash(const char *p) {

        if (!p)
                return NULL;

        while (*p == '/')
                p++;

        return p;
}

static int add_any_file(
                sd_journal *j,
                int fd,
                const char *path) {

        _cleanup_close_ int our_fd = -EBADF;
        JournalFile *f;
        struct stat st;
        int r;

        assert(j);
        assert(fd >= 0 || path);

        if (fd < 0) {
                assert(path);  /* For gcc. */
                if (j->toplevel_fd >= 0)
                        /* If there's a top-level fd defined make the path relative, explicitly, since otherwise
                         * openat() ignores the first argument. */

                        fd = our_fd = openat(j->toplevel_fd, skip_slash(path), O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                else
                        fd = our_fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0) {
                        r = log_debug_errno(errno, "Failed to open journal file %s: %m", path);
                        goto error;
                }

                r = fd_nonblock(fd, false);
                if (r < 0) {
                        r = log_debug_errno(errno, "Failed to turn off O_NONBLOCK for %s: %m", path);
                        goto error;
                }
        }

        if (fstat(fd, &st) < 0) {
                r = log_debug_errno(errno, "Failed to fstat %s: %m", path ?: "fd");
                goto error;
        }

        r = stat_verify_regular(&st);
        if (r < 0) {
                log_debug_errno(r, "Refusing to open %s: %m", path ?: "fd");
                goto error;
        }

        if (path) {
                f = ordered_hashmap_get(j->files, path);
                if (f) {
                        if (stat_inode_same(&f->last_stat, &st)) {
                                /* We already track this file, under the same path and with the same
                                 * device/inode numbers, it's hence really the same. Mark this file as seen
                                 * in this generation. This is used to GC old files in process_q_overflow()
                                 * to detect journal files that are still there and discern them from those
                                 * which are gone. */

                                f->last_seen_generation = j->generation;
                                (void) journal_file_read_tail_timestamp(j, f);
                                return 0;
                        }

                        /* So we tracked a file under this name, but it has a different inode/device. In that
                         * case, it got replaced (probably due to rotation?), let's drop it hence from our
                         * list. */
                        remove_file_real(j, f);
                        f = NULL;
                }
        }

        if (ordered_hashmap_size(j->files) >= JOURNAL_FILES_MAX) {
                r = log_debug_errno(SYNTHETIC_ERRNO(ETOOMANYREFS),
                                    "Too many open journal files, not adding %s.", path ?: "fd");
                goto error;
        }

        r = journal_file_open(fd, path, O_RDONLY, 0, 0, 0, NULL, j->mmap, NULL, &f);
        if (r < 0) {
                log_debug_errno(r, "Failed to open journal file %s: %m", path ?: "from fd");
                goto error;
        }

        /* journal_file_dump(f); */

        /* journal_file_open() generates an replacement fname if necessary, so we can use f->path. */
        r = ordered_hashmap_put(j->files, f->path, f);
        if (r < 0) {
                f->close_fd = false; /* Make sure journal_file_close() doesn't close the caller's fd
                                      * (or our own). The caller or we will do that ourselves. */
                (void) journal_file_close(f);
                goto error;
        }

        TAKE_FD(our_fd); /* the fd is now owned by the JournalFile object */

        f->last_seen_generation = j->generation;

        track_file_disposition(j, f);
        check_network(j, f->fd);
        (void) journal_file_read_tail_timestamp(j, f);

        j->current_invalidate_counter++;

        log_debug("File %s added.", f->path);

        return 0;

error:
        (void) journal_put_error(j, r, path);   /* path==NULL is OK. */
        return r;
}

static int add_file_by_name(
                sd_journal *j,
                const char *prefix,
                const char *filename) {

        _cleanup_free_ char *path = NULL;

        assert(j);
        assert(prefix);
        assert(filename);

        if (j->no_new_files)
                return 0;

        if (!file_type_wanted(j->flags, filename))
                return 0;

        path = path_join(prefix, filename);
        if (!path)
                return -ENOMEM;

        return add_any_file(j, -1, path);
}

static int remove_file_by_name(
                sd_journal *j,
                const char *prefix,
                const char *filename) {

        _cleanup_free_ char *path = NULL;
        JournalFile *f;

        assert(j);
        assert(prefix);
        assert(filename);

        path = path_join(prefix, filename);
        if (!path)
                return -ENOMEM;

        f = ordered_hashmap_get(j->files, path);
        if (!f)
                return 0;

        remove_file_real(j, f);
        return 1;
}

static void remove_file_real(sd_journal *j, JournalFile *f) {
        assert(j);
        assert(f);

        (void) ordered_hashmap_remove(j->files, f->path);

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

        if (j->fields_file == f) {
                j->fields_file = ordered_hashmap_next(j->files, j->fields_file->path);
                j->fields_offset = 0;
                if (!j->fields_file)
                        j->fields_file_lost = true;
        }

        journal_file_unlink_newest_by_boot_id(j, f);
        (void) journal_file_close(f);

        j->current_invalidate_counter++;
}

static int dirname_is_machine_id(const char *fn) {
        sd_id128_t id, machine;
        const char *e;
        int r;

        /* Returns true if the specified directory name matches the local machine ID */

        r = sd_id128_get_machine(&machine);
        if (r < 0)
                return r;

        e = strchr(fn, '.');
        if (e) {
                const char *k;

                /* Looks like it has a namespace suffix. Verify that. */
                if (!log_namespace_name_valid(e + 1))
                        return false;

                k = strndupa_safe(fn, e - fn);
                r = sd_id128_from_string(k, &id);
        } else
                r = sd_id128_from_string(fn, &id);
        if (r < 0)
                return r;

        return sd_id128_equal(id, machine);
}

static int dirname_has_namespace(const char *fn, const char *namespace) {
        const char *e;

        /* Returns true if the specified directory name matches the specified namespace */

        e = strchr(fn, '.');
        if (e) {
                const char *k;

                if (!namespace)
                        return false;

                if (!streq(e + 1, namespace))
                        return false;

                k = strndupa_safe(fn, e - fn);
                return id128_is_valid(k);
        }

        if (namespace)
                return false;

        return id128_is_valid(fn);
}

static bool dirent_is_journal_file(const struct dirent *de) {
        assert(de);

        /* Returns true if the specified directory entry looks like a journal file we might be interested in */

        if (!IN_SET(de->d_type, DT_REG, DT_LNK, DT_UNKNOWN))
                return false;

        return endswith(de->d_name, ".journal") ||
                endswith(de->d_name, ".journal~");
}

static bool dirent_is_journal_subdir(const struct dirent *de) {
        const char *e, *n;
        assert(de);

        /* returns true if the specified directory entry looks like a directory that might contain journal
         * files we might be interested in, i.e. is either a 128-bit ID or a 128-bit ID suffixed by a
         * namespace. */

        if (!IN_SET(de->d_type, DT_DIR, DT_LNK, DT_UNKNOWN))
                return false;

        e = strchr(de->d_name, '.');
        if (!e)
                return id128_is_valid(de->d_name); /* No namespace */

        n = strndupa_safe(de->d_name, e - de->d_name);
        if (!id128_is_valid(n))
                return false;

        return log_namespace_name_valid(e + 1);
}

static int directory_open(sd_journal *j, const char *path, DIR **ret) {
        DIR *d;

        assert(j);
        assert(path);
        assert(ret);

        if (j->toplevel_fd < 0)
                d = opendir(path);
        else
                /* Open the specified directory relative to the toplevel fd. Enforce that the path specified is
                 * relative, by dropping the initial slash */
                d = xopendirat(j->toplevel_fd, skip_slash(path), 0);
        if (!d)
                return -errno;

        *ret = d;
        return 0;
}

static int add_directory(sd_journal *j, const char *prefix, const char *dirname);

static void directory_enumerate(sd_journal *j, Directory *m, DIR *d) {
        assert(j);
        assert(m);
        assert(d);

        FOREACH_DIRENT_ALL(de, d, goto fail) {
                if (dirent_is_journal_file(de))
                        (void) add_file_by_name(j, m->path, de->d_name);

                if (m->is_root && dirent_is_journal_subdir(de))
                        (void) add_directory(j, m->path, de->d_name);
        }

        return;
fail:
        log_debug_errno(errno, "Failed to enumerate directory %s, ignoring: %m", m->path);
}

static void directory_watch(sd_journal *j, Directory *m, int fd, uint32_t mask) {
        int r;

        assert(j);
        assert(m);
        assert(fd >= 0);

        /* Watch this directory if that's enabled and if it not being watched yet. */

        if (m->wd > 0) /* Already have a watch? */
                return;
        if (j->inotify_fd < 0) /* Not watching at all? */
                return;

        m->wd = inotify_add_watch_fd(j->inotify_fd, fd, mask);
        if (m->wd < 0) {
                log_debug_errno(errno, "Failed to watch journal directory '%s', ignoring: %m", m->path);
                return;
        }

        r = hashmap_put(j->directories_by_wd, INT_TO_PTR(m->wd), m);
        if (r == -EEXIST)
                log_debug_errno(r, "Directory '%s' already being watched under a different path, ignoring: %m", m->path);
        if (r < 0) {
                log_debug_errno(r, "Failed to add watch for journal directory '%s' to hashmap, ignoring: %m", m->path);
                (void) inotify_rm_watch(j->inotify_fd, m->wd);
                m->wd = -1;
        }
}

static int add_directory(
                sd_journal *j,
                const char *prefix,
                const char *dirname) {

        _cleanup_free_ char *path = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        Directory *m;
        int r, k;

        assert(j);
        assert(prefix);

        /* Adds a journal file directory to watch. If the directory is already tracked this updates the inotify watch
         * and reenumerates directory contents */

        path = path_join(prefix, dirname);
        if (!path) {
                r = -ENOMEM;
                goto fail;
        }

        log_debug("Considering directory '%s'.", path);

        /* We consider everything local that is in a directory for the local machine ID, or that is stored in /run */
        if ((j->flags & SD_JOURNAL_LOCAL_ONLY) &&
            !((dirname && dirname_is_machine_id(dirname) > 0) || path_has_prefix(j, path, "/run")))
                return 0;

        if (dirname &&
            (!(FLAGS_SET(j->flags, SD_JOURNAL_ALL_NAMESPACES) ||
               dirname_has_namespace(dirname, j->namespace) > 0 ||
               (FLAGS_SET(j->flags, SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE) && dirname_has_namespace(dirname, NULL) > 0))))
                return 0;

        r = directory_open(j, path, &d);
        if (r < 0) {
                log_debug_errno(r, "Failed to open directory '%s': %m", path);
                goto fail;
        }

        m = hashmap_get(j->directories_by_path, path);
        if (!m) {
                m = new(Directory, 1);
                if (!m) {
                        r = -ENOMEM;
                        goto fail;
                }

                *m = (Directory) {
                        .is_root = false,
                        .path = path,
                };

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        free(m);
                        r = -ENOMEM;
                        goto fail;
                }

                path = NULL; /* avoid freeing in cleanup */
                j->current_invalidate_counter++;

                log_debug("Directory %s added.", m->path);

        } else if (m->is_root)
                return 0; /* Don't 'downgrade' from root directory */

        m->last_seen_generation = j->generation;

        directory_watch(j, m, dirfd(d),
                        IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                        IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT|IN_MOVED_FROM|
                        IN_ONLYDIR);

        if (!j->no_new_files)
                directory_enumerate(j, m, d);

        check_network(j, dirfd(d));

        return 0;

fail:
        k = journal_put_error(j, r, path ?: prefix);
        if (k < 0)
                return k;

        return r;
}

static int add_root_directory(sd_journal *j, const char *p, bool missing_ok) {

        _cleanup_closedir_ DIR *d = NULL;
        Directory *m;
        int r, k;

        assert(j);

        /* Adds a root directory to our set of directories to use. If the root directory is already in the set, we
         * update the inotify logic, and renumerate the directory entries. This call may hence be called to initially
         * populate the set, as well as to update it later. */

        if (p) {
                /* If there's a path specified, use it. */

                log_debug("Considering root directory '%s'.", p);

                if ((j->flags & SD_JOURNAL_RUNTIME_ONLY) &&
                    !path_has_prefix(j, p, "/run"))
                        return -EINVAL;

                if (j->prefix)
                        p = strjoina(j->prefix, p);

                r = directory_open(j, p, &d);
                if (r == -ENOENT && missing_ok)
                        return 0;
                if (r < 0) {
                        log_debug_errno(r, "Failed to open root directory %s: %m", p);
                        goto fail;
                }
        } else {
                _cleanup_close_ int dfd = -EBADF;

                /* If there's no path specified, then we use the top-level fd itself. We duplicate the fd here, since
                 * opendir() will take possession of the fd, and close it, which we don't want. */

                p = "."; /* store this as "." in the directories hashmap */

                dfd = fcntl(j->toplevel_fd, F_DUPFD_CLOEXEC, 3);
                if (dfd < 0) {
                        r = -errno;
                        goto fail;
                }

                d = take_fdopendir(&dfd);
                if (!d) {
                        r = -errno;
                        goto fail;
                }

                rewinddir(d);
        }

        m = hashmap_get(j->directories_by_path, p);
        if (!m) {
                m = new0(Directory, 1);
                if (!m) {
                        r = -ENOMEM;
                        goto fail;
                }

                m->is_root = true;

                m->path = strdup(p);
                if (!m->path) {
                        free(m);
                        r = -ENOMEM;
                        goto fail;
                }

                if (hashmap_put(j->directories_by_path, m->path, m) < 0) {
                        free(m->path);
                        free(m);
                        r = -ENOMEM;
                        goto fail;
                }

                j->current_invalidate_counter++;

                log_debug("Root directory %s added.", m->path);

        } else if (!m->is_root)
                return 0;

        directory_watch(j, m, dirfd(d),
                        IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB|IN_DELETE|
                        IN_ONLYDIR);

        if (!j->no_new_files)
                directory_enumerate(j, m, d);

        check_network(j, dirfd(d));

        return 0;

fail:
        k = journal_put_error(j, r, p);
        if (k < 0)
                return k;

        return r;
}

static void remove_directory(sd_journal *j, Directory *d) {
        assert(j);

        if (d->wd > 0) {
                hashmap_remove(j->directories_by_wd, INT_TO_PTR(d->wd));

                if (j->inotify_fd >= 0)
                        (void) inotify_rm_watch(j->inotify_fd, d->wd);
        }

        hashmap_remove(j->directories_by_path, d->path);

        if (d->is_root)
                log_debug("Root directory %s removed.", d->path);
        else
                log_debug("Directory %s removed.", d->path);

        free(d->path);
        free(d);
}

static int add_search_paths(sd_journal *j) {

        static const char search_paths[] =
                "/run/log/journal\0"
                "/var/log/journal\0";

        assert(j);

        /* We ignore most errors here, since the idea is to only open
         * what's actually accessible, and ignore the rest. */

        NULSTR_FOREACH(p, search_paths)
                (void) add_root_directory(j, p, true);

        if (!(j->flags & SD_JOURNAL_LOCAL_ONLY))
                (void) add_root_directory(j, "/var/log/journal/remote", true);

        return 0;
}

static int add_current_paths(sd_journal *j) {
        JournalFile *f;

        assert(j);
        assert(j->no_new_files);

        /* Simply adds all directories for files we have open as directories. We don't expect errors here, so we
         * treat them as fatal. */

        ORDERED_HASHMAP_FOREACH(f, j->files) {
                _cleanup_free_ char *dir = NULL;
                int r;

                r = path_extract_directory(f->path, &dir);
                if (r < 0)
                        return r;

                r = add_directory(j, dir, NULL);
                if (r < 0)
                        return r;
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

        return hashmap_ensure_allocated(&j->directories_by_wd, NULL);
}

static sd_journal *journal_new(int flags, const char *path, const char *namespace) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;

        j = new(sd_journal, 1);
        if (!j)
                return NULL;

        *j = (sd_journal) {
                .origin_id = origin_id_query(),
                .toplevel_fd = -EBADF,
                .inotify_fd = -EBADF,
                .flags = flags,
                .data_threshold = DEFAULT_DATA_THRESHOLD,
        };

        if (path) {
                char *t;

                t = strdup(path);
                if (!t)
                        return NULL;

                if (flags & SD_JOURNAL_OS_ROOT)
                        j->prefix = t;
                else
                        j->path = t;
        }

        if (namespace) {
                j->namespace = strdup(namespace);
                if (!j->namespace)
                        return NULL;
        }

        j->files = ordered_hashmap_new(&path_hash_ops);
        if (!j->files)
                return NULL;

        j->files_cache = ordered_hashmap_iterated_cache_new(j->files);
        j->directories_by_path = hashmap_new(&path_hash_ops);
        j->mmap = mmap_cache_new();
        if (!j->files_cache || !j->directories_by_path || !j->mmap)
                return NULL;

        return TAKE_PTR(j);
}

#define OPEN_ALLOWED_FLAGS                              \
        (SD_JOURNAL_LOCAL_ONLY |                        \
         SD_JOURNAL_RUNTIME_ONLY |                      \
         SD_JOURNAL_SYSTEM |                            \
         SD_JOURNAL_CURRENT_USER |                      \
         SD_JOURNAL_ALL_NAMESPACES |                    \
         SD_JOURNAL_INCLUDE_DEFAULT_NAMESPACE |         \
         SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_namespace(sd_journal **ret, const char *namespace, int flags) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return((flags & ~OPEN_ALLOWED_FLAGS) == 0, -EINVAL);

        j = journal_new(flags, NULL, namespace);
        if (!j)
                return -ENOMEM;

        r = add_search_paths(j);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(j);
        return 0;
}

_public_ int sd_journal_open(sd_journal **ret, int flags) {
        return sd_journal_open_namespace(ret, NULL, flags);
}

#define OPEN_CONTAINER_ALLOWED_FLAGS                    \
        (SD_JOURNAL_LOCAL_ONLY |                        \
         SD_JOURNAL_SYSTEM |                            \
         SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_container(sd_journal **ret, const char *machine, int flags) {
        _cleanup_free_ char *root = NULL, *class = NULL;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        char *p;
        int r;

        /* This is deprecated, people should use machined's OpenMachineRootDirectory() call instead in
         * combination with sd_journal_open_directory_fd(). */

        assert_return(machine, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return((flags & ~OPEN_CONTAINER_ALLOWED_FLAGS) == 0, -EINVAL);
        assert_return(hostname_is_valid(machine, 0), -EINVAL);

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(NULL, p,
                           "ROOT", &root,
                           "CLASS", &class);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!root)
                return -ENODATA;

        if (!streq_ptr(class, "container"))
                return -EIO;

        j = journal_new(flags, root, NULL);
        if (!j)
                return -ENOMEM;

        r = add_search_paths(j);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(j);
        return 0;
}

#define OPEN_DIRECTORY_ALLOWED_FLAGS                    \
        (SD_JOURNAL_OS_ROOT |                           \
         SD_JOURNAL_SYSTEM |                            \
         SD_JOURNAL_CURRENT_USER |                      \
         SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_directory(sd_journal **ret, const char *path, int flags) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(path, -EINVAL);
        assert_return((flags & ~OPEN_DIRECTORY_ALLOWED_FLAGS) == 0, -EINVAL);

        j = journal_new(flags, path, NULL);
        if (!j)
                return -ENOMEM;

        if (flags & SD_JOURNAL_OS_ROOT)
                r = add_search_paths(j);
        else
                r = add_root_directory(j, path, false);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(j);
        return 0;
}

#define OPEN_FILES_ALLOWED_FLAGS                        \
        (SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_files(sd_journal **ret, const char **paths, int flags) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return((flags & ~OPEN_FILES_ALLOWED_FLAGS) == 0, -EINVAL);

        j = journal_new(flags, NULL, NULL);
        if (!j)
                return -ENOMEM;

        STRV_FOREACH(path, paths) {
                r = add_any_file(j, -1, *path);
                if (r < 0)
                        return r;
        }

        j->no_new_files = true;

        *ret = TAKE_PTR(j);
        return 0;
}

#define OPEN_DIRECTORY_FD_ALLOWED_FLAGS                 \
        (SD_JOURNAL_OS_ROOT |                           \
         SD_JOURNAL_SYSTEM |                            \
         SD_JOURNAL_CURRENT_USER |                      \
         SD_JOURNAL_TAKE_DIRECTORY_FD |                 \
         SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_directory_fd(sd_journal **ret, int fd, int flags) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        struct stat st;
        bool take_fd;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return((flags & ~OPEN_DIRECTORY_FD_ALLOWED_FLAGS) == 0, -EINVAL);

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISDIR(st.st_mode))
                return -EBADFD;

        take_fd = FLAGS_SET(flags, SD_JOURNAL_TAKE_DIRECTORY_FD);
        j = journal_new(flags & ~SD_JOURNAL_TAKE_DIRECTORY_FD, NULL, NULL);
        if (!j)
                return -ENOMEM;

        j->toplevel_fd = fd;

        if (flags & SD_JOURNAL_OS_ROOT)
                r = add_search_paths(j);
        else
                r = add_root_directory(j, NULL, false);
        if (r < 0)
                return r;

        SET_FLAG(j->flags, SD_JOURNAL_TAKE_DIRECTORY_FD, take_fd);

        *ret = TAKE_PTR(j);
        return 0;
}

#define OPEN_FILES_FD_ALLOWED_FLAGS                        \
        (SD_JOURNAL_READ_TAIL_TIMESTAMP_ONCE)

_public_ int sd_journal_open_files_fd(sd_journal **ret, int fds[], unsigned n_fds, int flags) {
        JournalFile *f;
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(n_fds > 0, -EBADF);
        assert_return((flags & ~OPEN_FILES_FD_ALLOWED_FLAGS) == 0, -EINVAL);

        j = journal_new(flags, NULL, NULL);
        if (!j)
                return -ENOMEM;

        for (unsigned i = 0; i < n_fds; i++) {
                struct stat st;

                if (fds[i] < 0) {
                        r = -EBADF;
                        goto fail;
                }

                if (fstat(fds[i], &st) < 0) {
                        r = -errno;
                        goto fail;
                }

                r = stat_verify_regular(&st);
                if (r < 0)
                        goto fail;

                r = add_any_file(j, fds[i], NULL);
                if (r < 0)
                        goto fail;
        }

        j->no_new_files = true;
        j->no_inotify = true;

        *ret = TAKE_PTR(j);
        return 0;

fail:
        /* If we fail, make sure we don't take possession of the files we managed to make use of successfully, and they
         * remain open */
        ORDERED_HASHMAP_FOREACH(f, j->files)
                f->close_fd = false;

        return r;
}

_public_ void sd_journal_close(sd_journal *j) {
        Directory *d;

        if (!j || journal_origin_changed(j))
                return;

        journal_clear_newest_by_boot_id(j);

        sd_journal_flush_matches(j);

        ordered_hashmap_free_with_destructor(j->files, journal_file_close);
        iterated_cache_free(j->files_cache);

        while ((d = hashmap_first(j->directories_by_path)))
                remove_directory(j, d);

        while ((d = hashmap_first(j->directories_by_wd)))
                remove_directory(j, d);

        hashmap_free(j->directories_by_path);
        hashmap_free(j->directories_by_wd);

        if (FLAGS_SET(j->flags, SD_JOURNAL_TAKE_DIRECTORY_FD))
                safe_close(j->toplevel_fd);

        safe_close(j->inotify_fd);

        if (j->mmap) {
                mmap_cache_stats_log_debug(j->mmap);
                mmap_cache_unref(j->mmap);
        }

        hashmap_free_free(j->errors);

        free(j->path);
        free(j->prefix);
        free(j->namespace);
        free(j->unique_field);
        free(j->fields_buffer);
        free(j);
}

static int journal_file_read_tail_timestamp(sd_journal *j, JournalFile *f) {
        uint64_t offset, mo, rt;
        sd_id128_t id;
        ObjectType type;
        Object *o;
        int r;

        assert(j);
        assert(f);
        assert(f->header);

        /* Tries to read the timestamp of the most recently written entry. */

        if (f->header->state == f->newest_state &&
            f->header->state == STATE_ARCHIVED &&
            f->newest_entry_offset != 0)
                return 0; /* We have already read archived file. */

        if (JOURNAL_HEADER_CONTAINS(f->header, tail_entry_offset)) {
                offset = le64toh(READ_NOW(f->header->tail_entry_offset));
                type = OBJECT_ENTRY;
        } else {
                offset = le64toh(READ_NOW(f->header->tail_object_offset));
                type = OBJECT_UNUSED;
        }
        if (offset == 0)
                return -ENODATA; /* not a single object/entry, hence no tail timestamp */
        if (offset == f->newest_entry_offset)
                return 0; /* No new entry is added after we read last time. */

        /* Move to the last object in the journal file, in the hope it is an entry (which it usually will
         * be). If we lack the "tail_entry_offset" field in the header, we specify the type as OBJECT_UNUSED
         * here, since we cannot be sure what the last object will be, and want no noisy logging if it isn't
         * an entry. We instead check after figuring out the pointer. */
        r = journal_file_move_to_object(f, type, offset, &o);
        if (r < 0) {
                log_debug_errno(r, "Failed to move to last object in journal file, ignoring: %m");
                o = NULL;
                offset = 0;
        }
        if (o && o->object.type == OBJECT_ENTRY) {
                /* Yay, last object is an entry, let's use the data. */
                id = o->entry.boot_id;
                mo = le64toh(o->entry.monotonic);
                rt = le64toh(o->entry.realtime);
        } else {
                /* So the object is not an entry or we couldn't access it? In that case, let's read the most
                 * recent entry timestamps from the header. It's equally good. Unfortunately though, in old
                 * versions of the journal the boot ID in the header doesn't have to match the monotonic
                 * timestamp of the header. Let's check the header flag that indicates whether this strictly
                 * matches first hence, before using the data. */

                if (JOURNAL_HEADER_TAIL_ENTRY_BOOT_ID(f->header) && f->header->state == STATE_ARCHIVED) {
                        mo = le64toh(f->header->tail_entry_monotonic);
                        rt = le64toh(f->header->tail_entry_realtime);
                        id = f->header->tail_entry_boot_id;
                        offset = UINT64_MAX;
                } else {
                        /* Otherwise let's find the last entry manually (this possibly means traversing the
                         * chain of entry arrays, till the end */
                        r = journal_file_next_entry(f, 0, DIRECTION_UP, &o, offset == 0 ? &offset : NULL);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -ENODATA;

                        id = o->entry.boot_id;
                        mo = le64toh(o->entry.monotonic);
                        rt = le64toh(o->entry.realtime);
                }
        }

        if (mo > rt) /* monotonic clock is further ahead than realtime? that's weird, refuse to use the data */
                return -ENODATA;

        if (offset == f->newest_entry_offset) {
                /* Cached data and the current one should be equivalent. */
                assert(sd_id128_equal(f->newest_boot_id, id));
                assert(f->newest_monotonic_usec == mo);
                assert(f->newest_realtime_usec == rt);
                assert(sd_id128_equal(f->newest_machine_id, f->header->machine_id));

                return 0; /* No new entry is added after we read last time. */
        }

        if (!sd_id128_equal(f->newest_boot_id, id))
                journal_file_unlink_newest_by_boot_id(j, f);

        f->newest_boot_id = id;
        f->newest_monotonic_usec = mo;
        f->newest_realtime_usec = rt;
        f->newest_machine_id = f->header->machine_id;
        f->newest_entry_offset = offset;
        f->newest_state = f->header->state;

        r = journal_file_reshuffle_newest_by_boot_id(j, f);
        if (r < 0)
                return r;

        return 1; /* Updated. */
}

_public_ int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret) {
        JournalFile *f;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;
        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        uint64_t t = le64toh(o->entry.realtime);
        if (!VALID_REALTIME(t))
                return -EBADMSG;

        if (ret)
                *ret = t;

        return 0;
}

_public_ int sd_journal_get_monotonic_usec(sd_journal *j, uint64_t *ret, sd_id128_t *ret_boot_id) {
        JournalFile *f;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

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
                sd_id128_t id;

                r = sd_id128_get_boot(&id);
                if (r < 0)
                        return r;

                if (!sd_id128_equal(id, o->entry.boot_id))
                        return -ESTALE;
        }

        uint64_t t = le64toh(o->entry.monotonic);
        if (!VALID_MONOTONIC(t))
                return -EBADMSG;

        if (ret)
                *ret = t;

        return 0;
}

_public_ int sd_journal_get_seqnum(
                sd_journal *j,
                uint64_t *ret_seqnum,
                sd_id128_t *ret_seqnum_id) {

        JournalFile *f;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        f = j->current_file;
        if (!f)
                return -EADDRNOTAVAIL;

        if (f->current_offset <= 0)
                return -EADDRNOTAVAIL;

        r = journal_file_move_to_object(f, OBJECT_ENTRY, f->current_offset, &o);
        if (r < 0)
                return r;

        if (ret_seqnum_id)
                *ret_seqnum_id = f->header->seqnum_id;
        if (ret_seqnum)
                *ret_seqnum = le64toh(o->entry.seqnum);

        return 0;
}

static bool field_is_valid(const char *field) {
        assert(field);

        if (isempty(field))
                return false;

        if (startswith(field, "__"))
                return false;

        for (const char *p = field; *p; p++) {

                if (*p == '_')
                        continue;

                if (*p >= 'A' && *p <= 'Z')
                        continue;

                if (ascii_isdigit(*p))
                        continue;

                return false;
        }

        return true;
}

_public_ int sd_journal_get_data(sd_journal *j, const char *field, const void **data, size_t *size) {
        JournalFile *f;
        size_t field_length;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
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

        uint64_t n = journal_file_entry_n_items(f, o);
        for (uint64_t i = 0; i < n; i++) {
                uint64_t p;
                void *d;
                size_t l;

                p = journal_file_entry_item_object_offset(f, o, i);
                r = journal_file_data_payload(f, NULL, p, field, field_length, j->data_threshold, &d, &l);
                if (r == 0)
                        continue;
                if (IN_SET(r, -EADDRNOTAVAIL, -EBADMSG)) {
                        log_debug_errno(r, "Entry item %"PRIu64" data object is bad, skipping over it: %m", i);
                        continue;
                }
                if (r < 0)
                        return r;

                *data = d;
                *size = l;

                return 0;
        }

        return -ENOENT;
}

_public_ int sd_journal_enumerate_data(sd_journal *j, const void **data, size_t *size) {
        JournalFile *f;
        Object *o;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
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

        for (uint64_t n = journal_file_entry_n_items(f, o); j->current_field < n; j->current_field++) {
                uint64_t p;
                void *d;
                size_t l;

                p = journal_file_entry_item_object_offset(f, o, j->current_field);
                r = journal_file_data_payload(f, NULL, p, NULL, 0, j->data_threshold, &d, &l);
                if (IN_SET(r, -EADDRNOTAVAIL, -EBADMSG)) {
                        log_debug_errno(r, "Entry item %"PRIu64" data object is bad, skipping over it: %m", j->current_field);
                        continue;
                }
                if (r < 0)
                        return r;
                assert(r > 0);

                *data = d;
                *size = l;

                j->current_field++;

                return 1;
        }

        return 0;
}

_public_ int sd_journal_enumerate_available_data(sd_journal *j, const void **data, size_t *size) {
        for (;;) {
                int r;

                r = sd_journal_enumerate_data(j, data, size);
                if (r >= 0)
                        return r;
                if (!JOURNAL_ERRNO_IS_UNAVAILABLE_FIELD(r))
                        return r;
                j->current_field++; /* Try with the next field */
        }
}

_public_ void sd_journal_restart_data(sd_journal *j) {
        if (!j || journal_origin_changed(j))
                return;

        j->current_field = 0;
}

static int reiterate_all_paths(sd_journal *j) {
        assert(j);

        if (j->no_new_files)
                return add_current_paths(j);

        if (j->flags & SD_JOURNAL_OS_ROOT)
                return add_search_paths(j);

        if (j->toplevel_fd >= 0)
                return add_root_directory(j, NULL, false);

        if (j->path)
                return add_root_directory(j, j->path, true);

        return add_search_paths(j);
}

_public_ int sd_journal_get_fd(sd_journal *j) {
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        if (j->no_inotify)
                return -EMEDIUMTYPE;

        if (j->inotify_fd >= 0)
                return j->inotify_fd;

        r = allocate_inotify(j);
        if (r < 0)
                return r;

        log_debug("Reiterating files to get inotify watches established.");

        /* Iterate through all dirs again, to add them to the inotify */
        r = reiterate_all_paths(j);
        if (r < 0)
                return r;

        return j->inotify_fd;
}

_public_ int sd_journal_get_events(sd_journal *j) {
        int fd;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        fd = sd_journal_get_fd(j);
        if (fd < 0)
                return fd;

        return POLLIN;
}

_public_ int sd_journal_get_timeout(sd_journal *j, uint64_t *timeout_usec) {
        int fd;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(timeout_usec, -EINVAL);

        fd = sd_journal_get_fd(j);
        if (fd < 0)
                return fd;

        if (!j->on_network) {
                *timeout_usec = UINT64_MAX;
                return 0;
        }

        /* If we are on the network we need to regularly check for
         * changes manually */

        *timeout_usec = j->last_process_usec + JOURNAL_FILES_RECHECK_USEC;
        return 1;
}

static void process_q_overflow(sd_journal *j) {
        JournalFile *f;
        Directory *m;

        assert(j);

        /* When the inotify queue overruns we need to enumerate and re-validate all journal files to bring our list
         * back in sync with what's on disk. For this we pick a new generation counter value. It'll be assigned to all
         * journal files we encounter. All journal files and all directories that don't carry it after reenumeration
         * are subject for unloading. */

        log_debug("Inotify queue overrun, reiterating everything.");

        j->generation++;
        (void) reiterate_all_paths(j);

        ORDERED_HASHMAP_FOREACH(f, j->files) {

                if (f->last_seen_generation == j->generation)
                        continue;

                log_debug("File '%s' hasn't been seen in this enumeration, removing.", f->path);
                remove_file_real(j, f);
        }

        HASHMAP_FOREACH(m, j->directories_by_path) {

                if (m->last_seen_generation == j->generation)
                        continue;

                if (m->is_root) /* Never GC root directories */
                        continue;

                log_debug("Directory '%s' hasn't been seen in this enumeration, removing.", f->path);
                remove_directory(j, m);
        }

        log_debug("Reiteration complete.");
}

static void process_inotify_event(sd_journal *j, const struct inotify_event *e) {
        Directory *d;

        assert(j);
        assert(e);

        if (e->mask & IN_Q_OVERFLOW) {
                process_q_overflow(j);
                return;
        }

        /* Is this a subdirectory we watch? */
        d = hashmap_get(j->directories_by_wd, INT_TO_PTR(e->wd));
        if (d) {
                if (!(e->mask & IN_ISDIR) && e->len > 0 &&
                    (endswith(e->name, ".journal") ||
                     endswith(e->name, ".journal~"))) {

                        /* Event for a journal file */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB))
                                (void) add_file_by_name(j, d->path, e->name);
                        else if (e->mask & (IN_DELETE|IN_MOVED_FROM|IN_UNMOUNT))
                                (void) remove_file_by_name(j, d->path, e->name);

                } else if (!d->is_root && e->len == 0) {

                        /* Event for a subdirectory */

                        if (e->mask & (IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT))
                                remove_directory(j, d);

                } else if (d->is_root && (e->mask & IN_ISDIR) && e->len > 0 && id128_is_valid(e->name)) {

                        /* Event for root directory */

                        if (e->mask & (IN_CREATE|IN_MOVED_TO|IN_MODIFY|IN_ATTRIB))
                                (void) add_directory(j, d->path, e->name);
                }

                return;
        }

        if (e->mask & IN_IGNORED)
                return;

        log_debug("Unexpected inotify event.");
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
        assert_return(!journal_origin_changed(j), -ECHILD);

        if (j->inotify_fd < 0) /* We have no inotify fd yet? Then there's noting to process. */
                return 0;

        j->last_process_usec = now(CLOCK_MONOTONIC);
        j->last_invalidate_counter = j->current_invalidate_counter;

        for (;;) {
                union inotify_event_buffer buffer;
                ssize_t l;

                l = read(j->inotify_fd, &buffer, sizeof(buffer));
                if (l < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
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
        assert_return(!journal_origin_changed(j), -ECHILD);

        if (j->inotify_fd < 0) {
                JournalFile *f;

                /* This is the first invocation, hence create the inotify watch */
                r = sd_journal_get_fd(j);
                if (r < 0)
                        return r;

                /* Server might have done some vacuuming while we weren't watching. Get rid of the deleted
                 * files now so they don't stay around indefinitely. */
                ORDERED_HASHMAP_FOREACH(f, j->files) {
                        r = journal_file_fstat(f);
                        if (r == -EIDRM)
                                remove_file_real(j, f);
                        else if (r < 0)
                                log_debug_errno(r, "Failed to fstat() journal file '%s', ignoring: %m", f->path);
                }

                /* The journal might have changed since the context object was created and we weren't
                 * watching before, hence don't wait for anything, and return immediately. */
                return determine_change(j);
        }

        r = sd_journal_get_timeout(j, &t);
        if (r < 0)
                return r;

        if (t != UINT64_MAX) {
                t = usec_sub_unsigned(t, now(CLOCK_MONOTONIC));

                if (timeout_usec == UINT64_MAX || timeout_usec > t)
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
        JournalFile *f;
        bool first = true;
        uint64_t fmin = 0, tmax = 0;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(from || to, -EINVAL);
        assert_return(from != to, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files) {
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

_public_ int sd_journal_get_cutoff_monotonic_usec(
                sd_journal *j,
                sd_id128_t boot_id,
                uint64_t *ret_from,
                uint64_t *ret_to) {

        uint64_t from = UINT64_MAX, to = UINT64_MAX;
        bool found = false;
        JournalFile *f;
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(ret_from != ret_to, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files) {
                usec_t ff, tt;

                r = journal_file_get_cutoff_monotonic_usec(f, boot_id, &ff, &tt);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (found) {
                        from = MIN(ff, from);
                        to = MAX(tt, to);
                } else {
                        from = ff;
                        to = tt;
                        found = true;
                }
        }

        if (ret_from)
                *ret_from = from;
        if (ret_to)
                *ret_to = to;

        return found;
}

void journal_print_header(sd_journal *j) {
        JournalFile *f;
        bool newline = false;

        assert(j);

        ORDERED_HASHMAP_FOREACH(f, j->files) {
                if (newline)
                        putchar('\n');
                else
                        newline = true;

                journal_file_print_header(f);
        }
}

_public_ int sd_journal_get_usage(sd_journal *j, uint64_t *ret) {
        JournalFile *f;
        uint64_t sum = 0;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(ret, -EINVAL);

        ORDERED_HASHMAP_FOREACH(f, j->files) {
                struct stat st;
                uint64_t b;

                if (fstat(f->fd, &st) < 0)
                        return -errno;

                b = (uint64_t) st.st_blocks;
                if (b > UINT64_MAX / 512)
                        return -EOVERFLOW;
                b *= 512;

                if (sum > UINT64_MAX - b)
                        return -EOVERFLOW;
                sum += b;
        }

        *ret = sum;
        return 0;
}

_public_ int sd_journal_query_unique(sd_journal *j, const char *field) {
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        if (!field_is_valid(field))
                return -EINVAL;

        r = free_and_strdup(&j->unique_field, field);
        if (r < 0)
                return r;

        j->unique_file = NULL;
        j->unique_offset = 0;
        j->unique_file_lost = false;

        return 0;
}

_public_ int sd_journal_enumerate_unique(
                sd_journal *j,
                const void **ret_data,
                size_t *ret_size) {

        size_t k;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
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
                Object *o;
                void *odata;
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

                r = journal_file_move_to_object(j->unique_file, OBJECT_DATA, j->unique_offset, &o);
                if (r < 0)
                        return r;

                /* Let's pin the data object, so we can look at it at the same time as one on another file. */
                r = journal_file_pin_object(j->unique_file, o);
                if (r < 0)
                        return r;

                r = journal_file_data_payload(j->unique_file, o, j->unique_offset, NULL, 0,
                                              j->data_threshold, &odata, &ol);
                if (r < 0)
                        return r;

                /* Check if we have at least the field name and "=". */
                if (ol <= k)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "%s:offset " OFSfmt ": object has size %zu, expected at least %zu",
                                               j->unique_file->path,
                                               j->unique_offset, ol, k + 1);

                if (memcmp(odata, j->unique_field, k) != 0 || ((const char*) odata)[k] != '=')
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "%s:offset " OFSfmt ": object does not start with \"%s=\"",
                                               j->unique_file->path,
                                               j->unique_offset,
                                               j->unique_field);

                /* OK, now let's see if we already returned this data object by checking if it exists in the
                 * earlier traversed files. */
                found = false;
                ORDERED_HASHMAP_FOREACH(of, j->files) {
                        if (of == j->unique_file)
                                break;

                        /* Skip this file it didn't have any fields indexed */
                        if (JOURNAL_HEADER_CONTAINS(of->header, n_fields) && le64toh(of->header->n_fields) <= 0)
                                continue;

                        /* We can reuse the hash from our current file only on old-style journal files
                         * without keyed hashes. On new-style files we have to calculate the hash anew, to
                         * take the per-file hash seed into consideration. */
                        if (!JOURNAL_HEADER_KEYED_HASH(j->unique_file->header) && !JOURNAL_HEADER_KEYED_HASH(of->header))
                                r = journal_file_find_data_object_with_hash(of, odata, ol, le64toh(o->data.hash), NULL, NULL);
                        else
                                r = journal_file_find_data_object(of, odata, ol, NULL, NULL);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                found = true;
                                break;
                        }
                }

                if (found)
                        continue;

                *ret_data = odata;
                *ret_size = ol;

                return 1;
        }
}

_public_ int sd_journal_enumerate_available_unique(sd_journal *j, const void **data, size_t *size) {
        for (;;) {
                int r;

                r = sd_journal_enumerate_unique(j, data, size);
                if (r >= 0)
                        return r;
                if (!JOURNAL_ERRNO_IS_UNAVAILABLE_FIELD(r))
                        return r;
                /* Try with the next field. sd_journal_enumerate_unique() modifies state, so on the next try
                 * we will access the next field. */
        }
}

_public_ void sd_journal_restart_unique(sd_journal *j) {
        if (!j || journal_origin_changed(j))
                return;

        j->unique_file = NULL;
        j->unique_offset = 0;
        j->unique_file_lost = false;
}

_public_ int sd_journal_enumerate_fields(sd_journal *j, const char **field) {
        int r;

        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(field, -EINVAL);

        if (!j->fields_file) {
                if (j->fields_file_lost)
                        return 0;

                j->fields_file = ordered_hashmap_first(j->files);
                if (!j->fields_file)
                        return 0;

                j->fields_hash_table_index = 0;
                j->fields_offset = 0;
        }

        for (;;) {
                JournalFile *f, *of;
                uint64_t m;
                Object *o;
                size_t sz;
                bool found;

                f = j->fields_file;

                if (j->fields_offset == 0) {
                        bool eof = false;

                        /* We are not yet positioned at any field. Let's pick the first one */
                        r = journal_file_map_field_hash_table(f);
                        if (r < 0)
                                return r;

                        m = le64toh(f->header->field_hash_table_size) / sizeof(HashItem);
                        for (;;) {
                                if (j->fields_hash_table_index >= m) {
                                        /* Reached the end of the hash table, go to the next file. */
                                        eof = true;
                                        break;
                                }

                                j->fields_offset = le64toh(f->field_hash_table[j->fields_hash_table_index].head_hash_offset);

                                if (j->fields_offset != 0)
                                        break;

                                /* Empty hash table bucket, go to next one */
                                j->fields_hash_table_index++;
                        }

                        if (eof) {
                                /* Proceed with next file */
                                j->fields_file = ordered_hashmap_next(j->files, f->path);
                                if (!j->fields_file) {
                                        *field = NULL;
                                        return 0;
                                }

                                j->fields_offset = 0;
                                j->fields_hash_table_index = 0;
                                continue;
                        }

                } else {
                        /* We are already positioned at a field. If so, let's figure out the next field from it */

                        r = journal_file_move_to_object(f, OBJECT_FIELD, j->fields_offset, &o);
                        if (r < 0)
                                return r;

                        j->fields_offset = le64toh(o->field.next_hash_offset);
                        if (j->fields_offset == 0) {
                                /* Reached the end of the hash table chain */
                                j->fields_hash_table_index++;
                                continue;
                        }
                }

                /* We use OBJECT_UNUSED here, so that the iterator below doesn't remove our mmap window */
                r = journal_file_move_to_object(f, OBJECT_UNUSED, j->fields_offset, &o);
                if (r < 0)
                        return r;

                /* Because we used OBJECT_UNUSED above, we need to do our type check manually */
                if (o->object.type != OBJECT_FIELD)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "%s:offset " OFSfmt ": object has type %i, expected %i",
                                               f->path, j->fields_offset,
                                               o->object.type, OBJECT_FIELD);

                sz = le64toh(o->object.size) - offsetof(Object, field.payload);

                /* Let's see if we already returned this field name before. */
                found = false;
                ORDERED_HASHMAP_FOREACH(of, j->files) {
                        if (of == f)
                                break;

                        /* Skip this file it didn't have any fields indexed */
                        if (JOURNAL_HEADER_CONTAINS(of->header, n_fields) && le64toh(of->header->n_fields) <= 0)
                                continue;

                        if (!JOURNAL_HEADER_KEYED_HASH(f->header) && !JOURNAL_HEADER_KEYED_HASH(of->header))
                                r = journal_file_find_field_object_with_hash(of, o->field.payload, sz,
                                                                             le64toh(o->field.hash), NULL, NULL);
                        else
                                r = journal_file_find_field_object(of, o->field.payload, sz, NULL, NULL);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                found = true;
                                break;
                        }
                }

                if (found)
                        continue;

                /* Check if this is really a valid string containing no NUL byte */
                if (memchr(o->field.payload, 0, sz))
                        return -EBADMSG;

                if (j->data_threshold > 0 && sz > j->data_threshold)
                        sz = j->data_threshold;

                if (!GREEDY_REALLOC(j->fields_buffer, sz + 1))
                        return -ENOMEM;

                memcpy(j->fields_buffer, o->field.payload, sz);
                j->fields_buffer[sz] = 0;

                if (!field_is_valid(j->fields_buffer))
                        return -EBADMSG;

                *field = j->fields_buffer;
                return 1;
        }
}

_public_ void sd_journal_restart_fields(sd_journal *j) {
        if (!j || journal_origin_changed(j))
                return;

        j->fields_file = NULL;
        j->fields_hash_table_index = 0;
        j->fields_offset = 0;
        j->fields_file_lost = false;
}

_public_ int sd_journal_reliable_fd(sd_journal *j) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);

        return !j->on_network;
}

static char *lookup_field(const char *field, void *userdata) {
        sd_journal *j = ASSERT_PTR(userdata);
        const void *data;
        size_t size, d;
        int r;

        assert(field);

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
        assert_return(!journal_origin_changed(j), -ECHILD);
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

        r = catalog_get(secure_getenv("SYSTEMD_CATALOG") ?: CATALOG_DATABASE, id, &text);
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
        assert_return(!journal_origin_changed(j), -ECHILD);

        j->data_threshold = sz;
        return 0;
}

_public_ int sd_journal_get_data_threshold(sd_journal *j, size_t *sz) {
        assert_return(j, -EINVAL);
        assert_return(!journal_origin_changed(j), -ECHILD);
        assert_return(sz, -EINVAL);

        *sz = j->data_threshold;
        return 0;
}

_public_ int sd_journal_has_runtime_files(sd_journal *j) {
        assert_return(j, -EINVAL);

        return j->has_runtime_files;
}

_public_ int sd_journal_has_persistent_files(sd_journal *j) {
        assert_return(j, -EINVAL);

        return j->has_persistent_files;
}
