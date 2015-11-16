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
#include <string.h>

#include "alloc-util.h"
#include "hashmap.h"
#include "journald-rate-limit.h"
#include "list.h"
#include "random-util.h"
#include "string-util.h"
#include "util.h"

#define POOLS_MAX 5
#define BUCKETS_MAX 127
#define GROUPS_MAX 2047

static const int priority_map[] = {
        [LOG_EMERG]   = 0,
        [LOG_ALERT]   = 0,
        [LOG_CRIT]    = 0,
        [LOG_ERR]     = 1,
        [LOG_WARNING] = 2,
        [LOG_NOTICE]  = 3,
        [LOG_INFO]    = 3,
        [LOG_DEBUG]   = 4
};

typedef struct JournalRateLimitPool JournalRateLimitPool;
typedef struct JournalRateLimitGroup JournalRateLimitGroup;

struct JournalRateLimitPool {
        usec_t begin;
        unsigned num;
        unsigned suppressed;
};

struct JournalRateLimitGroup {
        JournalRateLimit *parent;

        char *id;
        JournalRateLimitPool pools[POOLS_MAX];
        uint64_t hash;

        LIST_FIELDS(JournalRateLimitGroup, bucket);
        LIST_FIELDS(JournalRateLimitGroup, lru);
};

struct JournalRateLimit {
        usec_t interval;
        unsigned burst;

        JournalRateLimitGroup* buckets[BUCKETS_MAX];
        JournalRateLimitGroup *lru, *lru_tail;

        unsigned n_groups;

        uint8_t hash_key[16];
};

JournalRateLimit *journal_rate_limit_new(usec_t interval, unsigned burst) {
        JournalRateLimit *r;

        assert(interval > 0 || burst == 0);

        r = new0(JournalRateLimit, 1);
        if (!r)
                return NULL;

        r->interval = interval;
        r->burst = burst;

        random_bytes(r->hash_key, sizeof(r->hash_key));

        return r;
}

static void journal_rate_limit_group_free(JournalRateLimitGroup *g) {
        assert(g);

        if (g->parent) {
                assert(g->parent->n_groups > 0);

                if (g->parent->lru_tail == g)
                        g->parent->lru_tail = g->lru_prev;

                LIST_REMOVE(lru, g->parent->lru, g);
                LIST_REMOVE(bucket, g->parent->buckets[g->hash % BUCKETS_MAX], g);

                g->parent->n_groups --;
        }

        free(g->id);
        free(g);
}

void journal_rate_limit_free(JournalRateLimit *r) {
        assert(r);

        while (r->lru)
                journal_rate_limit_group_free(r->lru);

        free(r);
}

_pure_ static bool journal_rate_limit_group_expired(JournalRateLimitGroup *g, usec_t ts) {
        unsigned i;

        assert(g);

        for (i = 0; i < POOLS_MAX; i++)
                if (g->pools[i].begin + g->parent->interval >= ts)
                        return false;

        return true;
}

static void journal_rate_limit_vacuum(JournalRateLimit *r, usec_t ts) {
        assert(r);

        /* Makes room for at least one new item, but drop all
         * expored items too. */

        while (r->n_groups >= GROUPS_MAX ||
               (r->lru_tail && journal_rate_limit_group_expired(r->lru_tail, ts)))
                journal_rate_limit_group_free(r->lru_tail);
}

static JournalRateLimitGroup* journal_rate_limit_group_new(JournalRateLimit *r, const char *id, usec_t ts) {
        JournalRateLimitGroup *g;
        struct siphash state;

        assert(r);
        assert(id);

        g = new0(JournalRateLimitGroup, 1);
        if (!g)
                return NULL;

        g->id = strdup(id);
        if (!g->id)
                goto fail;

        siphash24_init(&state, r->hash_key);
        string_hash_func(g->id, &state);
        g->hash = siphash24_finalize(&state);

        journal_rate_limit_vacuum(r, ts);

        LIST_PREPEND(bucket, r->buckets[g->hash % BUCKETS_MAX], g);
        LIST_PREPEND(lru, r->lru, g);
        if (!g->lru_next)
                r->lru_tail = g;
        r->n_groups ++;

        g->parent = r;
        return g;

fail:
        journal_rate_limit_group_free(g);
        return NULL;
}

static unsigned burst_modulate(unsigned burst, uint64_t available) {
        unsigned k;

        /* Modulates the burst rate a bit with the amount of available
         * disk space */

        k = u64log2(available);

        /* 1MB */
        if (k <= 20)
                return burst;

        burst = (burst * (k-20)) / 4;

        /*
         * Example:
         *
         *      <= 1MB = rate * 1
         *        16MB = rate * 2
         *       256MB = rate * 3
         *         4GB = rate * 4
         *        64GB = rate * 5
         *         1TB = rate * 6
         */

        return burst;
}

int journal_rate_limit_test(JournalRateLimit *r, const char *id, int priority, uint64_t available) {
        uint64_t h;
        JournalRateLimitGroup *g;
        JournalRateLimitPool *p;
        struct siphash state;
        unsigned burst;
        usec_t ts;

        assert(id);

        if (!r)
                return 1;

        if (r->interval == 0 || r->burst == 0)
                return 1;

        burst = burst_modulate(r->burst, available);

        ts = now(CLOCK_MONOTONIC);

        siphash24_init(&state, r->hash_key);
        string_hash_func(id, &state);
        h = siphash24_finalize(&state);
        g = r->buckets[h % BUCKETS_MAX];

        LIST_FOREACH(bucket, g, g)
                if (streq(g->id, id))
                        break;

        if (!g) {
                g = journal_rate_limit_group_new(r, id, ts);
                if (!g)
                        return -ENOMEM;
        }

        p = &g->pools[priority_map[priority]];

        if (p->begin <= 0) {
                p->suppressed = 0;
                p->num = 1;
                p->begin = ts;
                return 1;
        }

        if (p->begin + r->interval < ts) {
                unsigned s;

                s = p->suppressed;
                p->suppressed = 0;
                p->num = 1;
                p->begin = ts;

                return 1 + s;
        }

        if (p->num <= burst) {
                p->num++;
                return 1;
        }

        p->suppressed++;
        return 0;
}
