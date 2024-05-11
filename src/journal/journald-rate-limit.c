/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "hashmap.h"
#include "journald-rate-limit.h"
#include "list.h"
#include "logarithm.h"
#include "random-util.h"
#include "string-util.h"
#include "time-util.h"

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
        [LOG_DEBUG]   = 4,
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

        /* Interval is stored to keep track of when the group expires */
        usec_t interval;

        JournalRateLimitPool pools[POOLS_MAX];
        uint64_t hash;

        LIST_FIELDS(JournalRateLimitGroup, bucket);
        LIST_FIELDS(JournalRateLimitGroup, lru);
};

struct JournalRateLimit {

        JournalRateLimitGroup* buckets[BUCKETS_MAX];
        JournalRateLimitGroup *lru, *lru_tail;

        unsigned n_groups;

        uint8_t hash_key[16];
};

JournalRateLimit *journal_ratelimit_new(void) {
        JournalRateLimit *r;

        r = new0(JournalRateLimit, 1);
        if (!r)
                return NULL;

        random_bytes(r->hash_key, sizeof(r->hash_key));

        return r;
}

static JournalRateLimitGroup* journal_ratelimit_group_free(JournalRateLimitGroup *g) {
        if (!g)
                return NULL;

        if (g->parent) {
                assert(g->parent->n_groups > 0);

                if (g->parent->lru_tail == g)
                        g->parent->lru_tail = g->lru_prev;

                LIST_REMOVE(lru, g->parent->lru, g);
                LIST_REMOVE(bucket, g->parent->buckets[g->hash % BUCKETS_MAX], g);

                g->parent->n_groups--;
        }

        free(g->id);
        return mfree(g);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JournalRateLimitGroup*, journal_ratelimit_group_free);

void journal_ratelimit_free(JournalRateLimit *r) {
        assert(r);

        while (r->lru)
                journal_ratelimit_group_free(r->lru);

        free(r);
}

static bool journal_ratelimit_group_expired(JournalRateLimitGroup *g, usec_t ts) {
        assert(g);

        FOREACH_ELEMENT(p, g->pools)
                if (usec_add(p->begin, g->interval) >= ts)
                        return false;

        return true;
}

static void journal_ratelimit_vacuum(JournalRateLimit *r, usec_t ts) {
        assert(r);

        /* Makes room for at least one new item, but drop all expired items too. */

        while (r->n_groups >= GROUPS_MAX ||
               (r->lru_tail && journal_ratelimit_group_expired(r->lru_tail, ts)))
                journal_ratelimit_group_free(r->lru_tail);
}

static int journal_ratelimit_group_new(
                JournalRateLimit *rl,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        _cleanup_(journal_ratelimit_group_freep) JournalRateLimitGroup *g = NULL;

        assert(rl);
        assert(id);
        assert(ret);

        g = new0(JournalRateLimitGroup, 1);
        if (!g)
                return -ENOMEM;

        g->id = strdup(id);
        if (!g->id)
                return -ENOMEM;

        g->hash = siphash24_string(g->id, rl->hash_key);

        g->interval = interval;

        journal_ratelimit_vacuum(rl, ts);

        LIST_PREPEND(bucket, rl->buckets[g->hash % BUCKETS_MAX], g);
        LIST_PREPEND(lru, rl->lru, g);
        if (!g->lru_next)
                rl->lru_tail = g;
        rl->n_groups++;

        g->parent = rl;

        *ret = TAKE_PTR(g);
        return 0;
}

static int journal_ratelimit_group_acquire(
                JournalRateLimit *rl,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        JournalRateLimitGroup *head, *g = NULL;
        uint64_t h;

        assert(rl);
        assert(id);
        assert(ret);

        h = siphash24_string(id, rl->hash_key);
        head = rl->buckets[h % BUCKETS_MAX];

        LIST_FOREACH(bucket, i, head)
                if (streq(i->id, id)) {
                        g = i;
                        break;
                }

        if (!g)
                return journal_ratelimit_group_new(rl, id, interval, ts, ret);

        g->interval = interval;

        *ret = g;
        return 0;
}

static unsigned burst_modulate(unsigned burst, uint64_t available) {
        unsigned k;

        /* Modulates the burst rate a bit with the amount of available
         * disk space */

        k = log2u64(available);

        /* 1MB */
        if (k <= 20)
                return burst;

        burst = (burst * (k-16)) / 4;

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

int journal_ratelimit_test(
                JournalRateLimit *rl,
                const char *id,
                usec_t rl_interval,
                unsigned rl_burst,
                int priority,
                uint64_t available) {

        JournalRateLimitGroup *g;
        JournalRateLimitPool *p;
        unsigned burst;
        usec_t ts;
        int r;

        assert(id);

        /* Returns:
         *
         * 0     → the log message shall be suppressed,
         * 1 + n → the log message shall be permitted, and n messages were dropped from the peer before
         * < 0   → error
         */

        if (!rl)
                return 1;

        ts = now(CLOCK_MONOTONIC);

        r = journal_ratelimit_group_acquire(rl, id, rl_interval, ts, &g);
        if (r < 0)
                return r;

        if (rl_interval == 0 || rl_burst == 0)
                return 1;

        burst = burst_modulate(rl_burst, available);

        p = &g->pools[priority_map[priority]];

        if (p->begin <= 0) {
                p->suppressed = 0;
                p->num = 1;
                p->begin = ts;
                return 1;
        }

        if (usec_add(p->begin, rl_interval) < ts) {
                unsigned suppressed = p->suppressed;

                p->suppressed = 0;
                p->num = 1;
                p->begin = ts;

                return 1 + suppressed;
        }

        if (p->num < burst) {
                p->num++;
                return 1;
        }

        p->suppressed++;
        return 0;
}
