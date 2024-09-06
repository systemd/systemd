/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "journald-rate-limit.h"
#include "logarithm.h"
#include "string-util.h"
#include "time-util.h"

#define POOLS_MAX 5
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

typedef struct JournalRateLimitPool {
        usec_t begin;
        unsigned num;
        unsigned suppressed;
} JournalRateLimitPool;

typedef struct JournalRateLimitGroup {
        OrderedHashmap *groups_by_id;

        char *id;

        /* Interval is stored to keep track of when the group expires */
        usec_t interval;

        JournalRateLimitPool pools[POOLS_MAX];
} JournalRateLimitGroup;

static JournalRateLimitGroup* journal_ratelimit_group_free(JournalRateLimitGroup *g) {
        if (!g)
                return NULL;

        if (g->groups_by_id && g->id)
                /* The group is already removed from the hashmap when this is called from the
                 * destructor of the hashmap. Hence, do not check the return value here. */
                ordered_hashmap_remove_value(g->groups_by_id, g->id, g);

        free(g->id);
        return mfree(g);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JournalRateLimitGroup*, journal_ratelimit_group_free);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        journal_ratelimit_group_hash_ops,
        char,
        string_hash_func,
        string_compare_func,
        JournalRateLimitGroup,
        journal_ratelimit_group_free);

static bool journal_ratelimit_group_expired(JournalRateLimitGroup *g, usec_t ts) {
        assert(g);

        FOREACH_ELEMENT(p, g->pools)
                if (usec_add(p->begin, g->interval) >= ts)
                        return false;

        return true;
}

static void journal_ratelimit_vacuum(OrderedHashmap *groups_by_id, usec_t ts) {

        /* Makes room for at least one new item, but drop all expired items too. */

        while (ordered_hashmap_size(groups_by_id) >= GROUPS_MAX)
                journal_ratelimit_group_free(ordered_hashmap_first(groups_by_id));

        JournalRateLimitGroup *g;
        while ((g = ordered_hashmap_first(groups_by_id)) && journal_ratelimit_group_expired(g, ts))
                journal_ratelimit_group_free(g);
}

static int journal_ratelimit_group_new(
                OrderedHashmap **groups_by_id,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        _cleanup_(journal_ratelimit_group_freep) JournalRateLimitGroup *g = NULL;
        int r;

        assert(groups_by_id);
        assert(id);
        assert(ret);

        g = new(JournalRateLimitGroup, 1);
        if (!g)
                return -ENOMEM;

        *g = (JournalRateLimitGroup) {
                .id = strdup(id),
                .interval = interval,
        };
        if (!g->id)
                return -ENOMEM;

        journal_ratelimit_vacuum(*groups_by_id, ts);

        r = ordered_hashmap_ensure_put(groups_by_id, &journal_ratelimit_group_hash_ops, g->id, g);
        if (r < 0)
                return r;
        assert(r > 0);

        g->groups_by_id = *groups_by_id;

        *ret = TAKE_PTR(g);
        return 0;
}

static int journal_ratelimit_group_acquire(
                OrderedHashmap **groups_by_id,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        JournalRateLimitGroup *g;

        assert(groups_by_id);
        assert(id);
        assert(ret);

        g = ordered_hashmap_get(*groups_by_id, id);
        if (!g)
                return journal_ratelimit_group_new(groups_by_id, id, interval, ts, ret);

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
                OrderedHashmap **groups_by_id,
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

        assert(groups_by_id);
        assert(id);

        /* Returns:
         *
         * 0     → the log message shall be suppressed,
         * 1 + n → the log message shall be permitted, and n messages were dropped from the peer before
         * < 0   → error
         */

        ts = now(CLOCK_MONOTONIC);

        r = journal_ratelimit_group_acquire(groups_by_id, id, rl_interval, ts, &g);
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
                unsigned s;

                s = p->suppressed;
                p->suppressed = 0;
                p->num = 1;
                p->begin = ts;

                return 1 + s;
        }

        if (p->num < burst) {
                p->num++;
                return 1;
        }

        p->suppressed++;
        return 0;
}
