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
        Server *server;

        char *id;

        /* Interval is stored to keep track of when the group expires */
        usec_t interval;

        JournalRateLimitPool pools[POOLS_MAX];
} JournalRateLimitGroup;

static JournalRateLimitGroup* journal_ratelimit_group_free(JournalRateLimitGroup *g) {
        if (!g)
                return NULL;

        if (g->server && g->id)
                ordered_hashmap_remove(g->server->ratelimit_groups_by_id, g->id);

        free(g->id);
        return mfree(g);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(JournalRateLimitGroup*, journal_ratelimit_group_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
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

static void journal_ratelimit_vacuum(Server *s, usec_t ts) {
        assert(s);

        /* Makes room for at least one new item, but drop all expired items too. */

        while (ordered_hashmap_size(s->ratelimit_groups_by_id) >= GROUPS_MAX)
                journal_ratelimit_group_free(ordered_hashmap_first(s->ratelimit_groups_by_id));

        JournalRateLimitGroup *g;
        while ((g = ordered_hashmap_first(s->ratelimit_groups_by_id)) && journal_ratelimit_group_expired(g, ts))
                journal_ratelimit_group_free(g);
}

static int journal_ratelimit_group_new(
                Server *s,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        _cleanup_(journal_ratelimit_group_freep) JournalRateLimitGroup *g = NULL;
        int r;

        assert(s);
        assert(id);
        assert(ret);

        g = new0(JournalRateLimitGroup, 1);
        if (!g)
                return -ENOMEM;

        g->id = strdup(id);
        if (!g->id)
                return -ENOMEM;

        g->interval = interval;

        journal_ratelimit_vacuum(s, ts);

        r = ordered_hashmap_ensure_put(&s->ratelimit_groups_by_id, &journal_ratelimit_group_hash_ops, g->id, g);
        if (r < 0)
                return r;
        assert(r > 0);

        g->server = s;

        *ret = TAKE_PTR(g);
        return 0;
}

static int journal_ratelimit_group_acquire(
                Server *s,
                const char *id,
                usec_t interval,
                usec_t ts,
                JournalRateLimitGroup **ret) {

        JournalRateLimitGroup *g;

        assert(s);
        assert(id);
        assert(ret);

        g = ordered_hashmap_get(s->ratelimit_groups_by_id, id);
        if (!g)
                return journal_ratelimit_group_new(s, id, interval, ts, ret);

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
                Server *s,
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

        assert(s);
        assert(id);

        /* Returns:
         *
         * 0     → the log message shall be suppressed,
         * 1 + n → the log message shall be permitted, and n messages were dropped from the peer before
         * < 0   → error
         */

        if (ordered_hashmap_isempty(s->ratelimit_groups_by_id))
                return 1;

        ts = now(CLOCK_MONOTONIC);

        r = journal_ratelimit_group_acquire(s, id, rl_interval, ts, &g);
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
                unsigned suppressed;

                suppressed = p->suppressed;
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
