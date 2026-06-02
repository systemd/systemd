/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-future.h"

#include "alloc-util.h"
#include "resolved-fiber-util.h"

typedef struct ResolvedFuture {
        int dummy;
} ResolvedFuture;

static void* resolved_future_alloc(void) {
        return new0(ResolvedFuture, 1);
}

static void resolved_future_free(sd_future *f) {
        free(sd_future_get_private(f));
}

static int resolved_future_cancel(sd_future *f) {
        assert(f);

        return -EOPNOTSUPP;
}

static const sd_future_ops resolved_future_ops = {
        .size = sizeof(sd_future_ops),
        .alloc = resolved_future_alloc,
        .free = resolved_future_free,
        .cancel = resolved_future_cancel,
};

int resolved_future_new(sd_future **ret) {
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(ret);

        r = sd_future_new(&resolved_future_ops, &f);
        if (r < 0)
                return r;

        /* Object completion futures are shared by all waiters. sd_future_new() defaults to resuming the
         * current fiber when called from fiber context, which would make a shared future keep a stale
         * callback to the first waiter. Awaiters must use sd_future_new_wait() via sd_fiber_await()
         * instead, so each waiter owns its own callback and cancellation state. */
        r = sd_future_set_callback(f, NULL, NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(f);
        return 0;
}
