/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "curl-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define ASSERT_CURL_OK(expr)                                                            \
        ({                                                                              \
                CURLcode _code = (expr);                                                \
                if (_code != CURLE_OK)                                                  \
                        log_test_failed("Expected \"%s\" to be CURLE_OK, but got %d/%s",\
                                        #expr, (int) _code, sym_curl_easy_strerror(_code)); \
        })

/* Per-request context: the write callback appends bytes to ->body, and the
 * on_finished callback stashes the CURLcode plus a "fired" flag. Each test
 * uses one or more of these and cleans them up via context_done(). */
typedef struct Context {
        sd_event *event;
        char *body;
        size_t body_len;
        bool finished;
        CURLcode result;
} Context;

static void context_done(Context *f) {
        f->event = sd_event_unref(f->event);
        f->body = mfree(f->body);
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        Context *f = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;

        if (!GREEDY_REALLOC(f->body, f->body_len + sz + 1))
                return 0;
        memcpy(f->body + f->body_len, contents, sz);
        f->body[f->body_len + sz] = 0;
        f->body_len += sz;
        return sz;
}

static int on_finished(CurlSlot *slot, CURL *curl, CURLcode code, void *userdata) {
        Context *f = ASSERT_PTR(userdata);

        f->finished = true;
        f->result = code;

        return sd_event_exit(f->event, 0);
}

static int make_tmp_url(char **ret_path, char **ret_url, const char *body) {
        const char *t;
        ASSERT_OK(tmp_dir(&t));

        _cleanup_(unlink_and_freep) char *path = ASSERT_NOT_NULL(strjoin(t, "/test-curl-util.XXXXXX"));

        _cleanup_close_ int fd = ASSERT_OK(mkostemp_safe(path));
        ASSERT_OK(loop_write(fd, body, strlen(body)));

        char *url = ASSERT_NOT_NULL(strjoin("file://", path));

        *ret_url = url;
        *ret_path = TAKE_PTR(path);
        return 0;
}

static int build_easy(const char *url, Context *f, CURL **ret) {
        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        ASSERT_OK(curl_glue_make(&easy, url));

        ASSERT_CURL_OK(sym_curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_callback));
        ASSERT_CURL_OK(sym_curl_easy_setopt(easy, CURLOPT_WRITEDATA, f));

        *ret = TAKE_PTR(easy);
        return 0;
}

TEST(curl_glue_lifecycle) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        ASSERT_OK(curl_glue_new(&g, event));

        /* ref/unref roundtrip */
        ASSERT_PTR_EQ(curl_glue_ref(g), g);
        ASSERT_NULL(curl_glue_unref(g));
}

TEST(curl_glue_make) {
        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        ASSERT_OK(curl_glue_make(&easy, "file:///dev/null"));
        ASSERT_NOT_NULL(easy);
}

TEST(curl_perform_floating) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        ASSERT_OK(curl_glue_new(&g, event));

        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_free_ char *url = NULL;
        ASSERT_OK(make_tmp_url(&path, &url, "hello world"));

        _cleanup_(context_done) Context f = { .event = sd_event_ref(event) };

        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        ASSERT_OK(build_easy(url, &f, &easy));

        /* Floating: pass NULL for ret_slot. The glue owns the slot until completion. */
        ASSERT_OK(curl_glue_perform_async(g, easy, on_finished, &f, /* ret_slot= */ NULL));
        TAKE_PTR(easy);

        ASSERT_OK(sd_event_loop(event));

        ASSERT_TRUE(f.finished);
        ASSERT_CURL_OK(f.result);
        ASSERT_STREQ(f.body, "hello world");
}

TEST(curl_perform_slot) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        ASSERT_OK(curl_glue_new(&g, event));

        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_free_ char *url = NULL;
        ASSERT_OK(make_tmp_url(&path, &url, "slot test"));

        _cleanup_(context_done) Context f = { .event = sd_event_ref(event) };

        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        ASSERT_OK(build_easy(url, &f, &easy));

        _cleanup_(curl_slot_unrefp) CurlSlot *slot = NULL;
        ASSERT_OK(curl_glue_perform_async(g, easy, on_finished, &f, &slot));
        TAKE_PTR(easy);

        ASSERT_NOT_NULL(slot);
        ASSERT_NOT_NULL(curl_slot_get_easy(slot));
        ASSERT_PTR_EQ(curl_slot_get_glue(slot), g);

        ASSERT_OK(sd_event_loop(event));

        ASSERT_TRUE(f.finished);
        ASSERT_CURL_OK(f.result);
        ASSERT_STREQ(f.body, "slot test");

        /* After completion, disconnect has cleared the slot's back-pointers; the slot itself
         * is still alive because we hold a ref. Releasing it must be a clean no-op. */
        ASSERT_NULL(curl_slot_get_easy(slot));
        ASSERT_NULL(curl_slot_get_glue(slot));
}

TEST(curl_perform_cancel) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        ASSERT_OK(curl_glue_new(&g, event));

        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_free_ char *url = NULL;
        ASSERT_OK(make_tmp_url(&path, &url, "payload"));

        /* Two requests: cancelled is unref'd before we run the loop; sentinel runs to
         * completion and exits the loop. After the loop returns we know the dispatcher had
         * an opportunity to fire any pending completion — so cancelled.finished staying false
         * means our cancel actually prevented the callback from running, not just outraced it. */
        _cleanup_(context_done) Context cancelled = { .event = sd_event_ref(event) };
        _cleanup_(context_done) Context sentinel = { .event = sd_event_ref(event) };

        _cleanup_(curl_easy_cleanupp) CURL *easy_cancelled = NULL, *easy_sentinel = NULL;
        ASSERT_OK(build_easy(url, &cancelled, &easy_cancelled));
        ASSERT_OK(build_easy(url, &sentinel, &easy_sentinel));

        _cleanup_(curl_slot_unrefp) CurlSlot *slot = NULL;
        ASSERT_OK(curl_glue_perform_async(g, easy_cancelled, on_finished, &cancelled, &slot));
        TAKE_PTR(easy_cancelled);

        /* Cancel by dropping our only reference: removes the easy handle from the multi and
         * cleans it up. The callback must not fire afterwards. */
        slot = curl_slot_unref(slot);

        /* The sentinel runs as floating; its callback will exit the loop on completion. */
        ASSERT_OK(curl_glue_perform_async(g, easy_sentinel, on_finished, &sentinel, /* ret_slot= */ NULL));
        TAKE_PTR(easy_sentinel);

        ASSERT_OK(sd_event_loop(event));

        ASSERT_TRUE(sentinel.finished);
        ASSERT_FALSE(cancelled.finished);
}

typedef struct ConcurrentReq {
        Context ctx;
        const char *expected;
        unsigned *remaining;
} ConcurrentReq;

static int concurrent_on_finished(CurlSlot *slot, CURL *curl, CURLcode code, void *userdata) {
        ConcurrentReq *cr = ASSERT_PTR(userdata);

        cr->ctx.finished = true;
        cr->ctx.result = code;

        (*cr->remaining)--;
        if (*cr->remaining == 0)
                return sd_event_exit(cr->ctx.event, 0);
        return 0;
}

TEST(curl_concurrent) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        ASSERT_OK(sd_event_default(&event));

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        ASSERT_OK(curl_glue_new(&g, event));

        _cleanup_(unlink_and_freep) char *path_a = NULL, *path_b = NULL, *path_c = NULL;
        _cleanup_free_ char *url_a = NULL, *url_b = NULL, *url_c = NULL;
        ASSERT_OK(make_tmp_url(&path_a, &url_a, "alpha"));
        ASSERT_OK(make_tmp_url(&path_b, &url_b, "bravo"));
        ASSERT_OK(make_tmp_url(&path_c, &url_c, "charlie"));

        unsigned remaining = 3;
        ConcurrentReq reqs[3] = {
                { .ctx = { .event = sd_event_ref(event) }, .expected = "alpha",   .remaining = &remaining },
                { .ctx = { .event = sd_event_ref(event) }, .expected = "bravo",   .remaining = &remaining },
                { .ctx = { .event = sd_event_ref(event) }, .expected = "charlie", .remaining = &remaining },
        };

        _cleanup_(curl_easy_cleanupp) CURL *ea = NULL, *eb = NULL, *ec = NULL;
        ASSERT_OK(build_easy(url_a, &reqs[0].ctx, &ea));
        ASSERT_OK(build_easy(url_b, &reqs[1].ctx, &eb));
        ASSERT_OK(build_easy(url_c, &reqs[2].ctx, &ec));

        /* All three fire as floating slots; the only way the loop exits is through the
         * remaining-counter hitting zero, which means every callback fired with the right
         * userdata routed to its respective body. */
        ASSERT_OK(curl_glue_perform_async(g, ea, concurrent_on_finished, &reqs[0], NULL));
        TAKE_PTR(ea);
        ASSERT_OK(curl_glue_perform_async(g, eb, concurrent_on_finished, &reqs[1], NULL));
        TAKE_PTR(eb);
        ASSERT_OK(curl_glue_perform_async(g, ec, concurrent_on_finished, &reqs[2], NULL));
        TAKE_PTR(ec);

        ASSERT_OK(sd_event_loop(event));

        ASSERT_EQ(remaining, 0u);

        FOREACH_ARRAY(r, reqs, ELEMENTSOF(reqs)) {
                ASSERT_TRUE(r->ctx.finished);
                ASSERT_CURL_OK(r->ctx.result);
                ASSERT_STREQ(r->ctx.body, r->expected);
                context_done(&r->ctx);
        }
}

static int intro(void) {
        if (dlopen_curl(LOG_DEBUG) < 0)
                return log_tests_skipped("libcurl not available");
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
