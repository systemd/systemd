/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>

#include "alloc-util.h"
#include "curl-util.h"
#include "fd-util.h"
#include "locale-util.h"
#include "string-util.h"
#include "version.h"

static void curl_glue_check_finished(CurlGlue *g) {
        int r;

        assert(g);

        /* sd_event_get_exit_code() returns -ENODATA if no exit was scheduled yet */
        r = sd_event_get_exit_code(g->event, /* ret_code= */ NULL);
        if (r >= 0)
                return; /* exit scheduled? Then don't process this anymore */
        if (r != -ENODATA)
                log_debug_errno(r, "Unexpected error while checking for event loop exit code, ignoring: %m");

        CURLMsg *msg;
        int k = 0;
        msg = curl_multi_info_read(g->curl, &k);
        if (!msg)
                return;

        if (msg->msg == CURLMSG_DONE && g->on_finished)
                g->on_finished(g, msg->easy_handle, msg->data.result);

        /* This is a queue, process another item soon, but do so in a later event loop iteration. */
        (void) sd_event_source_set_enabled(g->defer, SD_EVENT_ONESHOT);
}

static int curl_glue_on_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        CurlGlue *g = ASSERT_PTR(userdata);
        int action, k = 0;

        assert(s);

        if (FLAGS_SET(revents, EPOLLIN | EPOLLOUT))
                action = CURL_POLL_INOUT;
        else if (revents & EPOLLIN)
                action = CURL_POLL_IN;
        else if (revents & EPOLLOUT)
                action = CURL_POLL_OUT;
        else
                action = 0;

        if (curl_multi_socket_action(g->curl, fd, action, &k) != CURLM_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to propagate IO event.");

        curl_glue_check_finished(g);
        return 0;
}

static int curl_glue_socket_callback(CURL *curl, curl_socket_t s, int action, void *userdata, void *socketp) {
        sd_event_source *io = socketp;
        CurlGlue *g = ASSERT_PTR(userdata);
        uint32_t events = 0;
        int r;

        assert(curl);

        if (action == CURL_POLL_REMOVE) {
                if (io) {
                        sd_event_source_disable_unref(io);

                        hashmap_remove(g->ios, FD_TO_PTR(s));
                }

                return 0;
        }

        /* Don't configure io event source anymore when the event loop is dead already. */
        if (g->event && sd_event_get_state(g->event) == SD_EVENT_FINISHED)
                return 0;

        r = hashmap_ensure_allocated(&g->ios, &trivial_hash_ops);
        if (r < 0) {
                log_oom();
                return -1;
        }

        if (action == CURL_POLL_IN)
                events = EPOLLIN;
        else if (action == CURL_POLL_OUT)
                events = EPOLLOUT;
        else if (action == CURL_POLL_INOUT)
                events = EPOLLIN|EPOLLOUT;

        if (io) {
                if (sd_event_source_set_io_events(io, events) < 0)
                        return -1;

                if (sd_event_source_set_enabled(io, SD_EVENT_ON) < 0)
                        return -1;
        } else {
                if (sd_event_add_io(g->event, &io, s, events, curl_glue_on_io, g) < 0)
                        return -1;

                if (curl_multi_assign(g->curl, s, io) != CURLM_OK)
                        return -1;

                (void) sd_event_source_set_description(io, "curl-io");

                r = hashmap_put(g->ios, FD_TO_PTR(s), io);
                if (r < 0) {
                        log_oom();
                        sd_event_source_unref(io);
                        return -1;
                }
        }

        return 0;
}

static int curl_glue_on_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        CurlGlue *g = ASSERT_PTR(userdata);
        int k = 0;

        assert(s);

        if (curl_multi_socket_action(g->curl, CURL_SOCKET_TIMEOUT, 0, &k) != CURLM_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to propagate timeout.");

        curl_glue_check_finished(g);
        return 0;
}

static int curl_glue_timer_callback(CURLM *curl, long timeout_ms, void *userdata) {
        CurlGlue *g = ASSERT_PTR(userdata);
        usec_t usec;

        assert(curl);

        /* Don't configure timer anymore when the event loop is dead already. */
        if (g->timer) {
                sd_event *event_loop = sd_event_source_get_event(g->timer);
                if (event_loop && sd_event_get_state(event_loop) == SD_EVENT_FINISHED)
                        return 0;
        }

        if (timeout_ms < 0) {
                if (sd_event_source_set_enabled(g->timer, SD_EVENT_OFF) < 0)
                        return -1;

                return 0;
        }

        usec = (usec_t) timeout_ms * USEC_PER_MSEC + USEC_PER_MSEC - 1;

        if (g->timer) {
                if (sd_event_source_set_time_relative(g->timer, usec) < 0)
                        return -1;

                if (sd_event_source_set_enabled(g->timer, SD_EVENT_ONESHOT) < 0)
                        return -1;
        } else {
                if (sd_event_add_time_relative(g->event, &g->timer, CLOCK_BOOTTIME, usec, 0, curl_glue_on_timer, g) < 0)
                        return -1;

                (void) sd_event_source_set_description(g->timer, "curl-timer");
        }

        return 0;
}

static int curl_glue_on_defer(sd_event_source *s, void *userdata) {
        CurlGlue *g = ASSERT_PTR(userdata);

        assert(s);

        curl_glue_check_finished(g);
        return 0;
}

CurlGlue *curl_glue_unref(CurlGlue *g) {
        sd_event_source *io;

        if (!g)
                return NULL;

        if (g->curl)
                curl_multi_cleanup(g->curl);

        while ((io = hashmap_steal_first(g->ios)))
                sd_event_source_unref(io);

        hashmap_free(g->ios);

        sd_event_source_disable_unref(g->timer);
        sd_event_source_disable_unref(g->defer);
        sd_event_unref(g->event);
        return mfree(g);
}

int curl_glue_new(CurlGlue **glue, sd_event *event) {
        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(curl_multi_cleanupp) CURLM *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r;

        if (event)
                e = sd_event_ref(event);
        else {
                r = sd_event_default(&e);
                if (r < 0)
                        return r;
        }

        c = curl_multi_init();
        if (!c)
                return -ENOMEM;

        g = new(CurlGlue, 1);
        if (!g)
                return -ENOMEM;

        *g = (CurlGlue) {
                .event = TAKE_PTR(e),
                .curl = TAKE_PTR(c),
        };

        if (curl_multi_setopt(g->curl, CURLMOPT_SOCKETDATA, g) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_SOCKETFUNCTION, curl_glue_socket_callback) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_TIMERDATA, g) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_TIMERFUNCTION, curl_glue_timer_callback) != CURLM_OK)
                return -EINVAL;

        r = sd_event_add_defer(g->event, &g->defer, curl_glue_on_defer, g);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(g->defer, "curl-defer");

        *glue = TAKE_PTR(g);

        return 0;
}

int curl_glue_make(CURL **ret, const char *url, void *userdata) {
        _cleanup_(curl_easy_cleanupp) CURL *c = NULL;
        const char *useragent;

        assert(ret);
        assert(url);

        c = curl_easy_init();
        if (!c)
                return -ENOMEM;

        if (DEBUG_LOGGING)
                (void) curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);

        if (curl_easy_setopt(c, CURLOPT_URL, url) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_PRIVATE, userdata) != CURLE_OK)
                return -EIO;

        useragent = strjoina(program_invocation_short_name, "/" GIT_VERSION);
        if (curl_easy_setopt(c, CURLOPT_USERAGENT, useragent) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 60L) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 30L) != CURLE_OK)
                return -EIO;

#if LIBCURL_VERSION_NUM >= 0x075500 /* libcurl 7.85.0 */
        if (curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "HTTP,HTTPS,FILE") != CURLE_OK)
#else
        if (curl_easy_setopt(c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS|CURLPROTO_FILE) != CURLE_OK)
#endif
                return -EIO;

        *ret = TAKE_PTR(c);
        return 0;
}

int curl_glue_add(CurlGlue *g, CURL *c) {
        assert(g);
        assert(c);

        if (curl_multi_add_handle(g->curl, c) != CURLM_OK)
                return -EIO;

        return 0;
}

void curl_glue_remove_and_free(CurlGlue *g, CURL *c) {
        assert(g);

        if (!c)
                return;

        if (g->curl)
                curl_multi_remove_handle(g->curl, c);

        curl_easy_cleanup(c);
}

struct curl_slist *curl_slist_new(const char *first, ...) {
        struct curl_slist *l;
        va_list ap;

        if (!first)
                return NULL;

        l = curl_slist_append(NULL, first);
        if (!l)
                return NULL;

        va_start(ap, first);

        for (;;) {
                struct curl_slist *n;
                const char *i;

                i = va_arg(ap, const char*);
                if (!i)
                        break;

                n = curl_slist_append(l, i);
                if (!n) {
                        va_end(ap);
                        curl_slist_free_all(l);
                        return NULL;
                }

                l = n;
        }

        va_end(ap);
        return l;
}

int curl_header_strdup(const void *contents, size_t sz, const char *field, char **value) {
        const char *p;
        char *s;

        p = memory_startswith_no_case(contents, sz, field);
        if (!p)
                return 0;

        sz -= p - (const char*) contents;

        if (memchr(p, 0, sz))
                return 0;

        /* Skip over preceding whitespace */
        while (sz > 0 && strchr(WHITESPACE, p[0])) {
                p++;
                sz--;
        }

        /* Truncate trailing whitespace */
        while (sz > 0 && strchr(WHITESPACE, p[sz-1]))
                sz--;

        s = strndup(p, sz);
        if (!s)
                return -ENOMEM;

        *value = s;
        return 1;
}

int curl_parse_http_time(const char *t, usec_t *ret) {
        assert(t);
        assert(ret);

        time_t v = curl_getdate(t, NULL);
        if (v == (time_t) -1)
                return -EINVAL;

        if ((usec_t) v >= USEC_INFINITY / USEC_PER_SEC) /* check overflow */
                return -ERANGE;

        *ret = (usec_t) v * USEC_PER_SEC;

        return 0;
}
