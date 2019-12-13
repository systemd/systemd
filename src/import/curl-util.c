/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>

#include "alloc-util.h"
#include "build.h"
#include "curl-util.h"
#include "fd-util.h"
#include "locale-util.h"
#include "string-util.h"

static void curl_glue_check_finished(CurlGlue *g) {
        CURLMsg *msg;
        int k = 0;

        assert(g);

        msg = curl_multi_info_read(g->curl, &k);
        if (!msg)
                return;

        if (msg->msg != CURLMSG_DONE)
                return;

        if (g->on_finished)
                g->on_finished(g, msg->easy_handle, msg->data.result);
}

static int curl_glue_on_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        CurlGlue *g = userdata;
        int action, k = 0;

        assert(s);
        assert(g);

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

static int curl_glue_socket_callback(CURLM *curl, curl_socket_t s, int action, void *userdata, void *socketp) {
        sd_event_source *io = socketp;
        CurlGlue *g = userdata;
        uint32_t events = 0;
        int r;

        assert(curl);
        assert(g);

        if (action == CURL_POLL_REMOVE) {
                if (io) {
                        sd_event_source_disable_unref(io);

                        hashmap_remove(g->ios, FD_TO_PTR(s));
                }

                return 0;
        }

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
        CurlGlue *g = userdata;
        int k = 0;

        assert(s);
        assert(g);

        if (curl_multi_socket_action(g->curl, CURL_SOCKET_TIMEOUT, 0, &k) != CURLM_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to propagate timeout.");

        curl_glue_check_finished(g);
        return 0;
}

static int curl_glue_timer_callback(CURLM *curl, long timeout_ms, void *userdata) {
        CurlGlue *g = userdata;
        usec_t usec;

        assert(curl);
        assert(g);

        if (timeout_ms < 0) {
                if (g->timer) {
                        if (sd_event_source_set_enabled(g->timer, SD_EVENT_OFF) < 0)
                                return -1;
                }

                return 0;
        }

        usec = now(clock_boottime_or_monotonic()) + (usec_t) timeout_ms * USEC_PER_MSEC + USEC_PER_MSEC - 1;

        if (g->timer) {
                if (sd_event_source_set_time(g->timer, usec) < 0)
                        return -1;

                if (sd_event_source_set_enabled(g->timer, SD_EVENT_ONESHOT) < 0)
                        return -1;
        } else {
                if (sd_event_add_time(g->event, &g->timer, clock_boottime_or_monotonic(), usec, 0, curl_glue_on_timer, g) < 0)
                        return -1;

                (void) sd_event_source_set_description(g->timer, "curl-timer");
        }

        return 0;
}

CurlGlue *curl_glue_unref(CurlGlue *g) {
        sd_event_source *io;

        if (!g)
                return NULL;

        if (g->curl)
                curl_multi_cleanup(g->curl);

        while ((io = hashmap_steal_first(g->ios))) {
                sd_event_source_unref(io);
        }

        hashmap_free(g->ios);

        sd_event_source_unref(g->timer);
        sd_event_unref(g->event);
        return mfree(g);
}

int curl_glue_new(CurlGlue **glue, sd_event *event) {
        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(curl_multi_cleanupp) CURL *c = NULL;
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

        /* curl_easy_setopt(c, CURLOPT_VERBOSE, 1L); */

        if (curl_easy_setopt(c, CURLOPT_URL, url) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_PRIVATE, userdata) != CURLE_OK)
                return -EIO;

        useragent = strjoina(program_invocation_short_name, "/" GIT_VERSION);
        if (curl_easy_setopt(c, CURLOPT_USERAGENT, useragent) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK)
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
        _cleanup_(freelocalep) locale_t loc = (locale_t) 0;
        const char *e;
        struct tm tm;
        time_t v;

        assert(t);
        assert(ret);

        loc = newlocale(LC_TIME_MASK, "C", (locale_t) 0);
        if (loc == (locale_t) 0)
                return -errno;

        /* RFC822 */
        e = strptime_l(t, "%a, %d %b %Y %H:%M:%S %Z", &tm, loc);
        if (!e || *e != 0)
                /* RFC 850 */
                e = strptime_l(t, "%A, %d-%b-%y %H:%M:%S %Z", &tm, loc);
        if (!e || *e != 0)
                /* ANSI C */
                e = strptime_l(t, "%a %b %d %H:%M:%S %Y", &tm, loc);
        if (!e || *e != 0)
                return -EINVAL;

        v = timegm(&tm);
        if (v == (time_t) -1)
                return -EINVAL;

        *ret = (usec_t) v * USEC_PER_SEC;
        return 0;
}
