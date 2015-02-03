/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include "curl-util.h"

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
        int action, k = 0, translated_fd;

        assert(s);
        assert(g);

        translated_fd = PTR_TO_INT(hashmap_get(g->translate_fds, INT_TO_PTR(fd+1)));
        assert(translated_fd > 0);
        translated_fd--;

        if ((revents & (EPOLLIN|EPOLLOUT)) == (EPOLLIN|EPOLLOUT))
                action = CURL_POLL_INOUT;
        else if (revents & EPOLLIN)
                action = CURL_POLL_IN;
        else if (revents & EPOLLOUT)
                action = CURL_POLL_OUT;
        else
                action = 0;

        if (curl_multi_socket_action(g->curl, translated_fd, action, &k) < 0) {
                log_debug("Failed to propagate IO event.");
                return -EINVAL;
        }

        curl_glue_check_finished(g);
        return 0;
}

static int curl_glue_socket_callback(CURLM *curl, curl_socket_t s, int action, void *userdata, void *socketp) {
        sd_event_source *io;
        CurlGlue *g = userdata;
        uint32_t events = 0;
        int r;

        assert(curl);
        assert(g);

        io = hashmap_get(g->ios, INT_TO_PTR(s+1));

        if (action == CURL_POLL_REMOVE) {
                if (io) {
                        int fd;

                        fd = sd_event_source_get_io_fd(io);
                        assert(fd >= 0);

                        sd_event_source_set_enabled(io, SD_EVENT_OFF);
                        sd_event_source_unref(io);

                        hashmap_remove(g->ios, INT_TO_PTR(s+1));
                        hashmap_remove(g->translate_fds, INT_TO_PTR(fd+1));

                        safe_close(fd);
                }

                return 0;
        }

        r = hashmap_ensure_allocated(&g->ios, &trivial_hash_ops);
        if (r < 0) {
                log_oom();
                return -1;
        }

        r = hashmap_ensure_allocated(&g->translate_fds, &trivial_hash_ops);
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
                _cleanup_close_ int fd = -1;

                /* When curl needs to remove an fd from us it closes
                 * the fd first, and only then calls into us. This is
                 * nasty, since we cannot pass the fd on to epoll()
                 * anymore. Hence, duplicate the fds here, and keep a
                 * copy for epoll which we control after use. */

                fd = fcntl(s, F_DUPFD_CLOEXEC, 3);
                if (fd < 0)
                        return -1;

                if (sd_event_add_io(g->event, &io, fd, events, curl_glue_on_io, g) < 0)
                        return -1;

                sd_event_source_set_description(io, "curl-io");

                r = hashmap_put(g->ios, INT_TO_PTR(s+1), io);
                if (r < 0) {
                        log_oom();
                        sd_event_source_unref(io);
                        return -1;
                }

                r = hashmap_put(g->translate_fds, INT_TO_PTR(fd+1), INT_TO_PTR(s+1));
                if (r < 0) {
                        log_oom();
                        hashmap_remove(g->ios, INT_TO_PTR(s+1));
                        sd_event_source_unref(io);
                        return -1;
                }

                fd = -1;
        }

        return 0;
}

static int curl_glue_on_timer(sd_event_source *s, uint64_t usec, void *userdata) {
        CurlGlue *g = userdata;
        int k = 0;

        assert(s);
        assert(g);

        if (curl_multi_socket_action(g->curl, CURL_SOCKET_TIMEOUT, 0, &k) != CURLM_OK) {
                log_debug("Failed to propagate timeout.");
                return -EINVAL;
        }

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

                sd_event_source_set_description(g->timer, "curl-timer");
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
                int fd;

                fd = sd_event_source_get_io_fd(io);
                assert(fd >= 0);

                hashmap_remove(g->translate_fds, INT_TO_PTR(fd+1));

                safe_close(fd);
                sd_event_source_unref(io);
        }

        hashmap_free(g->ios);

        sd_event_source_unref(g->timer);
        sd_event_unref(g->event);
        free(g);

        return NULL;
}

int curl_glue_new(CurlGlue **glue, sd_event *event) {
        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        int r;

        g = new0(CurlGlue, 1);
        if (!g)
                return -ENOMEM;

        if (event)
                g->event = sd_event_ref(event);
        else {
                r = sd_event_default(&g->event);
                if (r < 0)
                        return r;
        }

        g->curl = curl_multi_init();
        if (!g->curl)
                return -ENOMEM;

        if (curl_multi_setopt(g->curl, CURLMOPT_SOCKETDATA, g) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_SOCKETFUNCTION, curl_glue_socket_callback) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_TIMERDATA, g) != CURLM_OK)
                return -EINVAL;

        if (curl_multi_setopt(g->curl, CURLMOPT_TIMERFUNCTION, curl_glue_timer_callback) != CURLM_OK)
                return -EINVAL;

        *glue = g;
        g = NULL;

        return 0;
}

int curl_glue_make(CURL **ret, const char *url, void *userdata) {
        const char *useragent;
        CURL *c;
        int r;

        assert(ret);
        assert(url);

        c = curl_easy_init();
        if (!c)
                return -ENOMEM;

        /* curl_easy_setopt(c, CURLOPT_VERBOSE, 1L); */

        if (curl_easy_setopt(c, CURLOPT_URL, url) != CURLE_OK) {
                r = -EIO;
                goto fail;
        }

        if (curl_easy_setopt(c, CURLOPT_PRIVATE, userdata) != CURLE_OK) {
                r = -EIO;
                goto fail;
        }

        useragent = strjoina(program_invocation_short_name, "/" PACKAGE_VERSION);
        if (curl_easy_setopt(c, CURLOPT_USERAGENT, useragent) != CURLE_OK) {
                r = -EIO;
                goto fail;
        }

        if (curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK) {
                r = -EIO;
                goto fail;
        }

        *ret = c;
        return 0;

fail:
        curl_easy_cleanup(c);
        return r;
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
        const char *p = contents;
        size_t l;
        char *s;

        l = strlen(field);
        if (sz < l)
                return 0;

        if (memcmp(p, field, l) != 0)
                return 0;

        p += l;
        sz -= l;

        if (memchr(p, 0, sz))
                return 0;

        /* Skip over preceeding whitespace */
        while (sz > 0 && strchr(WHITESPACE, p[0])) {
                p++;
                sz--;
        }

        /* Truncate trailing whitespace*/
        while (sz > 0 && strchr(WHITESPACE, p[sz-1]))
                sz--;

        s = strndup(p, sz);
        if (!s)
                return -ENOMEM;

        *value = s;
        return 1;
}

int curl_parse_http_time(const char *t, usec_t *ret) {
        const char *e;
        locale_t loc;
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
        freelocale(loc);
        if (!e || *e != 0)
                return -EINVAL;

        v = timegm(&tm);
        if (v == (time_t) -1)
                return -EINVAL;

        *ret = (usec_t) v * USEC_PER_SEC;
        return 0;
}
