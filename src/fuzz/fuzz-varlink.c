/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "varlink.h"
#include "log.h"

static FILE *null = NULL;

static int method_something(Varlink *v, JsonVariant *p, VarlinkMethodFlags flags, void *userdata) {
        json_variant_dump(p, JSON_FORMAT_NEWLINE|JSON_FORMAT_PRETTY, null, NULL);
        return 0;
}

static int reply_callback(Varlink *v, JsonVariant *p, const char *error_id, VarlinkReplyFlags flags, void *userdata) {
        json_variant_dump(p, JSON_FORMAT_NEWLINE|JSON_FORMAT_PRETTY, null, NULL);
        return 0;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        struct iovec *iov = ASSERT_PTR(userdata);
        bool write_eof = false, read_eof = false;

        assert(s);
        assert(fd >= 0);

        if ((revents & (EPOLLOUT|EPOLLHUP|EPOLLERR)) && iov->iov_len > 0) {
                ssize_t n;

                /* never write more than 143 bytes a time, to make broken up recv()s on the other side more
                 * likely, and thus test some additional code paths. */
                n = send(fd, iov->iov_base, MIN(iov->iov_len, 143U), MSG_NOSIGNAL|MSG_DONTWAIT);
                if (n < 0) {
                        if (ERRNO_IS_DISCONNECT(errno))
                                write_eof = true;
                        else
                                assert_se(errno == EAGAIN);
                } else
                        IOVEC_INCREMENT(iov, 1, n);
        }

        if (revents & EPOLLIN) {
                char c[137];
                ssize_t n;

                n = recv(fd, c, sizeof(c), MSG_DONTWAIT);
                if (n < 0) {
                        if (ERRNO_IS_DISCONNECT(errno))
                                read_eof = true;
                        else
                                assert_se(errno == EAGAIN);
                } else if (n == 0)
                        read_eof = true;
                else
                        hexdump(null, c, (size_t) n);
        }

        /* After we wrote everything we could turn off EPOLLOUT. And if we reached read EOF too turn off the
         * whole thing. */
        if (write_eof || iov->iov_len == 0) {

                if (read_eof)
                        assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);
                else
                        assert_se(sd_event_source_set_io_events(s, EPOLLIN) >= 0);
        }

        return 0;
}

static int idle_callback(sd_event_source *s, void *userdata) {
        assert(s);

        /* Called as idle callback when there's nothing else to do anymore */
        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        struct iovec server_iov = IOVEC_MAKE((void*) data, size), client_iov = IOVEC_MAKE((void*) data, size);
        /* Important: the declaration order matters here! we want that the fds are closed on return after the
         * event sources, hence we declare the fds first, the event sources second */
        _cleanup_close_pair_ int server_pair[2] = { -1, -1 }, client_pair[2] = { -1, -1 };
        _cleanup_(sd_event_source_unrefp) sd_event_source *idle_event_source = NULL,
                *server_event_source = NULL, *client_event_source = NULL;
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        log_set_max_level(LOG_CRIT);
        log_parse_environment();

        assert_se(null = fopen("/dev/null", "we"));

        assert_se(sd_event_default(&e) >= 0);

        /* Test one: write the data as method call to a server */
        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, server_pair) >= 0);
        assert_se(varlink_server_new(&s, 0) >= 0);
        assert_se(varlink_server_set_description(s, "myserver") >= 0);
        assert_se(varlink_server_attach_event(s, e, 0) >= 0);
        assert_se(varlink_server_add_connection(s, server_pair[0], NULL) >= 0);
        TAKE_FD(server_pair[0]);
        assert_se(varlink_server_bind_method(s, "io.test.DoSomething", method_something) >= 0);
        assert_se(sd_event_add_io(e, &server_event_source, server_pair[1], EPOLLIN|EPOLLOUT, io_callback, &server_iov) >= 0);

        /* Test two: write the data as method response to a client */
        assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, client_pair) >= 0);
        assert_se(varlink_connect_fd(&c, client_pair[0]) >= 0);
        TAKE_FD(client_pair[0]);
        assert_se(varlink_set_description(c, "myclient") >= 0);
        assert_se(varlink_attach_event(c, e, 0) >= 0);
        assert_se(varlink_bind_reply(c, reply_callback) >= 0);
        assert_se(varlink_invoke(c, "io.test.DoSomething", NULL) >= 0);
        assert_se(sd_event_add_io(e, &client_event_source, client_pair[1], EPOLLIN|EPOLLOUT, io_callback, &client_iov) >= 0);

        assert_se(sd_event_add_defer(e, &idle_event_source, idle_callback, NULL) >= 0);
        assert_se(sd_event_source_set_priority(idle_event_source, SD_EVENT_PRIORITY_IDLE) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        null = safe_fclose(null);

        return 0;
}
