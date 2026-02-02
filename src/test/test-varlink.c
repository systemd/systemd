/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "fd-util.h"
#include "json-util.h"
#include "memfd-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "varlink-util.h"

/* Let's pick some high value, that is higher than the largest listen() backlog, but leaves enough room below
   the typical RLIMIT_NOFILE value of 1024 so that we can process both sides of each socket in our
   process. Or in other words: "OVERLOAD_CONNECTIONS * 2 + x < 1024" should hold, for some small x that
   should cover any auxiliary fds, the listener server fds, stdin/stdout/stderr and whatever else. */
#define OVERLOAD_CONNECTIONS 333

static int n_done = 0;
static int block_write_fd = -EBADF;

static int method_something(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ret = NULL;
        sd_json_variant *a, *b;
        int64_t x, y;
        int r;

        a = sd_json_variant_by_key(parameters, "a");
        if (!a)
                return ASSERT_ERROR(sd_varlink_error(link, "io.test.BadParameters", NULL), EBADR);

        x = sd_json_variant_integer(a);

        b = sd_json_variant_by_key(parameters, "b");
        if (!b)
                return ASSERT_ERROR(sd_varlink_error(link, "io.test.BadParameters", NULL), EBADR);

        y = sd_json_variant_integer(b);

        r = sd_json_build(&ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("sum", SD_JSON_BUILD_INTEGER(x + y))));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, ret);
}

static int method_something_more(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ret = NULL;
        int r;

        struct Something {
                int x;
                int y;
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "a", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct Something, x), SD_JSON_MANDATORY },
                { "b", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct Something, y), SD_JSON_MANDATORY},
                {}
        };
        struct Something s = {};

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &s);
        if (r != 0)
                return r;

        for (int i = 0; i < 5; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                r = sd_json_build(&w, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("sum", SD_JSON_BUILD_INTEGER(s.x + (s.y * i)))));
                if (r < 0)
                        return r;

                r = sd_varlink_notify(link, w);
                if (r < 0)
                        return r;
        }

        r = sd_json_build(&ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("sum", SD_JSON_BUILD_INTEGER(s.x + (s.y * 5)))));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, ret);
}

static void test_fd(int fd, const void *buf, size_t n) {
        char rbuf[n + 1];
        ssize_t m;

        ASSERT_OK_ERRNO(m = read(fd, rbuf, n + 1));
        ASSERT_OK_ZERO(memcmp_nn(buf, n, rbuf, m));
}

static int method_passfd(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ret = NULL;
        sd_json_variant *a;
        int r;

        a = sd_json_variant_by_key(parameters, "fd");
        if (!a)
                return ASSERT_ERROR(sd_varlink_error_invalid_parameter_name(link, "fd"), EINVAL);

        ASSERT_STREQ(sd_json_variant_string(a), "whoop");

        int xx, yy, zz;
        ASSERT_OK(xx = sd_varlink_peek_fd(link, 0));
        ASSERT_OK(yy = sd_varlink_peek_fd(link, 1));
        ASSERT_OK(zz = sd_varlink_peek_fd(link, 2));

        log_info("%i %i %i", xx, yy, zz);

        test_fd(xx, "foo", 3);
        test_fd(yy, "bar", 3);
        test_fd(zz, "quux", 4);

        _cleanup_close_ int vv = -EBADF, ww = -EBADF;
        ASSERT_OK(vv = memfd_new_and_seal_string("data", "miau"));
        ASSERT_OK(ww = memfd_new_and_seal_string("data", "wuff"));

        r = sd_json_build(&ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("yo", SD_JSON_BUILD_INTEGER(88))));
        if (r < 0)
                return r;

        ASSERT_OK_EQ(sd_varlink_push_fd(link, vv), 0);
        ASSERT_OK_EQ(sd_varlink_push_fd(link, ww), 1);

        TAKE_FD(vv);
        TAKE_FD(ww);

        return sd_varlink_reply(link, ret);
}

static int method_fail_with_errno(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = sd_varlink_dispatch(link, parameters, NULL, NULL);
        if (r != 0)
                return r;

        return sd_varlink_error_errno(link, EHWPOISON);
}

static int method_done(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        if (++n_done == 2)
                sd_event_exit(sd_varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        sd_json_variant *sum;

        sum = sd_json_variant_by_key(parameters, "sum");

        ASSERT_EQ(sd_json_variant_integer(sum), 7+22);

        if (++n_done == 2)
                sd_event_exit(sd_varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int on_connect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        uid_t uid = UID_INVALID;

        ASSERT_NOT_NULL(s);
        ASSERT_NOT_NULL(link);

        ASSERT_OK(sd_varlink_get_peer_uid(link, &uid));
        ASSERT_EQ(getuid(), uid);
        ASSERT_OK(sd_varlink_set_allow_fd_passing_input(link, true));
        ASSERT_OK(sd_varlink_set_allow_fd_passing_output(link, true));

        return 0;
}

static int overload_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {

        /* This method call reply should always be called with a disconnection, since the method call should
         * be talking to an overloaded server */

        log_debug("Over reply triggered with error: %s", strna(error_id));
        ASSERT_STREQ(error_id, SD_VARLINK_ERROR_DISCONNECTED);
        /* Local disconnect errors carry empty parameters. Ensure we propagate
         * a consistent empty object for API reliability. */
        ASSERT_TRUE(sd_json_variant_is_blank_object(parameters));
        sd_event_exit(sd_varlink_get_event(link), 0);

        return 0;
}

static void flood_test(const char *address) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ sd_varlink **connections = NULL;
        size_t k;
        char x = 'x';

        log_debug("Flooding server...");

        /* Block the main event loop while we flood */
        ASSERT_OK_EQ_ERRNO(write(block_write_fd, &x, sizeof(x)), (ssize_t) sizeof(x));

        ASSERT_OK(sd_event_default(&e));

        /* Flood the server with connections */
        ASSERT_NOT_NULL(connections = new0(sd_varlink*, OVERLOAD_CONNECTIONS));
        for (k = 0; k < OVERLOAD_CONNECTIONS; k++) {
                _cleanup_free_ char *t = NULL;
                log_debug("connection %zu", k);
                ASSERT_OK(sd_varlink_connect_address(connections + k, address));

                ASSERT_OK(asprintf(&t, "flood-%zu", k));
                ASSERT_OK(sd_varlink_set_description(connections[k], t));
                ASSERT_OK(sd_varlink_attach_event(connections[k], e, k));
                ASSERT_OK(sd_varlink_sendb(connections[k], "io.test.Rubbish", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_INTEGER(k)))));
        }

        /* Then, create one more, which should fail */
        log_debug("Creating overload connection...");
        ASSERT_OK(sd_varlink_connect_address(&c, address));
        ASSERT_OK(sd_varlink_set_description(c, "overload-client"));
        ASSERT_OK(sd_varlink_attach_event(c, e, k));
        ASSERT_OK(sd_varlink_bind_reply(c, overload_reply));
        ASSERT_OK(sd_varlink_invokeb(c, "io.test.Overload", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("foo", JSON_BUILD_CONST_STRING("bar")))));

        /* Unblock it */
        log_debug("Unblocking server...");
        block_write_fd = safe_close(block_write_fd);

        /* This loop will terminate as soon as the overload reply callback is called */
        ASSERT_OK(sd_event_loop(e));

        /* And close all connections again */
        for (k = 0; k < OVERLOAD_CONNECTIONS; k++)
                connections[k] = sd_varlink_unref(connections[k]);
}

static void *thread(void *arg) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *c = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *i = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *wrong = NULL;
        sd_json_variant *o = NULL, *k = NULL, *j = NULL;
        const char *error_id, *e;
        int x = 0;

        ASSERT_OK(sd_json_build(&i, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(88)),
                                                   SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_INTEGER(99)))));

        ASSERT_OK(sd_varlink_connect_address(&c, arg));
        ASSERT_OK(sd_varlink_set_description(c, "thread-client"));
        ASSERT_OK(sd_varlink_set_allow_fd_passing_input(c, true));
        ASSERT_OK(sd_varlink_set_allow_fd_passing_output(c, true));

        /* Test that client is able to perform two sequential sd_varlink_collect calls if first resulted in an error */
        ASSERT_OK(sd_json_build(&wrong, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(88)),
                                                       SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(99)))));
        ASSERT_OK(sd_varlink_collect(c, "io.test.DoSomethingMore", wrong, &j, &error_id));
        ASSERT_STREQ(error_id, "org.varlink.service.InvalidParameter");

        ASSERT_OK(sd_varlink_collect(c, "io.test.DoSomethingMore", i, &j, &error_id));

        ASSERT_NULL(error_id);
        ASSERT_TRUE(sd_json_variant_is_array(j));
        ASSERT_FALSE(sd_json_variant_is_blank_array(j));

        JSON_VARIANT_ARRAY_FOREACH(k, j) {
                ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_key(k, "sum")), 88 + (99 * x));
                x++;
        }
        ASSERT_EQ(x, 6);

        ASSERT_OK(sd_varlink_call(c, "io.test.DoSomething", i, &o, &e));
        ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_key(o, "sum")), 88 + 99);
        ASSERT_NULL(e);

        int fd1, fd2, fd3;
        ASSERT_OK(fd1 = memfd_new_and_seal_string("data", "foo"));
        ASSERT_OK(fd2 = memfd_new_and_seal_string("data", "bar"));
        ASSERT_OK(fd3 = memfd_new_and_seal_string("data", "quux"));

        ASSERT_OK_EQ(sd_varlink_push_fd(c, fd1), 0);
        ASSERT_OK_EQ(sd_varlink_push_fd(c, fd2), 1);
        ASSERT_OK_EQ(sd_varlink_push_fd(c, fd3), 2);

        ASSERT_OK(sd_varlink_callb(c, "io.test.PassFD", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("fd", SD_JSON_BUILD_STRING("whoop")))));
        ASSERT_NULL(e);

        int fd4, fd5;
        ASSERT_OK(fd4 = sd_varlink_peek_fd(c, 0));
        ASSERT_OK(fd5 = sd_varlink_peek_fd(c, 1));

        test_fd(fd4, "miau", 4);
        test_fd(fd5, "wuff", 4);

        ASSERT_OK(sd_varlink_callb(c, "io.test.PassFD", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("fdx", SD_JSON_BUILD_STRING("whoopx")))));
        ASSERT_TRUE(sd_varlink_error_is_invalid_parameter(e, o, "fd"));

        ASSERT_OK(sd_varlink_callb(c, "io.test.IDontExist", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_REAL(5.5)))));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(o, "method")), "io.test.IDontExist");
        ASSERT_STREQ(e, SD_VARLINK_ERROR_METHOD_NOT_FOUND);

        ASSERT_OK(sd_varlink_call(c, "io.test.FailWithErrno", NULL, &o, &e));
        ASSERT_ERROR(sd_varlink_error_to_errno(e, o), EHWPOISON);
        flood_test(arg);

        ASSERT_OK(sd_varlink_send(c, "io.test.Done", NULL));

        return NULL;
}

static int block_fd_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        char c;

        ASSERT_OK(fd_nonblock(fd, false));

        ASSERT_OK_EQ_ERRNO(read(fd, &c, sizeof(c)), (ssize_t) sizeof(c));
        /* When a character is written to this pipe we'll block until the pipe is closed. */

        ASSERT_OK_ZERO_ERRNO(read(fd, &c, sizeof(c)));

        ASSERT_OK(fd_nonblock(fd, true));

        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));

        return 0;
}

TEST(chat) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *block_event = NULL;
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *c = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int block_fds[2] = EBADF_PAIR;
        pthread_t t;
        const char *sp;

        ASSERT_OK(mkdtemp_malloc("/tmp/varlink-test-XXXXXX", &tmpdir));
        sp = strjoina(tmpdir, "/socket");

        ASSERT_OK(sd_event_default(&e));

        ASSERT_OK_ERRNO(pipe2(block_fds, O_NONBLOCK|O_CLOEXEC));
        ASSERT_OK(sd_event_add_io(e, &block_event, block_fds[0], EPOLLIN, block_fd_handler, NULL));
        ASSERT_OK(sd_event_source_set_priority(block_event, SD_EVENT_PRIORITY_IMPORTANT));
        block_write_fd = TAKE_FD(block_fds[1]);

        ASSERT_OK(varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID, NULL));
        ASSERT_OK(sd_varlink_server_set_info(s, "Vendor", "Product", "Version", "URL"));
        ASSERT_OK(varlink_set_info_systemd(s));
        ASSERT_OK(sd_varlink_server_set_description(s, "our-server"));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.PassFD", method_passfd));
        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.DoSomething", method_something));
        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.DoSomethingMore", method_something_more));
        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.FailWithErrno", method_fail_with_errno));
        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.Done", method_done));
        ASSERT_OK(sd_varlink_server_bind_connect(s, on_connect));
        ASSERT_OK(sd_varlink_server_listen_address(s, sp, 0600));
        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));
        ASSERT_OK(sd_varlink_server_set_connections_max(s, OVERLOAD_CONNECTIONS));

        ASSERT_OK(sd_json_build(&v, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(7)),
                                                   SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_INTEGER(22)))));

        ASSERT_OK(sd_varlink_connect_address(&c, sp));
        ASSERT_OK(sd_varlink_set_description(c, "main-client"));
        ASSERT_OK(sd_varlink_bind_reply(c, reply));

        ASSERT_OK(sd_varlink_invoke(c, "io.test.DoSomething", v));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        ASSERT_OK(-pthread_create(&t, NULL, thread, (void*) sp));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_OK(-pthread_join(t, NULL));
}

static int method_invalid(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        sd_json_dispatch_field table[] = {
                { "iexist", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };

        const char *p = NULL;

        r = sd_varlink_dispatch(link, parameters, table, &p);
        if (r != 0)
                return r;

        assert_not_reached();
}

static int reply_invalid(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ASSERT_TRUE(sd_varlink_error_is_invalid_parameter(error_id, parameters, "idontexist"));
        ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        return 0;
}

TEST(invalid_parameter) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "foo.mytest.Invalid", method_invalid));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        ASSERT_OK(sd_varlink_bind_reply(c, reply_invalid));

        ASSERT_OK(sd_varlink_invokebo(c, "foo.mytest.Invalid",
                                      SD_JSON_BUILD_PAIR_STRING("iexist", "foo"),
                                      SD_JSON_BUILD_PAIR_STRING("idontexist", "bar")));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_error_sentinel(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* Set an error sentinel and return without sending a reply. The sentinel error should be sent automatically. */
        ASSERT_OK(varlink_set_sentinel(link, "io.test.SentinelError"));
        return 0;
}

static int reply_sentinel_error(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ASSERT_STREQ(error_id, "io.test.SentinelError");
        ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        return 0;
}

TEST(sentinel_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.ErrorSentinel", method_with_error_sentinel));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        ASSERT_OK(sd_varlink_bind_reply(c, reply_sentinel_error));

        ASSERT_OK(sd_varlink_invoke(c, "io.test.ErrorSentinel", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_empty_sentinel(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* Set an empty sentinel and return without sending a reply. An empty reply should be sent automatically. */
        ASSERT_OK(varlink_set_sentinel(link, /* error_id= */ NULL));
        return 0;
}

static int reply_sentinel_empty(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ASSERT_NULL(error_id);
        ASSERT_TRUE(sd_json_variant_is_blank_object(parameters));
        ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        return 0;
}

TEST(sentinel_empty) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.EmptySentinel", method_with_empty_sentinel));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        ASSERT_OK(sd_varlink_bind_reply(c, reply_sentinel_empty));

        ASSERT_OK(sd_varlink_invoke(c, "io.test.EmptySentinel", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_sentinel_but_reply(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* Set a sentinel but also send a reply. The sentinel should not be used. */
        ASSERT_OK(varlink_set_sentinel(link, "io.test.SentinelError"));
        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("result", "explicit-reply"));
}

static int reply_sentinel_explicit(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        ASSERT_NULL(error_id);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "result")), "explicit-reply");
        ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        return 0;
}

TEST(sentinel_with_explicit_reply) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.SentinelButReply", method_with_sentinel_but_reply));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        ASSERT_OK(sd_varlink_bind_reply(c, reply_sentinel_explicit));

        ASSERT_OK(sd_varlink_invoke(c, "io.test.SentinelButReply", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_oneway_sentinel(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* The method was called oneway, so varlink_set_sentinel() should be a no-op and the server should
         * transition back to idle without sending any reply. */
        ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_METHOD_ONEWAY));
        ASSERT_OK(varlink_set_sentinel(link, "io.test.SentinelError"));
        return 0;
}

static int method_oneway_sentinel_pong(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("result", "pong"));
}

static int reply_oneway_sentinel_pong(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        /* If we get here, it means the oneway sentinel call didn't break the connection and the server
         * properly handled a subsequent regular method call. */
        ASSERT_NULL(error_id);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "result")), "pong");
        ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        return 0;
}

TEST(sentinel_oneway) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.OnewaySentinel", method_with_oneway_sentinel));
        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.Pong", method_oneway_sentinel_pong));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        /* Send a oneway call with a sentinel — the sentinel should be silently ignored. */
        ASSERT_OK(sd_varlink_send(c, "io.test.OnewaySentinel", /* parameters= */ NULL));

        /* Follow up with a regular call to verify the server is still functional. */
        ASSERT_OK(sd_varlink_bind_reply(c, reply_oneway_sentinel_pong));
        ASSERT_OK(sd_varlink_invoke(c, "io.test.Pong", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_fd_sentinel(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_close_ int fd1 = -EBADF, fd2 = -EBADF;

        ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        /* Set a sentinel so sd_varlink_reply() defers sending: each reply and its pushed fds are captured in
         * the queue, and the last one is sent as the final reply when the callback returns. */
        ASSERT_OK(varlink_set_sentinel(link, /* error_id= */ NULL));

        /* First reply: push one fd with "alpha" content */
        ASSERT_OK(fd1 = memfd_new_and_seal_string("data", "alpha"));
        ASSERT_OK_EQ(sd_varlink_push_fd(link, fd1), 0);
        TAKE_FD(fd1);
        ASSERT_OK(sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_INTEGER("index", 0)));

        /* Second reply: push one fd with "beta" content */
        ASSERT_OK(fd2 = memfd_new_and_seal_string("data", "beta"));
        ASSERT_OK_EQ(sd_varlink_push_fd(link, fd2), 0);
        TAKE_FD(fd2);
        ASSERT_OK(sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_INTEGER("index", 1)));

        return 0;
}

static int reply_sentinel_fd(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        int *state = ASSERT_PTR(sd_varlink_get_userdata(link));

        if (*state == 0) {
                /* First reply: should carry "continues" flag and fd with "alpha" */
                ASSERT_NULL(error_id);
                ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
                ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_key(parameters, "index")), 0);

                int fd;
                ASSERT_OK(fd = sd_varlink_peek_fd(link, 0));
                test_fd(fd, "alpha", STRLEN("alpha"));
                (*state)++;
        } else if (*state == 1) {
                /* Second (final) reply: no "continues" flag, fd with "beta" */
                ASSERT_NULL(error_id);
                ASSERT_FALSE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
                ASSERT_EQ(sd_json_variant_integer(sd_json_variant_by_key(parameters, "index")), 1);

                int fd;
                ASSERT_OK(fd = sd_varlink_peek_fd(link, 0));
                test_fd(fd, "beta", STRLEN("beta"));

                ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        } else
                assert_not_reached();

        return 0;
}

TEST(sentinel_with_fds) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.FDSentinel", method_with_fd_sentinel));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));
        ASSERT_OK(sd_varlink_set_allow_fd_passing_input(c, true));
        ASSERT_OK(sd_varlink_set_allow_fd_passing_output(c, true));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        int state = 0;
        sd_varlink_set_userdata(c, &state);
        ASSERT_OK(sd_varlink_bind_reply(c, reply_sentinel_fd));

        ASSERT_OK(sd_varlink_observe(c, "io.test.FDSentinel", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

static int method_with_notify_then_error(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        /* Send a notify first, then return an error. The notify should be received before the error. */
        ASSERT_OK(sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_STRING("status", "in-progress")));
        return sd_varlink_error(link, "io.test.OperationFailed", /* parameters= */ NULL);
}

static int reply_notify_then_error(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        int *state = ASSERT_PTR(sd_varlink_get_userdata(link));

        if (*state == 0) {
                /* First callback: should be the notify (no error, has "more" flag) */
                ASSERT_NULL(error_id);
                ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
                ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "status")), "in-progress");
                (*state)++;
        } else if (*state == 1) {
                /* Second callback: should be the error */
                ASSERT_STREQ(error_id, "io.test.OperationFailed");
                ASSERT_FALSE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
                ASSERT_OK(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS));
        } else
                assert_not_reached();

        return 0;
}

TEST(notify_then_error) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        ASSERT_OK(sd_varlink_server_new(&s, 0));

        ASSERT_OK(sd_varlink_server_attach_event(s, e, 0));

        ASSERT_OK(sd_varlink_server_bind_method(s, "io.test.NotifyThenError", method_with_notify_then_error));

        int connfd[2];
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd));
        ASSERT_OK(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL));

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        ASSERT_OK(sd_varlink_connect_fd(&c, connfd[1]));

        ASSERT_OK(sd_varlink_attach_event(c, e, 0));

        int state = 0;
        sd_varlink_set_userdata(c, &state);
        ASSERT_OK(sd_varlink_bind_reply(c, reply_notify_then_error));

        ASSERT_OK(sd_varlink_observe(c, "io.test.NotifyThenError", /* parameters= */ NULL));

        ASSERT_OK(sd_event_loop(e));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
