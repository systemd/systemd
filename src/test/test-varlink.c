/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "fd-util.h"
#include "json-util.h"
#include "memfd-util.h"
#include "rm-rf.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"
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
        if (!a) {
                r = sd_varlink_error(link, "io.test.BadParameters", NULL);
                assert_se(r == -EBADR);
                return r;
        }

        x = sd_json_variant_integer(a);

        b = sd_json_variant_by_key(parameters, "b");
        if (!b) {
                r = sd_varlink_error(link, "io.test.BadParameters", NULL);
                assert_se(r == -EBADR);
                return r;
        }

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

        m = read(fd, rbuf, n + 1);
        assert_se(m >= 0);
        assert_se(memcmp_nn(buf, n, rbuf, m) == 0);
}

static int method_passfd(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ret = NULL;
        sd_json_variant *a;
        int r;

        a = sd_json_variant_by_key(parameters, "fd");
        if (!a) {
                r = sd_varlink_error_invalid_parameter_name(link, "fd");
                assert_se(r == -EINVAL);
                return r;
        }

        ASSERT_STREQ(sd_json_variant_string(a), "whoop");

        int xx = sd_varlink_peek_fd(link, 0),
                yy = sd_varlink_peek_fd(link, 1),
                zz = sd_varlink_peek_fd(link, 2);

        log_info("%i %i %i", xx, yy, zz);

        assert_se(xx >= 0);
        assert_se(yy >= 0);
        assert_se(zz >= 0);

        test_fd(xx, "foo", 3);
        test_fd(yy, "bar", 3);
        test_fd(zz, "quux", 4);

        _cleanup_close_ int vv = memfd_new_and_seal_string("data", "miau");
        _cleanup_close_ int ww = memfd_new_and_seal_string("data", "wuff");

        assert_se(vv >= 0);
        assert_se(ww >= 0);

        r = sd_json_build(&ret, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("yo", SD_JSON_BUILD_INTEGER(88))));
        if (r < 0)
                return r;

        assert_se(sd_varlink_push_fd(link, vv) == 0);
        assert_se(sd_varlink_push_fd(link, ww) == 1);

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

        assert_se(sd_json_variant_integer(sum) == 7+22);

        if (++n_done == 2)
                sd_event_exit(sd_varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int on_connect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        uid_t uid = UID_INVALID;

        assert_se(s);
        assert_se(link);

        assert_se(sd_varlink_get_peer_uid(link, &uid) >= 0);
        assert_se(getuid() == uid);
        assert_se(sd_varlink_set_allow_fd_passing_input(link, true) >= 0);
        assert_se(sd_varlink_set_allow_fd_passing_output(link, true) >= 0);

        return 0;
}

static int overload_reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {

        /* This method call reply should always be called with a disconnection, since the method call should
         * be talking to an overloaded server */

        log_debug("Over reply triggered with error: %s", strna(error_id));
        ASSERT_STREQ(error_id, SD_VARLINK_ERROR_DISCONNECTED);
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
        assert_se(write(block_write_fd, &x, sizeof(x)) == sizeof(x));

        assert_se(sd_event_default(&e) >= 0);

        /* Flood the server with connections */
        assert_se(connections = new0(sd_varlink*, OVERLOAD_CONNECTIONS));
        for (k = 0; k < OVERLOAD_CONNECTIONS; k++) {
                _cleanup_free_ char *t = NULL;
                log_debug("connection %zu", k);
                assert_se(sd_varlink_connect_address(connections + k, address) >= 0);

                assert_se(asprintf(&t, "flood-%zu", k) >= 0);
                assert_se(sd_varlink_set_description(connections[k], t) >= 0);
                assert_se(sd_varlink_attach_event(connections[k], e, k) >= 0);
                assert_se(sd_varlink_sendb(connections[k], "io.test.Rubbish", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_INTEGER(k)))) >= 0);
        }

        /* Then, create one more, which should fail */
        log_debug("Creating overload connection...");
        assert_se(sd_varlink_connect_address(&c, address) >= 0);
        assert_se(sd_varlink_set_description(c, "overload-client") >= 0);
        assert_se(sd_varlink_attach_event(c, e, k) >= 0);
        assert_se(sd_varlink_bind_reply(c, overload_reply) >= 0);
        assert_se(sd_varlink_invokeb(c, "io.test.Overload", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("foo", JSON_BUILD_CONST_STRING("bar")))) >= 0);

        /* Unblock it */
        log_debug("Unblocking server...");
        block_write_fd = safe_close(block_write_fd);

        /* This loop will terminate as soon as the overload reply callback is called */
        assert_se(sd_event_loop(e) >= 0);

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

        assert_se(sd_json_build(&i, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(88)),
                                                   SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_INTEGER(99)))) >= 0);

        assert_se(sd_varlink_connect_address(&c, arg) >= 0);
        assert_se(sd_varlink_set_description(c, "thread-client") >= 0);
        assert_se(sd_varlink_set_allow_fd_passing_input(c, true) >= 0);
        assert_se(sd_varlink_set_allow_fd_passing_output(c, true) >= 0);

        /* Test that client is able to perform two sequential sd_varlink_collect calls if first resulted in an error */
        assert_se(sd_json_build(&wrong, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(88)),
                                                       SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_INTEGER(99)))) >= 0);
        assert_se(sd_varlink_collect(c, "io.test.DoSomethingMore", wrong, &j, &error_id) >= 0);
        assert_se(strcmp_ptr(error_id, "org.varlink.service.InvalidParameter") == 0);

        assert_se(sd_varlink_collect(c, "io.test.DoSomethingMore", i, &j, &error_id) >= 0);

        assert_se(!error_id);
        assert_se(sd_json_variant_is_array(j) && !sd_json_variant_is_blank_array(j));

        JSON_VARIANT_ARRAY_FOREACH(k, j) {
                assert_se(sd_json_variant_integer(sd_json_variant_by_key(k, "sum")) == 88 + (99 * x));
                x++;
        }
        assert_se(x == 6);

        assert_se(sd_varlink_call(c, "io.test.DoSomething", i, &o, &e) >= 0);
        assert_se(sd_json_variant_integer(sd_json_variant_by_key(o, "sum")) == 88 + 99);
        assert_se(!e);

        int fd1 = memfd_new_and_seal_string("data", "foo");
        int fd2 = memfd_new_and_seal_string("data", "bar");
        int fd3 = memfd_new_and_seal_string("data", "quux");

        assert_se(fd1 >= 0);
        assert_se(fd2 >= 0);
        assert_se(fd3 >= 0);

        assert_se(sd_varlink_push_fd(c, fd1) == 0);
        assert_se(sd_varlink_push_fd(c, fd2) == 1);
        assert_se(sd_varlink_push_fd(c, fd3) == 2);

        assert_se(sd_varlink_callb(c, "io.test.PassFD", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("fd", SD_JSON_BUILD_STRING("whoop")))) >= 0);
        assert_se(!e);

        int fd4 = sd_varlink_peek_fd(c, 0);
        int fd5 = sd_varlink_peek_fd(c, 1);

        assert_se(fd4 >= 0);
        assert_se(fd5 >= 0);

        test_fd(fd4, "miau", 4);
        test_fd(fd5, "wuff", 4);

        assert_se(sd_varlink_callb(c, "io.test.PassFD", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("fdx", SD_JSON_BUILD_STRING("whoopx")))) >= 0);
        ASSERT_TRUE(sd_varlink_error_is_invalid_parameter(e, o, "fd"));

        assert_se(sd_varlink_callb(c, "io.test.IDontExist", &o, &e, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_REAL(5.5)))) >= 0);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(o, "method")), "io.test.IDontExist");
        ASSERT_STREQ(e, SD_VARLINK_ERROR_METHOD_NOT_FOUND);

        ASSERT_OK(sd_varlink_call(c, "io.test.FailWithErrno", NULL, &o, &e));
        ASSERT_ERROR(sd_varlink_error_to_errno(e, o), EHWPOISON);
        flood_test(arg);

        assert_se(sd_varlink_send(c, "io.test.Done", NULL) >= 0);

        return NULL;
}

static int block_fd_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        char c;

        assert_se(fd_nonblock(fd, false) >= 0);

        assert_se(read(fd, &c, sizeof(c)) == sizeof(c));
        /* When a character is written to this pipe we'll block until the pipe is closed. */

        assert_se(read(fd, &c, sizeof(c)) == 0);

        assert_se(fd_nonblock(fd, true) >= 0);

        assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);

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

        assert_se(mkdtemp_malloc("/tmp/varlink-test-XXXXXX", &tmpdir) >= 0);
        sp = strjoina(tmpdir, "/socket");

        assert_se(sd_event_default(&e) >= 0);

        assert_se(pipe2(block_fds, O_NONBLOCK|O_CLOEXEC) >= 0);
        assert_se(sd_event_add_io(e, &block_event, block_fds[0], EPOLLIN, block_fd_handler, NULL) >= 0);
        assert_se(sd_event_source_set_priority(block_event, SD_EVENT_PRIORITY_IMPORTANT) >= 0);
        block_write_fd = TAKE_FD(block_fds[1]);

        assert_se(varlink_server_new(&s, SD_VARLINK_SERVER_ACCOUNT_UID, NULL) >= 0);
        assert_se(sd_varlink_server_set_info(s, "Vendor", "Product", "Version", "URL") >= 0);
        assert_se(varlink_set_info_systemd(s) >= 0);
        assert_se(sd_varlink_server_set_description(s, "our-server") >= 0);

        assert_se(sd_varlink_server_bind_method(s, "io.test.PassFD", method_passfd) >= 0);
        assert_se(sd_varlink_server_bind_method(s, "io.test.DoSomething", method_something) >= 0);
        assert_se(sd_varlink_server_bind_method(s, "io.test.DoSomethingMore", method_something_more) >= 0);
        assert_se(sd_varlink_server_bind_method(s, "io.test.FailWithErrno", method_fail_with_errno) >= 0);
        assert_se(sd_varlink_server_bind_method(s, "io.test.Done", method_done) >= 0);
        assert_se(sd_varlink_server_bind_connect(s, on_connect) >= 0);
        assert_se(sd_varlink_server_listen_address(s, sp, 0600) >= 0);
        assert_se(sd_varlink_server_attach_event(s, e, 0) >= 0);
        assert_se(sd_varlink_server_set_connections_max(s, OVERLOAD_CONNECTIONS) >= 0);

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_INTEGER(7)),
                                                   SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_INTEGER(22)))) >= 0);

        assert_se(sd_varlink_connect_address(&c, sp) >= 0);
        assert_se(sd_varlink_set_description(c, "main-client") >= 0);
        assert_se(sd_varlink_bind_reply(c, reply) >= 0);

        assert_se(sd_varlink_invoke(c, "io.test.DoSomething", v) >= 0);

        assert_se(sd_varlink_attach_event(c, e, 0) >= 0);

        assert_se(pthread_create(&t, NULL, thread, (void*) sp) == 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(pthread_join(t, NULL) == 0);
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
        assert(sd_varlink_error_is_invalid_parameter(error_id, parameters, "idontexist"));
        assert(sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS) >= 0);
        return 0;
}

TEST(invalid_parameter) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        assert_se(sd_event_default(&e) >= 0);

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        assert_se(sd_varlink_server_new(&s, 0) >= 0);

        assert_se(sd_varlink_server_attach_event(s, e, 0) >= 0);

        assert_se(sd_varlink_server_bind_method(s, "foo.mytest.Invalid", method_invalid) >= 0);

        int connfd[2];
        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, connfd) >= 0);
        assert_se(sd_varlink_server_add_connection(s, connfd[0], /* ret= */ NULL) >= 0);

        _cleanup_(sd_varlink_unrefp) sd_varlink *c = NULL;
        assert_se(sd_varlink_connect_fd(&c, connfd[1]) >= 0);

        assert_se(sd_varlink_attach_event(c, e, 0) >= 0);

        assert_se(sd_varlink_bind_reply(c, reply_invalid) >= 0);

        assert_se(sd_varlink_invokebo(c, "foo.mytest.Invalid",
                                      SD_JSON_BUILD_PAIR_STRING("iexist", "foo"),
                                      SD_JSON_BUILD_PAIR_STRING("idontexist", "bar")) >= 0);

        assert_se(sd_event_loop(e) >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
