/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>

#include "sd-event.h"

#include "fd-util.h"
#include "json.h"
#include "rm-rf.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "varlink.h"

/* Let's pick some high value, that is higher than the largest listen() backlog, but leaves enough room below
   the typical RLIMIT_NOFILE value of 1024 so that we can process both sides of each socket in our
   process. Or in other words: "OVERLOAD_CONNECTIONS * 2 + x < 1024" should hold, for some small x that
   should cover any auxiliary fds, the listener server fds, stdin/stdout/stderr and whatever else. */
#define OVERLOAD_CONNECTIONS 333

static int n_done = 0;
static int block_write_fd = -1;

static int method_something(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *ret = NULL;
        JsonVariant *a, *b;
        intmax_t x, y;
        int r;

        a = json_variant_by_key(parameters, "a");
        if (!a)
                return varlink_error(link, "io.test.BadParameters", NULL);

        x = json_variant_integer(a);

        b = json_variant_by_key(parameters, "b");
        if (!b)
                return varlink_error(link, "io.test.BadParameters", NULL);

        y = json_variant_integer(b);

        r = json_build(&ret, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("sum", JSON_BUILD_INTEGER(x + y))));
        if (r < 0)
                return r;

        return varlink_reply(link, ret);
}

static int method_done(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        if (++n_done == 2)
                sd_event_exit(varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int reply(Varlink *link, JsonVariant *parameters, const char *error_id, VarlinkReplyFlags flags, void *userdata) {
        JsonVariant *sum;

        sum = json_variant_by_key(parameters, "sum");

        assert_se(json_variant_integer(sum) == 7+22);

        if (++n_done == 2)
                sd_event_exit(varlink_get_event(link), EXIT_FAILURE);

        return 0;
}

static int on_connect(VarlinkServer *s, Varlink *link, void *userdata) {
        uid_t uid = UID_INVALID;

        assert(s);
        assert(link);

        assert_se(varlink_get_peer_uid(link, &uid) >= 0);
        assert_se(getuid() == uid);

        return 0;
}

static int overload_reply(Varlink *link, JsonVariant *parameters, const char *error_id, VarlinkReplyFlags flags, void *userdata) {

        /* This method call reply should always be called with a disconnection, since the method call should
         * be talking to an overloaded server */

        log_debug("Over reply triggered with error: %s", strna(error_id));
        assert_se(streq(error_id, VARLINK_ERROR_DISCONNECTED));
        sd_event_exit(varlink_get_event(link), 0);

        return 0;
}

static void flood_test(const char *address) {
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_free_ Varlink **connections = NULL;
        size_t k;
        char x = 'x';

        log_debug("Flooding server...");

        /* Block the main event loop while we flood */
        assert_se(write(block_write_fd, &x, sizeof(x)) == sizeof(x));

        assert_se(sd_event_default(&e) >= 0);

        /* Flood the server with connections */
        assert_se(connections = new0(Varlink*, OVERLOAD_CONNECTIONS));
        for (k = 0; k < OVERLOAD_CONNECTIONS; k++) {
                _cleanup_free_ char *t = NULL;
                log_debug("connection %zu", k);
                assert_se(varlink_connect_address(connections + k, address) >= 0);

                assert_se(asprintf(&t, "flood-%zu", k) >= 0);
                assert_se(varlink_set_description(connections[k], t) >= 0);
                assert_se(varlink_attach_event(connections[k], e, k) >= 0);
                assert_se(varlink_sendb(connections[k], "io.test.Rubbish", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("id", JSON_BUILD_INTEGER(k)))) >= 0);
        }

        /* Then, create one more, which should fail */
        log_debug("Creating overload connection...");
        assert_se(varlink_connect_address(&c, address) >= 0);
        assert_se(varlink_set_description(c, "overload-client") >= 0);
        assert_se(varlink_attach_event(c, e, k) >= 0);
        assert_se(varlink_bind_reply(c, overload_reply) >= 0);
        assert_se(varlink_invokeb(c, "io.test.Overload", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("foo", JSON_BUILD_STRING("bar")))) >= 0);

        /* Unblock it */
        log_debug("Unblocking server...");
        block_write_fd = safe_close(block_write_fd);

        /* This loop will terminate as soon as the overload reply callback is called */
        assert_se(sd_event_loop(e) >= 0);

        /* And close all connections again */
        for (k = 0; k < OVERLOAD_CONNECTIONS; k++)
                connections[k] = varlink_unref(connections[k]);
}

static void *thread(void *arg) {
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *i = NULL;
        JsonVariant *o = NULL;
        const char *e;

        assert_se(json_build(&i, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("a", JSON_BUILD_INTEGER(88)),
                                                   JSON_BUILD_PAIR("b", JSON_BUILD_INTEGER(99)))) >= 0);

        assert_se(varlink_connect_address(&c, arg) >= 0);
        assert_se(varlink_set_description(c, "thread-client") >= 0);

        assert_se(varlink_call(c, "io.test.DoSomething", i, &o, &e, NULL) >= 0);
        assert_se(json_variant_integer(json_variant_by_key(o, "sum")) == 88 + 99);
        assert_se(!e);

        assert_se(varlink_callb(c, "io.test.IDontExist", &o, &e, NULL, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("x", JSON_BUILD_REAL(5.5)))) >= 0);
        assert_se(streq_ptr(json_variant_string(json_variant_by_key(o, "method")), "io.test.IDontExist"));
        assert_se(streq(e, VARLINK_ERROR_METHOD_NOT_FOUND));

        flood_test(arg);

        assert_se(varlink_send(c, "io.test.Done", NULL) >= 0);

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

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *block_event = NULL;
        _cleanup_(varlink_server_unrefp) VarlinkServer *s = NULL;
        _cleanup_(varlink_flush_close_unrefp) Varlink *c = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmpdir = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(close_pairp) int block_fds[2] = { -1, -1 };
        pthread_t t;
        const char *sp;

        log_set_max_level(LOG_DEBUG);
        log_open();

        assert_se(mkdtemp_malloc("/tmp/varlink-test-XXXXXX", &tmpdir) >= 0);
        sp = strjoina(tmpdir, "/socket");

        assert_se(sd_event_default(&e) >= 0);

        assert_se(pipe2(block_fds, O_NONBLOCK|O_CLOEXEC) >= 0);
        assert_se(sd_event_add_io(e, &block_event, block_fds[0], EPOLLIN, block_fd_handler, NULL) >= 0);
        assert_se(sd_event_source_set_priority(block_event, SD_EVENT_PRIORITY_IMPORTANT) >= 0);
        block_write_fd = TAKE_FD(block_fds[1]);

        assert_se(varlink_server_new(&s, VARLINK_SERVER_ACCOUNT_UID) >= 0);
        assert_se(varlink_server_set_description(s, "our-server") >= 0);

        assert_se(varlink_server_bind_method(s, "io.test.DoSomething", method_something) >= 0);
        assert_se(varlink_server_bind_method(s, "io.test.Done", method_done) >= 0);
        assert_se(varlink_server_bind_connect(s, on_connect) >= 0);
        assert_se(varlink_server_listen_address(s, sp, 0600) >= 0);
        assert_se(varlink_server_attach_event(s, e, 0) >= 0);
        assert_se(varlink_server_set_connections_max(s, OVERLOAD_CONNECTIONS) >= 0);

        assert_se(varlink_connect_address(&c, sp) >= 0);
        assert_se(varlink_set_description(c, "main-client") >= 0);
        assert_se(varlink_bind_reply(c, reply) >= 0);

        assert_se(json_build(&v, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("a", JSON_BUILD_INTEGER(7)),
                                                   JSON_BUILD_PAIR("b", JSON_BUILD_INTEGER(22)))) >= 0);

        assert_se(varlink_invoke(c, "io.test.DoSomething", v) >= 0);

        assert_se(varlink_attach_event(c, e, 0) >= 0);

        assert_se(pthread_create(&t, NULL, thread, (void*) sp) == 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(pthread_join(t, NULL) == 0);

        return 0;
}
