/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

#include "fd-util.h"
#include "tests.h"
#include "time-util.h"
#include "ovsdb/ovsdb-client.h"
#include "ovsdb/ovsdb-ops.h"

/* Read bytes from a non-blocking fd until we have a complete JSON object (brace depth returns to 0).
 * Uses poll() to wait for data with a timeout. Returns message length or negative errno. */
static ssize_t read_json_message(int fd, char *buf, size_t bufsize) {
        size_t pos = 0;
        int depth = 0;
        bool started = false, in_string = false, escape_next = false;

        for (;;) {
                char ch;
                ssize_t n;
                struct pollfd pfd = { .fd = fd, .events = POLLIN };

                ASSERT_LT(pos, bufsize);

                n = read(fd, &ch, 1);
                if (n < 0) {
                        if (errno == EAGAIN) {
                                if (poll(&pfd, 1, 5000) <= 0)
                                        return -ETIMEDOUT;
                                continue;
                        }
                        return -errno;
                }
                if (n == 0)
                        return -ECONNRESET;

                buf[pos++] = ch;

                if (in_string) {
                        if (escape_next) {
                                escape_next = false;
                                continue;
                        }
                        if (ch == '\\') {
                                escape_next = true;
                                continue;
                        }
                        if (ch == '"')
                                in_string = false;
                        continue;
                }

                if (ch == '"') {
                        in_string = true;
                } else if (ch == '{') {
                        depth++;
                        started = true;
                } else if (ch == '}') {
                        depth--;
                        if (started && depth == 0) {
                                buf[pos] = '\0';
                                return (ssize_t) pos;
                        }
                }
        }
}

TEST(client_handshake_success) {
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        char buf[4096];
        ssize_t n;
        static const char schema_reply[] =
                "{\"id\":1,\"result\":{\"name\":\"Open_vSwitch\",\"version\":\"8.8.0\","
                "\"tables\":{\"Open_vSwitch\":{\"columns\":{\"bridges\":{}}},"
                "\"Bridge\":{\"columns\":{\"name\":{},\"ports\":{}}},"
                "\"Port\":{\"columns\":{\"name\":{},\"interfaces\":{}}},"
                "\"Interface\":{\"columns\":{\"name\":{},\"type\":{}}}}},"
                "\"error\":null}";

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));

        /* Client takes ownership of fds[0]; we use fds[1] as the "server" side */
        ASSERT_OK(ovsdb_client_new_from_fd(&c, e, fds[0]));
        fds[0] = -EBADF; /* fd is now owned by the client */

        ASSERT_EQ(ovsdb_client_get_state(c), OVSDB_CLIENT_DISCONNECTED);
        ASSERT_OK(ovsdb_client_start(c));
        ASSERT_EQ(ovsdb_client_get_state(c), OVSDB_CLIENT_HANDSHAKING);

        /* Drive the event loop so the client flushes its output */
        for (int i = 0; i < 50; i++)
                (void) sd_event_run(e, 10 * USEC_PER_MSEC);

        /* Read the get_schema request from the server side */
        n = read_json_message(fds[1], buf, sizeof(buf));
        ASSERT_GT(n, 0);
        ASSERT_NOT_NULL(strstr(buf, "get_schema"));

        /* Write the schema reply */
        ASSERT_EQ((ssize_t) strlen(schema_reply), write(fds[1], schema_reply, strlen(schema_reply)));

        /* Drive the event loop until the client processes the reply */
        for (int i = 0; i < 200 && ovsdb_client_get_state(c) == OVSDB_CLIENT_HANDSHAKING; i++)
                ASSERT_OK(sd_event_run(e, 50 * USEC_PER_MSEC));

        ASSERT_EQ(ovsdb_client_get_state(c), OVSDB_CLIENT_READY);
        ASSERT_NOT_NULL(ovsdb_client_get_schema(c));
}

TEST(client_schema_failure) {
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        char buf[4096];
        ssize_t n;
        /* Schema missing Bridge table */
        static const char bad_schema_reply[] =
                "{\"id\":1,\"result\":{\"name\":\"Open_vSwitch\",\"version\":\"8.8.0\","
                "\"tables\":{\"Open_vSwitch\":{\"columns\":{\"bridges\":{}}},"
                "\"Port\":{\"columns\":{\"name\":{},\"interfaces\":{}}},"
                "\"Interface\":{\"columns\":{\"name\":{},\"type\":{}}}}},"
                "\"error\":null}";

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));

        ASSERT_OK(ovsdb_client_new_from_fd(&c, e, fds[0]));
        fds[0] = -EBADF;

        ASSERT_OK(ovsdb_client_start(c));

        /* Drive the event loop so the client flushes its output */
        for (int i = 0; i < 50; i++)
                (void) sd_event_run(e, 10 * USEC_PER_MSEC);

        /* Read and discard the get_schema request */
        n = read_json_message(fds[1], buf, sizeof(buf));
        ASSERT_GT(n, 0);

        /* Write the bad schema reply */
        ASSERT_EQ((ssize_t) strlen(bad_schema_reply), write(fds[1], bad_schema_reply, strlen(bad_schema_reply)));

        /* Drive the event loop until the client processes the reply */
        for (int i = 0; i < 200 && ovsdb_client_get_state(c) == OVSDB_CLIENT_HANDSHAKING; i++)
                ASSERT_OK(sd_event_run(e, 50 * USEC_PER_MSEC));

        ASSERT_EQ(ovsdb_client_get_state(c), OVSDB_CLIENT_FAILED);
}

/* Helper to drive event loop + handshake a client to READY state */
static void drive_handshake(sd_event *e, OVSDBClient *c, int server_fd) {
        char buf[4096];
        ssize_t n;
        static const char schema_reply[] =
                "{\"id\":1,\"result\":{\"name\":\"Open_vSwitch\",\"version\":\"8.8.0\","
                "\"tables\":{\"Open_vSwitch\":{\"columns\":{\"bridges\":{}}},"
                "\"Bridge\":{\"columns\":{\"name\":{},\"ports\":{}}},"
                "\"Port\":{\"columns\":{\"name\":{},\"interfaces\":{}}},"
                "\"Interface\":{\"columns\":{\"name\":{},\"type\":{}}}}},"
                "\"error\":null}";

        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 50; i++)
                (void) sd_event_run(e, 10 * USEC_PER_MSEC);

        n = read_json_message(server_fd, buf, sizeof(buf));
        ASSERT_GT(n, 0);
        ASSERT_NOT_NULL(strstr(buf, "get_schema"));

        ASSERT_EQ((ssize_t) strlen(schema_reply), write(server_fd, schema_reply, strlen(schema_reply)));

        for (int i = 0; i < 200 && ovsdb_client_get_state(c) == OVSDB_CLIENT_HANDSHAKING; i++)
                ASSERT_OK(sd_event_run(e, 50 * USEC_PER_MSEC));

        ASSERT_EQ(ovsdb_client_get_state(c), OVSDB_CLIENT_READY);
}

TEST(client_transact) {
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op = NULL, *ops = NULL, *row = NULL;
        char buf[8192];
        ssize_t n;

        ASSERT_OK(sd_event_default(&e));
        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));

        ASSERT_OK(ovsdb_client_new_from_fd(&c, e, fds[0]));
        fds[0] = -EBADF;

        drive_handshake(e, c, fds[1]);

        /* Build a simple insert operation */
        ASSERT_OK(sd_json_build(&row,
                        SD_JSON_BUILD_OBJECT(
                                SD_JSON_BUILD_PAIR_STRING("name", "br0"))));
        ASSERT_OK(ovsdb_op_insert("Bridge", /* uuid_name= */ NULL, row, &op));

        /* Wrap op in an array */
        sd_json_variant *op_arr[] = { op };
        ASSERT_OK(sd_json_variant_new_array(&ops, op_arr, 1));

        /* Send transact */
        ASSERT_OK(ovsdb_client_transact(c, ops, /* cb= */ NULL, /* userdata= */ NULL));

        /* Drive event loop to flush output */
        for (int i = 0; i < 50; i++)
                (void) sd_event_run(e, 10 * USEC_PER_MSEC);

        /* Read the transact message from the server side */
        n = read_json_message(fds[1], buf, sizeof(buf));
        ASSERT_GT(n, 0);
        ASSERT_NOT_NULL(strstr(buf, "transact"));
        ASSERT_NOT_NULL(strstr(buf, "Open_vSwitch"));
        ASSERT_NOT_NULL(strstr(buf, "insert"));
        ASSERT_NOT_NULL(strstr(buf, "Bridge"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
