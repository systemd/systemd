/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"
#include "sd-varlink-idl.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "memfd-util.h"
#include "serialize.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "varlink-internal.h"
#include "varlink-serialize.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                Hold,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_DEFINE_INPUT(value, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_INTERFACE(io_test_Serialize, "io.test.Serialize", &vl_method_Hold);

typedef struct Context {
        sd_varlink *call;
        const char *data;
        unsigned n_calls, n_replies;
} Context;

static int method_hold(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));
        c->n_calls++;
        c->call = sd_varlink_ref(link);
        return sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_STRING("data", c->data));
}

static void make_server(sd_varlink_server **ret, Context *c) {
        ASSERT_OK(sd_varlink_server_new(ret, SD_VARLINK_SERVER_INHERIT_USERDATA|
                                            SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|
                                            SD_VARLINK_SERVER_ACCOUNT_UID));
        sd_varlink_server_set_userdata(*ret, c);
        ASSERT_OK(sd_varlink_server_add_interface(*ret, &vl_interface_io_test_Serialize));
        ASSERT_OK(sd_varlink_server_bind_method(*ret, "io.test.Serialize.Hold", method_hold));
}

static int reply(sd_varlink *link, sd_json_variant *parameters, const char *error_id, sd_varlink_reply_flags_t flags, void *userdata) {
        Context *c = ASSERT_PTR(userdata);

        ASSERT_NULL(error_id);
        ASSERT_TRUE(FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "data")), c->data);
        c->n_replies++;
        return sd_event_exit(sd_varlink_get_event(link), EXIT_SUCCESS);
}

static void test_pending_stream(bool partial_write, bool disconnect) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL, *restored_server = NULL;
        _cleanup_(sd_varlink_close_unrefp) sd_varlink *client = NULL, *restored = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_pair_ int sockets[2] = EBADF_PAIR;
        _cleanup_close_ int passed_fd = ASSERT_OK(memfd_new_and_seal_string("passed-fd", "descriptor"));
        _cleanup_fdset_free_ FDSet *fds = ASSERT_NOT_NULL(fdset_new());
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *data = ASSERT_NOT_NULL(strrep("x", LONG_LINE_MAX)), *line = NULL;
        Context original = { .data = data }, restored_context = { .data = data };

        make_server(&server, &original);
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, sockets));
        int size = 4096;
        ASSERT_OK_ERRNO(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)));

        sd_varlink *accepted;
        ASSERT_OK(sd_varlink_server_add_connection(server, sockets[0], &accepted));
        TAKE_FD(sockets[0]);
        ASSERT_OK(sd_varlink_connect_fd(&client, sockets[1]));
        TAKE_FD(sockets[1]);
        ASSERT_OK(sd_varlink_set_allow_fd_passing_output(client, true));
        ASSERT_EQ(sd_varlink_push_dup_fd(client, passed_fd), 0);
        ASSERT_OK(sd_varlink_observebo(client, "io.test.Serialize.Hold", SD_JSON_BUILD_PAIR_STRING("value", "preserved")));
        ASSERT_OK(sd_varlink_flush(client));

        while (!original.call)
                ASSERT_OK_POSITIVE(sd_varlink_process(accepted));
        ASSERT_EQ(original.n_calls, 1U);
        ASSERT_GT(accepted->stream.output_buffer_size, (size_t) LONG_LINE_MAX);

        if (partial_write) {
                ASSERT_OK_POSITIVE(sd_varlink_process(accepted));
                ASSERT_GT(accepted->stream.output_buffer_index, 0U);
                ASSERT_GT(accepted->stream.output_buffer_size, 0U);
        }

        if (disconnect) {
                client = sd_varlink_close_unref(client);
                ASSERT_OK_POSITIVE(sd_varlink_wait(accepted, USEC_PER_SEC));
                while (accepted->state != VARLINK_PENDING_DISCONNECT)
                        ASSERT_OK_POSITIVE(sd_varlink_process(accepted));
        }

        uint64_t cookie;
        ASSERT_OK(varlink_get_socket_cookie(original.call, &cookie));
        ASSERT_OK(open_serialization_file("test-varlink", &f));
        ASSERT_OK(varlink_serialize(original.call, "connection", f, fds));
        ASSERT_EQ(fdset_size(fds), 2U); /* Only the socket and the received descriptor. */
        ASSERT_OK(finish_serialization_file(f));
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &line));
        ASSERT_STREQ(line, "connection");
        line = mfree(line);

        unsigned output_records = 0;
        while (ASSERT_OK(deserialize_read_line(f, &line)) > 0) {
                if (startswith(line, "output-buffer="))
                        output_records++;
                line = mfree(line);
        }
        ASSERT_GT(output_records, 1U);

        rewind(f);
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &line));
        ASSERT_OK(varlink_deserialize(/* s= */ NULL, f, fds));
        ASSERT_EQ(fdset_size(fds), 2U);
        line = mfree(line);
        rewind(f);
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &line));

        original.call = sd_varlink_close_unref(original.call);
        ASSERT_EQ(sd_varlink_server_current_connections(server), 0U);
        ASSERT_NULL(varlink_server_get_connection(server, cookie));

        make_server(&restored_server, &restored_context);
        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_varlink_server_attach_event(restored_server, event, 0));
        ASSERT_OK(varlink_deserialize(restored_server, f, fds));
        ASSERT_TRUE(fdset_isempty(fds));
        restored = sd_varlink_ref(ASSERT_NOT_NULL(varlink_server_get_connection(restored_server, cookie)));
        ASSERT_EQ(sd_varlink_server_current_connections(restored_server), 1U);

        uid_t uid;
        ASSERT_OK(sd_varlink_get_peer_uid(restored, &uid));
        ASSERT_EQ(uid, getuid());

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        ASSERT_OK(sd_varlink_get_current_parameters(restored, &parameters));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(parameters, "value")), "preserved");
        char buffer[STRLEN("descriptor")];
        ASSERT_EQ(pread(ASSERT_OK(sd_varlink_peek_fd(restored, 0)), buffer, sizeof(buffer), 0), (ssize_t) sizeof(buffer));
        ASSERT_EQ(memcmp(buffer, "descriptor", sizeof(buffer)), 0);

        if (disconnect) {
                ASSERT_OK_POSITIVE(sd_varlink_process(restored));
                ASSERT_FALSE(sd_varlink_is_connected(restored));
                ASSERT_EQ(sd_varlink_server_current_connections(restored_server), 0U);
                ASSERT_NULL(varlink_server_get_connection(restored_server, cookie));
                return;
        }

        sd_varlink_set_userdata(client, &restored_context);
        ASSERT_OK(sd_varlink_bind_reply(client, reply));
        ASSERT_OK(sd_varlink_set_relative_timeout(client, 5 * USEC_PER_SEC));
        ASSERT_OK(sd_varlink_attach_event(client, event, 0));
        ASSERT_OK(sd_event_loop(event));
        ASSERT_EQ(restored_context.n_replies, 1U);
        ASSERT_EQ(restored_context.n_calls, 0U);
}

TEST(pending_notification) {
        test_pending_stream(/* partial_write= */ false, /* disconnect= */ false);
}

TEST(partial_notification) {
        test_pending_stream(/* partial_write= */ true, /* disconnect= */ false);
}

TEST(pending_disconnect) {
        test_pending_stream(/* partial_write= */ false, /* disconnect= */ true);
}

TEST(invalid_connection_record) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_fdset_free_ FDSet *fds = ASSERT_NOT_NULL(fdset_new());
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        Context context = {};

        make_server(&server, &context);
        ASSERT_OK(open_serialization_file("test-varlink", &f));
        fputs("stream-flags=invalid\nsocket-cookie=1\n\nnext=record\n", f);
        ASSERT_OK(finish_serialization_file(f));
        ASSERT_ERROR(varlink_deserialize(server, f, fds), EINVAL);
        ASSERT_OK_POSITIVE(deserialize_read_line(f, &line));
        ASSERT_STREQ(line, "next=record");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
