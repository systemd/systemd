/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <unistd.h>

#include "sd-json.h"

#include "fd-util.h"
#include "io-util.h"
#include "json-stream.h"
#include "tests.h"

TEST(find_message_end_simple_object) {
        const char *buf = "{\"id\":1}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_simple_array) {
        const char *buf = "[1,2,3]";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_nested) {
        const char *buf = "{\"a\":{\"b\":[1,2]}}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_with_leading_whitespace) {
        const char *buf = "  \t\n{\"id\":1}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_back_to_back) {
        const char *buf = "{\"id\":1}{\"id\":2}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        /* Should only consume the first message */
        ASSERT_EQ(consumed, strlen("{\"id\":1}"));
}

TEST(find_message_end_string_with_escapes) {
        const char *buf = "{\"key\":\"val\\\"ue\"}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_string_with_backslash_escape) {
        const char *buf = "{\"key\":\"val\\\\\"}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

TEST(find_message_end_incomplete) {
        const char *buf = "{\"id\":1";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_ZERO(r);
        ASSERT_EQ(consumed, 0u);
}

TEST(find_message_end_empty) {
        size_t consumed;
        int r;

        r = json_stream_find_message_end(NULL, 0, &consumed);
        ASSERT_OK_ZERO(r);
        ASSERT_EQ(consumed, 0u);

        r = json_stream_find_message_end("", 0, &consumed);
        ASSERT_OK_ZERO(r);
        ASSERT_EQ(consumed, 0u);
}

TEST(find_message_end_only_whitespace) {
        const char *buf = "   \n\t  ";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_ZERO(r);
        ASSERT_EQ(consumed, 0u);
}

TEST(find_message_end_bad_leading_char) {
        const char *buf = "hello";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_EQ(r, -EBADMSG);
        ASSERT_EQ(consumed, 0u);
}

TEST(find_message_end_braces_inside_string) {
        /* Braces inside strings should not affect depth counting */
        const char *buf = "{\"key\":\"{}\"}";
        size_t consumed;
        int r;

        r = json_stream_find_message_end(buf, strlen(buf), &consumed);
        ASSERT_OK_POSITIVE(r);
        ASSERT_EQ(consumed, strlen(buf));
}

static JsonStreamPhase test_phase_cb(void *userdata) {
        return JSON_STREAM_PHASE_READING;
}

static int test_dispatch_cb(void *userdata) {
        return 0;
}

TEST(json_stream_delimiterless_roundtrip) {
        /* Create socketpair, init JsonStream with delimiterless flag,
         * write two back-to-back JSON objects to the peer side,
         * drive reads and verify both messages parse correctly. */
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v1 = NULL, *v2 = NULL;
        int r;

        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));

        ASSERT_OK(json_stream_init(&s, &(JsonStreamParams) {
                .phase = test_phase_cb,
                .dispatch = test_dispatch_cb,
        }));

        json_stream_set_flags(&s, JSON_STREAM_DELIMITERLESS, true);

        ASSERT_OK(json_stream_connect_fd_pair(&s, fds[0], fds[0]));
        fds[0] = -EBADF; /* stream owns it now */

        /* Write two back-to-back JSON objects with no delimiter to the peer fd */
        const char *wire = "{\"id\":1,\"result\":\"ok\"}{\"id\":2,\"method\":\"echo\"}";
        ASSERT_OK(loop_write(fds[1], wire, strlen(wire)));
        close(fds[1]);
        fds[1] = -EBADF;

        /* Read data from the socket into the stream's input buffer */
        r = json_stream_read(&s);
        ASSERT_OK(r);

        /* Parse first message */
        r = json_stream_parse(&s, &v1);
        ASSERT_OK_POSITIVE(r);
        ASSERT_NOT_NULL(v1);

        sd_json_variant *id1 = sd_json_variant_by_key(v1, "id");
        ASSERT_NOT_NULL(id1);
        ASSERT_EQ(sd_json_variant_integer(id1), 1);

        sd_json_variant *result = sd_json_variant_by_key(v1, "result");
        ASSERT_NOT_NULL(result);
        ASSERT_STREQ(sd_json_variant_string(result), "ok");

        /* Parse second message */
        r = json_stream_parse(&s, &v2);
        ASSERT_OK_POSITIVE(r);
        ASSERT_NOT_NULL(v2);

        sd_json_variant *id2 = sd_json_variant_by_key(v2, "id");
        ASSERT_NOT_NULL(id2);
        ASSERT_EQ(sd_json_variant_integer(id2), 2);

        sd_json_variant *method = sd_json_variant_by_key(v2, "method");
        ASSERT_NOT_NULL(method);
        ASSERT_STREQ(sd_json_variant_string(method), "echo");

        json_stream_done(&s);
}

TEST(json_stream_delimiterless_partial_reads) {
        /* Verify that a message arriving in multiple TCP segments parses correctly.
         * This exercises the fix for the scan-from-partial-buffer bug: after an
         * incomplete parse, input_buffer_unscanned must remain equal to
         * input_buffer_size so that the next parse re-scans from the beginning. */
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        JsonStream s = {};
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        ASSERT_OK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));

        ASSERT_OK(json_stream_init(&s, &(JsonStreamParams) {
                .phase = test_phase_cb,
                .dispatch = test_dispatch_cb,
        }));

        json_stream_set_flags(&s, JSON_STREAM_DELIMITERLESS, true);

        ASSERT_OK(json_stream_connect_fd_pair(&s, fds[0], fds[0]));
        fds[0] = -EBADF; /* stream owns it now */

        /* Write first half of the JSON message */
        const char *part1 = "{\"id\":1,";
        ASSERT_OK(loop_write(fds[1], part1, strlen(part1)));

        /* Read partial data into the stream buffer */
        r = json_stream_read(&s);
        ASSERT_OK(r);

        /* Attempt to parse — should return 0 (incomplete) */
        r = json_stream_parse(&s, &v);
        ASSERT_OK_ZERO(r);
        ASSERT_NULL(v);

        /* Write second half of the JSON message and close */
        const char *part2 = "\"result\":\"ok\"}";
        ASSERT_OK(loop_write(fds[1], part2, strlen(part2)));
        close(fds[1]);
        fds[1] = -EBADF;

        /* Read remaining data */
        r = json_stream_read(&s);
        ASSERT_OK(r);

        /* Parse again — should now succeed */
        r = json_stream_parse(&s, &v);
        ASSERT_OK_POSITIVE(r);
        ASSERT_NOT_NULL(v);

        sd_json_variant *id = sd_json_variant_by_key(v, "id");
        ASSERT_NOT_NULL(id);
        ASSERT_EQ(sd_json_variant_integer(id), 1);

        sd_json_variant *result = sd_json_variant_by_key(v, "result");
        ASSERT_NOT_NULL(result);
        ASSERT_STREQ(sd_json_variant_string(result), "ok");

        json_stream_done(&s);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
