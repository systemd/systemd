/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "json-stream.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"

#define PARTIAL_TIMEOUT_USEC (200U * USEC_PER_MSEC)

static JsonStreamPhase test_phase(void *userdata) {
        return *(JsonStreamPhase*) ASSERT_PTR(userdata);
}

static int test_dispatch(void *userdata) {
        return 0;
}

static void stream_setup(JsonStream *s, JsonStreamPhase *phase, int fds[static 2]) {
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, fds));

        ASSERT_OK(json_stream_init(
                                s,
                                &(JsonStreamParams) {
                                        .phase = test_phase,
                                        .dispatch = test_dispatch,
                                        .userdata = phase,
                                        .partial_message_timeout = PARTIAL_TIMEOUT_USEC,
                                }));

        ASSERT_OK(json_stream_attach_fds(s, fds[0], fds[0]));
        fds[0] = -EBADF; /* owned by the stream now */
}

/* Reads and parses until a message is available or an error is returned, waiting for input in between */
static int stream_read_message(JsonStream *s, sd_json_variant **ret) {
        int r;

        for (;;) {
                r = json_stream_parse(s, ret);
                if (r != 0)
                        return r;

                r = json_stream_read(s);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                ASSERT_OK(json_stream_wait(s, USEC_INFINITY));
        }
}

TEST(partial_input_timeout) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        JsonStreamPhase phase = JSON_STREAM_PHASE_READING;

        stream_setup(&s, &phase, fds);

        /* A complete message is fine */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK_EQ_ERRNO(write(fds[1], "{\"a\":1}", 8), 8);
        ASSERT_OK_POSITIVE(stream_read_message(&s, &v));
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(v, "a")), 1u);
        v = sd_json_variant_unref(v);

        /* Between messages no deadline applies */
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK_ZERO(json_stream_wait(&s, 2 * PARTIAL_TIMEOUT_USEC));
        ASSERT_OK_ZERO(json_stream_read(&s));

        /* A message that is completed in time is fine too */
        ASSERT_OK_EQ_ERRNO(write(fds[1], "{\"b\":", 5), 5);
        ASSERT_OK_POSITIVE(json_stream_read(&s));
        ASSERT_OK_ZERO(json_stream_parse(&s, &v));
        ASSERT_NE(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK_EQ_ERRNO(write(fds[1], "2}", 3), 3);
        ASSERT_OK_POSITIVE(stream_read_message(&s, &v));
        ASSERT_EQ(sd_json_variant_unsigned(sd_json_variant_by_key(v, "b")), 2u);
        v = sd_json_variant_unref(v);
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);

        /* Start a message, and don't complete it. If the consumer isn't reading, no deadline applies. */
        ASSERT_OK_EQ_ERRNO(write(fds[1], "{\"c\":", 5), 5);
        ASSERT_OK_POSITIVE(json_stream_read(&s));
        ASSERT_OK_ZERO(json_stream_parse(&s, &v));
        phase = JSON_STREAM_PHASE_OTHER;
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        phase = JSON_STREAM_PHASE_READING;
        ASSERT_NE(json_stream_get_timeout(&s), USEC_INFINITY);

        /* Trickling in more bytes doesn't extend the deadline */
        usec_t deadline = json_stream_get_timeout(&s);
        ASSERT_OK_EQ_ERRNO(write(fds[1], "  ", 2), 2);
        ASSERT_OK_POSITIVE(json_stream_read(&s));
        ASSERT_OK_ZERO(json_stream_parse(&s, &v));
        ASSERT_EQ(json_stream_get_timeout(&s), deadline);

        /* Also get stuck in the middle of writing a message, so that an output deadline is armed too */
        _cleanup_free_ char *big = ASSERT_NOT_NULL(new(char, 4U * 1024U * 1024U + 1));
        memset(big, 'x', 4U * 1024U * 1024U);
        big[4U * 1024U * 1024U] = 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        ASSERT_OK(sd_json_buildo(&w, SD_JSON_BUILD_PAIR_STRING("big", big)));
        ASSERT_OK(json_stream_enqueue(&s, w));

        int r;
        while ((r = json_stream_write(&s)) > 0)
                ;
        ASSERT_OK_ZERO(r);
        ASSERT_OK_POSITIVE(json_stream_has_buffered_output(&s));
        ASSERT_EQ(json_stream_get_timeout(&s), deadline);

        usec_t start = now(CLOCK_MONOTONIC);
        ASSERT_ERROR(stream_read_message(&s, &v), ETIMEDOUT);
        ASSERT_GE(now(CLOCK_MONOTONIC), deadline);
        ASSERT_LT(now(CLOCK_MONOTONIC) - start, 10 * PARTIAL_TIMEOUT_USEC);

        /* The stream is dead in both directions now, and neither the elapsed input deadline nor the
         * pending output deadline is in force anymore, even after the latter elapsed */
        ASSERT_TRUE(FLAGS_SET(s.flags, JSON_STREAM_READ_DISCONNECTED|JSON_STREAM_WRITE_DISCONNECTED));
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK(usleep_safe(2 * PARTIAL_TIMEOUT_USEC));
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK_ZERO(json_stream_read(&s));
        ASSERT_OK_ZERO(json_stream_write(&s));
}

TEST(partial_output_timeout) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        JsonStreamPhase phase = JSON_STREAM_PHASE_OTHER;
        int r;

        stream_setup(&s, &phase, fds);

        /* A message much larger than what the socket buffers can take */
        _cleanup_free_ char *big = ASSERT_NOT_NULL(new(char, 4U * 1024U * 1024U + 1));
        memset(big, 'x', 4U * 1024U * 1024U);
        big[4U * 1024U * 1024U] = 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK(sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("big", big)));
        ASSERT_OK(json_stream_enqueue(&s, v));

        /* Write until the socket buffer is full, we are now in the middle of the message */
        while ((r = json_stream_write(&s)) > 0)
                ;
        ASSERT_OK_ZERO(r);
        ASSERT_OK_POSITIVE(json_stream_has_buffered_output(&s));
        ASSERT_NE(json_stream_get_timeout(&s), USEC_INFINITY);

        /* Draining the socket on the other side makes progress, but doesn't extend the deadline */
        usec_t deadline = json_stream_get_timeout(&s);
        for (;;) {
                char buf[64U * 1024U];
                ssize_t n = read(fds[1], buf, sizeof(buf));
                if (n < 0 && errno == EAGAIN)
                        break;
                ASSERT_GT(n, 0);
        }
        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_EQ(json_stream_get_timeout(&s), deadline);

        ASSERT_ERROR(json_stream_flush(&s), ETIMEDOUT);
        ASSERT_GE(now(CLOCK_MONOTONIC), deadline);

        /* The stream is dead in both directions now, and the elapsed deadline is not in force anymore */
        ASSERT_TRUE(FLAGS_SET(s.flags, JSON_STREAM_READ_DISCONNECTED|JSON_STREAM_WRITE_DISCONNECTED));
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK_ZERO(json_stream_write(&s));
        ASSERT_OK_ZERO(json_stream_read(&s));
}

TEST(partial_output_boundary) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_close_pair_ int fds[2] = EBADF_PAIR;
        JsonStreamPhase phase = JSON_STREAM_PHASE_OTHER;

        stream_setup(&s, &phase, fds);

        /* Messages that are written out in full leave no deadline behind, regardless how long the peer
         * takes to read them */
        for (unsigned i = 0; i < 3; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                ASSERT_OK(sd_json_buildo(&v, SD_JSON_BUILD_PAIR_UNSIGNED("i", i)));
                ASSERT_OK(json_stream_enqueue(&s, v));
        }

        ASSERT_OK(json_stream_flush(&s));
        ASSERT_EQ(json_stream_get_timeout(&s), USEC_INFINITY);
        ASSERT_OK_ZERO(json_stream_has_buffered_output(&s));
}

static void drain_pipe(int fd) {
        for (;;) {
                char buf[4096];
                ssize_t n = read(fd, buf, sizeof(buf));
                if (n < 0 && errno == EAGAIN)
                        return;
                ASSERT_GT(n, 0);
        }
}

TEST(partial_output_delimiter) {
        _cleanup_(json_stream_done) JsonStream s = {};
        _cleanup_close_pair_ int in[2] = EBADF_PAIR, out[2] = EBADF_PAIR;
        JsonStreamPhase phase = JSON_STREAM_PHASE_OTHER;
        int r;

        /* Use a multi-byte delimiter whose last byte may appear inside messages, and a pipe with a fixed
         * capacity of 4096 bytes, so that we control exactly where writes stop. */
        ASSERT_OK(json_stream_init(
                                &s,
                                &(JsonStreamParams) {
                                        .delimiter = "XY",
                                        .phase = test_phase,
                                        .dispatch = test_dispatch,
                                        .userdata = &phase,
                                        .partial_message_timeout = PARTIAL_TIMEOUT_USEC,
                                }));

        ASSERT_OK_ERRNO(pipe2(in, O_NONBLOCK|O_CLOEXEC));
        ASSERT_OK_ERRNO(pipe2(out, O_NONBLOCK|O_CLOEXEC));
        r = fcntl(out[1], F_SETPIPE_SZ, 4096);
        if (r < 0)
                return (void) log_tests_skipped_errno(errno, "Failed to set pipe size");
        if (r != 4096)
                return (void) log_tests_skipped("Pipe size is not 4096");

        ASSERT_OK(json_stream_attach_fds(&s, in[0], out[1]));
        in[0] = out[1] = -EBADF;

        /* A message of exactly 4095 bytes, i.e. its delimiter will be split between two writes. Its
         * contents end in the last delimiter byte. */
        _cleanup_free_ char *ys = ASSERT_NOT_NULL(strrep("Y", 4095 - STRLEN("{\"x\":\"\"}")));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        ASSERT_OK(sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("x", ys)));
        ASSERT_OK(json_stream_enqueue(&s, v));
        ASSERT_OK(json_stream_enqueue(&s, v));

        /* First write: the message and the first delimiter byte. Mid-message, hence the clock starts. */
        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_OK_ZERO(json_stream_write(&s));
        ASSERT_EQ(s.output_buffer_size, 2 * 4097u - 4096u);
        usec_t since = s.output_partial_since;
        ASSERT_NE(since, USEC_INFINITY);

        /* Second write: the second delimiter byte, and the 2nd message, without its delimiter. That
         * completed the first message, hence the clock is restarted. */
        usleep_safe(10 * USEC_PER_MSEC);
        drain_pipe(out[0]);
        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_OK_ZERO(json_stream_write(&s));
        ASSERT_NE(s.output_partial_since, USEC_INFINITY);
        ASSERT_GT(s.output_partial_since, since);
        ASSERT_EQ(s.output_buffer_size, 2u);

        /* Third write: just the delimiter, we are at a message boundary again */
        drain_pipe(out[0]);
        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_OK_ZERO(json_stream_has_buffered_output(&s));
        ASSERT_EQ(s.output_partial_since, USEC_INFINITY);

        /* Now a message that is larger than the pipe: the 'Y' at the end of each write must not be
         * mistaken for the end of the message, and the clock must not be restarted. */
        _cleanup_free_ char *big = ASSERT_NOT_NULL(strrep("Y", 3 * 4096));
        v = sd_json_variant_unref(v);
        ASSERT_OK(sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("x", big)));
        ASSERT_OK(json_stream_enqueue(&s, v));

        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_OK_ZERO(json_stream_write(&s));
        since = s.output_partial_since;
        ASSERT_NE(since, USEC_INFINITY);

        usleep_safe(10 * USEC_PER_MSEC);
        drain_pipe(out[0]);
        ASSERT_OK_POSITIVE(json_stream_write(&s));
        ASSERT_EQ(s.output_partial_since, since);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
