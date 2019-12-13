/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-stream.h"

static int stream_fds[2] = { -1, -1 };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s;
        StdoutStream *stream;
        int v;

        if (size == 0 || size > 65536)
                return 0;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, stream_fds) >= 0);
        dummy_server_init(&s, NULL, 0);
        assert_se(stdout_stream_install(&s, stream_fds[0], &stream) >= 0);
        assert_se(write(stream_fds[1], data, size) == (ssize_t) size);
        while (ioctl(stream_fds[0], SIOCINQ, &v) == 0 && v)
                sd_event_run(s.event, (uint64_t) -1);
        if (s.n_stdout_streams)
                stdout_stream_destroy(stream);
        server_done(&s);
        stream_fds[1] = safe_close(stream_fds[1]);

        return 0;
}
