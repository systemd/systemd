/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-event.h"

#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-journald-util.h"
#include "journald-stream.h"
#include "tests.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (outside_size_range(size, 1, 65536))
                return 0;

        fuzz_setup_logging();

        _cleanup_close_pair_ int stream_fds[2] = EBADF_PAIR;
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, stream_fds));

        _cleanup_(manager_freep) Manager *m = NULL;
        dummy_manager_new(&m, /* buffer= */ NULL, /* size= */ 0);

        StdoutStream *stream;
        ASSERT_OK(stdout_stream_install(m, stream_fds[0], &stream));
        int fd0 = TAKE_FD(stream_fds[0]); /* avoid double close */

        ASSERT_OK_EQ_ERRNO(write(stream_fds[1], data, size), (ssize_t) size);
        for (int v; ioctl(fd0, SIOCINQ, &v) == 0 && v > 0;)
                ASSERT_OK(sd_event_run(m->event, UINT64_MAX));

        if (m->n_stdout_streams > 0)
                stdout_stream_terminate(stream);

        return 0;
}
