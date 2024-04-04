/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-notify-inline.h"

#include "fd-util.h"
#include "fs-util.h"
#include "socket-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static int notify(int unset_environment, const char *message) {
        return sd_notify_inline(unset_environment, message);
}

TEST(sd_notify_inline) {
        _cleanup_(unlink_and_freep) char *t;
        assert_se(tempfn_random("/tmp/test-sd-notify-inline", NULL, &t) >= 0);

        _cleanup_close_ int listen_socket;
        union sockaddr_union sa = { .un.sun_family = AF_UNIX };
        size_t l;

        l = strlen(t);
        assert_se(l < sizeof(sa.un.sun_path));
        memcpy(sa.un.sun_path, t, l + 1);

        listen_socket = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(listen_socket >= 0);
        assert_se(bind(listen_socket, &sa.sa, sizeof(sa.un)) >= 0);

        setenv("NOTIFY_SOCKET", t, 1);

        assert_se(notify(1, "FOOBAR=barbar") == 1);
        assert_se(notify(1, "FOOBAR=barbar") == 0);
        assert_se(notify(1, "") == -EINVAL);

        setenv("NOTIFY_SOCKET", "bar", 1);

        assert_se(notify(1, "FOOBAR=barbar") == -EAFNOSUPPORT);
        assert_se(notify(1, "FOOBAR=barbar") == 0);
        assert_se(notify(1, "") == -EINVAL);
}

TEST(sd_notifyf_inline) {
        _cleanup_(unlink_and_freep) char *t;
        assert_se(tempfn_random("/tmp/test-sd-notify-inline", NULL, &t) >= 0);

        _cleanup_close_ int listen_socket;
        union sockaddr_union sa = { .un.sun_family = AF_UNIX };
        size_t l;

        l = strlen(t);
        assert_se(l < sizeof(sa.un.sun_path));
        memcpy(sa.un.sun_path, t, l + 1);

        listen_socket = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        assert_se(listen_socket >= 0);
        assert_se(bind(listen_socket, &sa.sa, sizeof(sa.un)) >= 0);

        setenv("NOTIFY_SOCKET", t, 1);

        assert_se(sd_notifyf_inline(1, "FOOBAR=%s", "barbar") == 1);
        assert_se(sd_notifyf_inline(1, "FOOBAR=%s", "barbar") == 0);
        assert_se(sd_notifyf_inline(1, "") == -EINVAL);

        setenv("NOTIFY_SOCKET", "bar", 1);

        assert_se(sd_notifyf_inline(1, "FOOBAR=%s", "barbar") == -EAFNOSUPPORT);
        assert_se(sd_notifyf_inline(1, "FOOBAR=%s", "barbar") == 0);
        assert_se(sd_notifyf_inline(1, "") == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
