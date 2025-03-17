/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "fd-util.h"
#include "namespace-util.h"
#include "nsresource.h"
#include "tests.h"

TEST(delegatetap) {
        int r;

        _cleanup_close_ int userns_fd = userns_acquire_self_root();
        if (ERRNO_IS_NEG_PRIVILEGE(userns_fd) || ERRNO_IS_NEG_NOT_SUPPORTED(userns_fd))
                return (void) log_tests_skipped_errno(userns_fd, "User namespaces not available");
        ASSERT_OK(userns_fd);

        r = nsresource_register_userns("foobar", userns_fd);
        if (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "systemd-nsresourced cannot be reached");
        ASSERT_OK(r);

        _cleanup_free_ char *ifname = NULL;
        _cleanup_close_ int tap_fd = nsresource_add_netif_tap(userns_fd, &ifname);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(tap_fd))
                return (void) log_tests_skipped_errno(tap_fd, "tap device support not available");
        ASSERT_OK(tap_fd);

        ASSERT_GE(if_nametoindex(ifname), 2U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
