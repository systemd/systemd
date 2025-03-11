/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "nsresource.h"
#include "tests.h"
#include "fd-util.h"
#include "namespace-util.h"

TEST(delegatetap) {
        int r;

        _cleanup_close_ int userns_fd = userns_acquire_self_root();
        if (ERRNO_IS_NEG_PRIVILEGE(userns_fd) || ERRNO_IS_NEG_NOT_SUPPORTED(userns_fd))
                return (void) log_tests_skipped("User namespaces not available, skipping test.");

        assert_se(userns_fd >= 0);

        r = nsresource_register_userns("foobar", userns_fd);
        if (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT)
                return (void) log_tests_skipped("systemd-nsresourced cannot be reached, skipping test.");

        assert_se(r >= 0);

        _cleanup_free_ char *ifname = NULL;
        _cleanup_close_ int tap_fd = nsresource_add_netif_tap(userns_fd, &ifname);

        assert_se(tap_fd >= 0);
        assert_se(if_nametoindex(ifname) > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
