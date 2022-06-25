/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <linux/netfilter.h>

#include "macro.h"
#include "nfproto-util.h"
#include "tests.h"

TEST(nfproto_to_af) {
        for (int i = 0; i < NFPROTO_NUMPROTO; i++)
                if (IN_SET(i, NFPROTO_UNSPEC, NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_BRIDGE, NFPROTO_DECNET))
                        assert_se(nfproto_to_af(i) == i);
                else
                        assert_se(nfproto_to_af(i) == -EINVAL);
}

TEST(af_to_nfproto) {
        for (int i = 0; i < AF_MAX; i++)
                if (IN_SET(i, AF_UNSPEC, AF_INET, AF_INET6, AF_BRIDGE, AF_DECnet))
                        assert_se(af_to_nfproto(i) == i);
                else
                        assert_se(af_to_nfproto(i) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
