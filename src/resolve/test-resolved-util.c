/* SPDX-License-Identifier: LGPL-2.1+ */

#include "log.h"
#include "resolved-util.h"
#include "string-util.h"
#include "tests.h"


static void test_in_addr_ifindex_name_from_string_auto_one(const char *a, const char *expected) {
        int family, ifindex;
        union in_addr_union ua;
        _cleanup_free_ char *server_name = NULL;

        assert_se(in_addr_ifindex_name_from_string_auto(a, &family, &ua, &ifindex, &server_name) >= 0);
        assert_se(streq_ptr(server_name, expected));
}

static void test_in_addr_ifindex_name_from_string_auto(void) {
        log_info("/* %s */", __func__);

        test_in_addr_ifindex_name_from_string_auto_one("192.168.0.1", NULL);
        test_in_addr_ifindex_name_from_string_auto_one("192.168.0.1#test.com", "test.com");
        test_in_addr_ifindex_name_from_string_auto_one("fe80::18%19", NULL);
        test_in_addr_ifindex_name_from_string_auto_one("fe80::18%19#another.test.com", "another.test.com");
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_in_addr_ifindex_name_from_string_auto();
        return 0;
}
