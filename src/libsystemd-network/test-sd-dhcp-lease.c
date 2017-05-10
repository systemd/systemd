#include <errno.h>

#include "dhcp-lease-internal.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

/* According to RFC1035 section 4.1.4, a domain name in a message can be either:
 *      - a sequence of labels ending in a zero octet
 *      - a pointer
 *      - a sequence of labels ending with a pointer
 */
static void test_dhcp_lease_parse_search_domains_basic(void) {
        int r;
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[] = {
                0x03, 'F', 'O', 'O', 0x03, 'B', 'A', 'R', 0x00,
                0x04, 'A', 'B', 'C', 'D', 0x03, 'E', 'F', 'G', 0x00,
        };

        r = dhcp_lease_parse_search_domains(optionbuf, sizeof(optionbuf), &domains);
        assert_se(r == 2);
        assert_se(streq(domains[0], "FOO.BAR"));
        assert_se(streq(domains[1], "ABCD.EFG"));
}

static void test_dhcp_lease_parse_search_domains_ptr(void) {
        int r;
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[] = {
                0x03, 'F', 'O', 'O', 0x00, 0xC0, 0x00,
        };

        r = dhcp_lease_parse_search_domains(optionbuf, sizeof(optionbuf), &domains);
        assert_se(r == 2);
        assert_se(streq(domains[0], "FOO"));
        assert_se(streq(domains[1], "FOO"));
}

static void test_dhcp_lease_parse_search_domains_labels_and_ptr(void) {
        int r;
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[] = {
                0x03, 'F', 'O', 'O', 0x03, 'B', 'A', 'R', 0x00,
                0x03, 'A', 'B', 'C', 0xC0, 0x04,
        };

        r = dhcp_lease_parse_search_domains(optionbuf, sizeof(optionbuf), &domains);
        assert_se(r == 2);
        assert_se(streq(domains[0], "FOO.BAR"));
        assert_se(streq(domains[1], "ABC.BAR"));
}

/* Tests for exceptions. */

static void test_dhcp_lease_parse_search_domains_no_data(void) {
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[3] = {0, 0, 0};

        assert_se(dhcp_lease_parse_search_domains(NULL, 0, &domains) == -ENODATA);
        assert_se(dhcp_lease_parse_search_domains(optionbuf, 0, &domains) == -ENODATA);
}

static void test_dhcp_lease_parse_search_domains_loops(void) {
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[] = {
                0x03, 'F', 'O', 'O', 0x00, 0x03, 'B', 'A', 'R', 0xC0, 0x06,
        };

        assert_se(dhcp_lease_parse_search_domains(optionbuf, sizeof(optionbuf), &domains) == -EBADMSG);
}

static void test_dhcp_lease_parse_search_domains_wrong_len(void) {
        _cleanup_strv_free_ char **domains = NULL;
        static const uint8_t optionbuf[] = {
                0x03, 'F', 'O', 'O', 0x03, 'B', 'A', 'R', 0x00,
                0x04, 'A', 'B', 'C', 'D', 0x03, 'E', 'F', 'G', 0x00,
        };

        assert_se(dhcp_lease_parse_search_domains(optionbuf, sizeof(optionbuf) - 5, &domains) == -EBADMSG);
}

int main(int argc, char *argv[]) {
        test_dhcp_lease_parse_search_domains_basic();
        test_dhcp_lease_parse_search_domains_ptr();
        test_dhcp_lease_parse_search_domains_labels_and_ptr();
        test_dhcp_lease_parse_search_domains_no_data();
        test_dhcp_lease_parse_search_domains_loops();
        test_dhcp_lease_parse_search_domains_wrong_len();
}
