/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-search-domain.h"
#include "resolved-link.h"
#include "resolved-manager.h"

#include "log.h"
#include "tests.h"

static void check_domains(DnsSearchDomain *head, const char **expected, size_t n) {
        size_t i = 0;

        LIST_FOREACH(domains, d, head) {
                ASSERT_STREQ(DNS_SEARCH_DOMAIN_NAME(d), expected[i]);
                i++;
        }

        ASSERT_EQ(i, n);
}

/* ================================================================
 * dns_search_domain_new()
 * ================================================================ */

TEST(dns_search_domain_new_system) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd = NULL;

        ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "local"));

        ASSERT_TRUE(sd->linked);
        ASSERT_STREQ(DNS_SEARCH_DOMAIN_NAME(sd), "local");
}

TEST(dns_search_domain_new_system_limit) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd = NULL;
        unsigned int i;

        for (i = 0; i < MANAGER_SEARCH_DOMAINS_MAX; i++) {
                ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "local"));
                ASSERT_EQ(manager.n_search_domains, i + 1);
                dns_search_domain_unref(sd);
        }

        ASSERT_ERROR(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "local"), E2BIG);
}

TEST(dns_search_domain_new_link) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));

        ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, "local."));

        ASSERT_TRUE(sd->linked);
        ASSERT_STREQ(DNS_SEARCH_DOMAIN_NAME(sd), "local");
}

TEST(dns_search_domain_new_link_limit) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd = NULL;
        unsigned int i;

        ASSERT_OK(link_new(&manager, &link, 1));

        for (i = 0; i < LINK_SEARCH_DOMAINS_MAX; i++) {
                ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, "local"));
                ASSERT_EQ(link->n_search_domains, i + 1);
        }

        ASSERT_ERROR(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, "local"), E2BIG);
}

/* ================================================================
 * dns_search_domain_unlink()
 * ================================================================ */

TEST(dns_search_domain_unlink_system) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "local");
        dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "vpn.example.com");
        dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, NULL, "org");

        ASSERT_TRUE(sd2->linked);
        ASSERT_EQ(manager.n_search_domains, 3u);

        dns_search_domain_unlink(sd2);

        ASSERT_FALSE(sd2->linked);
        ASSERT_EQ(manager.n_search_domains, 2u);

        const char *expected[] = { "local", "org" };
        check_domains(manager.search_domains, expected, 2);
}

TEST(dns_search_domain_unlink_link) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        link_new(&manager, &link, 1);

        dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_LINK, link, "local");
        dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_LINK, link, "vpn.example.com");
        dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_LINK, link, "org");

        ASSERT_TRUE(sd2->linked);
        ASSERT_EQ(link->n_search_domains, 3u);

        dns_search_domain_unlink(sd2);

        ASSERT_FALSE(sd2->linked);
        ASSERT_EQ(link->n_search_domains, 2u);

        const char *expected[] = { "local", "org" };
        check_domains(link->search_domains, expected, 2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
