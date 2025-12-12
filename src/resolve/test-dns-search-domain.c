/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-search-domain.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "strv.h"
#include "tests.h"

static void check_domains(DnsSearchDomain *head, char * const *expected) {
        ASSERT_NOT_NULL(head);
        ASSERT_NOT_NULL(expected);

        size_t i = 0, n = strv_length(expected);
        LIST_FOREACH(domains, d, head) {
                ASSERT_LT(i, n);
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

        ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd);

        ASSERT_TRUE(sd->linked);
        ASSERT_STREQ(DNS_SEARCH_DOMAIN_NAME(sd), "local");
}

TEST(dns_search_domain_new_system_limit) {
        Manager manager = {};
        DnsSearchDomain *sd;

        for (size_t i = 0; i < MANAGER_SEARCH_DOMAINS_MAX; i++) {
                ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
                ASSERT_NOT_NULL(sd);
                ASSERT_EQ(manager.n_search_domains, i + 1);
        }

        sd = NULL;
        ASSERT_ERROR(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"), E2BIG);
        ASSERT_NULL(sd);

        dns_search_domain_unlink_all(manager.search_domains);
        ASSERT_EQ(manager.n_search_domains, 0u);
}

TEST(dns_search_domain_new_link) {
        Manager manager = {};
        Link *link;
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd = NULL;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "local."));
        ASSERT_NOT_NULL(sd);

        ASSERT_TRUE(sd->linked);
        ASSERT_STREQ(DNS_SEARCH_DOMAIN_NAME(sd), "local");
}

TEST(dns_search_domain_new_link_limit) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        DnsSearchDomain *sd;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        for (size_t i = 0; i < LINK_SEARCH_DOMAINS_MAX; i++) {
                ASSERT_OK(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "local"));
                ASSERT_NOT_NULL(sd);
                ASSERT_EQ(link->n_search_domains, i + 1);
        }

        sd = NULL;
        ASSERT_ERROR(dns_search_domain_new(&manager, &sd, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "local"), E2BIG);
        ASSERT_NULL(sd);
}

/* ================================================================
 * dns_search_domain_unlink()
 * ================================================================ */

TEST(dns_search_domain_unlink_system) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        ASSERT_TRUE(sd2->linked);
        ASSERT_EQ(manager.n_search_domains, 3u);

        dns_search_domain_unlink(TAKE_PTR(sd2));
        ASSERT_EQ(manager.n_search_domains, 2u);

        check_domains(manager.search_domains, STRV_MAKE("local", "org"));
}

TEST(dns_search_domain_unlink_link) {
        Manager manager = {};
        _cleanup_(link_freep) Link *link = NULL;
        DnsSearchDomain *sd1, *sd2, *sd3;

        ASSERT_OK(link_new(&manager, &link, 1));
        ASSERT_NOT_NULL(link);

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_LINK, link, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        ASSERT_TRUE(sd2->linked);
        ASSERT_EQ(link->n_search_domains, 3u);

        dns_search_domain_unlink(sd2);
        ASSERT_EQ(link->n_search_domains, 2u);

        check_domains(link->search_domains, STRV_MAKE("local", "org"));
}

/* ================================================================
 * dns_search_domain_mark_all()
 * ================================================================ */

TEST(dns_search_domain_mark_all) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        ASSERT_FALSE(sd1->marked);
        ASSERT_FALSE(sd2->marked);
        ASSERT_FALSE(sd3->marked);

        dns_search_domain_mark_all(sd1);

        ASSERT_TRUE(sd1->marked);
        ASSERT_TRUE(sd2->marked);
        ASSERT_TRUE(sd3->marked);
}

/* ================================================================
 * dns_search_domain_move_back_and_unmark()
 * ================================================================ */

TEST(dns_search_domain_move_back_and_unmark) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        dns_search_domain_move_back_and_unmark(sd1);
        check_domains(manager.search_domains, STRV_MAKE("local", "vpn.example.com", "org"));

        sd1->marked = true;

        dns_search_domain_move_back_and_unmark(sd1);
        check_domains(manager.search_domains, STRV_MAKE("vpn.example.com", "org", "local"));

        sd3->marked = true;

        dns_search_domain_move_back_and_unmark(sd3);
        check_domains(manager.search_domains, STRV_MAKE("vpn.example.com", "local", "org"));
}

/* ================================================================
 * dns_search_domain_unlink_marked()
 * ================================================================ */

TEST(dns_search_domain_unlink_marked) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        ASSERT_FALSE(dns_search_domain_unlink_marked(sd1));
        ASSERT_EQ(manager.n_search_domains, 3u);
        check_domains(manager.search_domains, STRV_MAKE("local", "vpn.example.com", "org"));

        sd2->marked = true;

        ASSERT_TRUE(dns_search_domain_unlink_marked(sd1));
        TAKE_PTR(sd2);
        ASSERT_EQ(manager.n_search_domains, 2u);
        check_domains(manager.search_domains, STRV_MAKE("local", "org"));

        sd1->marked = true;

        ASSERT_TRUE(dns_search_domain_unlink_marked(sd1));
        TAKE_PTR(sd1);
        ASSERT_EQ(manager.n_search_domains, 1u);
        check_domains(manager.search_domains, STRV_MAKE("org"));
}

/* ================================================================
 * dns_search_domain_find()
 * ================================================================ */

TEST(dns_search_domain_find) {
        Manager manager = {};
        _cleanup_(dns_search_domain_unrefp) DnsSearchDomain *sd1 = NULL, *sd2 = NULL, *sd3 = NULL;
        DnsSearchDomain *ret;

        ASSERT_OK(dns_search_domain_new(&manager, &sd1, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "local"));
        ASSERT_NOT_NULL(sd1);

        ASSERT_OK(dns_search_domain_new(&manager, &sd2, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "vpn.example.com"));
        ASSERT_NOT_NULL(sd2);

        ASSERT_OK(dns_search_domain_new(&manager, &sd3, DNS_SEARCH_DOMAIN_SYSTEM, /* link= */ NULL, /* delegate= */ NULL, "org"));
        ASSERT_NOT_NULL(sd3);

        ASSERT_OK_POSITIVE(dns_search_domain_find(sd1, "local", &ret));
        ASSERT_PTR_EQ(ret, sd1);

        ASSERT_OK_POSITIVE(dns_search_domain_find(sd1, "org", &ret));
        ASSERT_PTR_EQ(ret, sd3);

        ASSERT_OK_POSITIVE(dns_search_domain_find(sd1, "vpn.example.com", &ret));
        ASSERT_PTR_EQ(ret, sd2);

        ASSERT_OK_ZERO(dns_search_domain_find(sd1, "co.uk", &ret));
        ASSERT_NULL(ret);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
