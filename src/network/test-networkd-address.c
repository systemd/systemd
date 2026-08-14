/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include "dhcp6-address-registration.h"
#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "hashmap.h"
#include "networkd-address.h"
#include "networkd-dhcp6.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "tests.h"
#include "time-util.h"

static DHCP6AddressRegistration *test_address_registration_get(
                sd_dhcp6_client *client,
                const struct in6_addr *address) {

        return hashmap_get(client->address_registration.registrations, address);
}

static void test_FORMAT_LIFETIME_one(usec_t lifetime, const char *expected) {
        const char *t = FORMAT_LIFETIME(lifetime);

        log_debug(USEC_FMT " → \"%s\" (expected \"%s\")", lifetime, t, strna(expected));
        if (expected)
                ASSERT_STREQ(t, expected);
}

TEST(FORMAT_LIFETIME) {
        usec_t now_usec;

        now_usec = now(CLOCK_BOOTTIME);

        test_FORMAT_LIFETIME_one(now_usec, "for 0");
        test_FORMAT_LIFETIME_one(USEC_INFINITY, "forever");

        /* These two are necessarily racy, especially for slow test environment. */
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 2 * USEC_PER_SEC - 1), NULL);
        test_FORMAT_LIFETIME_one(usec_add(now_usec, 3 * USEC_PER_WEEK + USEC_PER_SEC - 1), NULL);
}

TEST(dhcp6_address_registration_eligibility) {
        Link link = {};
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));

        address.family = AF_INET;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.family = AF_INET6;

        address.scope = RT_SCOPE_LINK;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.scope = RT_SCOPE_UNIVERSE;

        address.flags = IFA_F_TENTATIVE;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.flags = IFA_F_DADFAILED;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.flags = 0;

        address.state = NETWORK_CONFIG_STATE_CONFIGURING;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.state = NETWORK_CONFIG_STATE_CONFIGURED;

        address.lifetime_valid_usec = now(CLOCK_BOOTTIME);
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.lifetime_valid_usec = usec_add(now(CLOCK_BOOTTIME), USEC_PER_HOUR);

        address.source = NETWORK_CONFIG_SOURCE_DHCP6;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));

        address.source = NETWORK_CONFIG_SOURCE_STATIC;
        address.also_requested_by_dhcp6 = true;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_NDISC;
        ASSERT_FALSE(dhcp6_address_is_eligible_for_registration(&address));
        address.also_requested_by_dhcp6 = false;

        address.source = NETWORK_CONFIG_SOURCE_NDISC;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_DHCP_PD;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_MODEM_MANAGER;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_RUNTIME;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
        address.source = NETWORK_CONFIG_SOURCE_FOREIGN;
        address.lifetime_valid_usec = USEC_INFINITY;
        ASSERT_TRUE(dhcp6_address_is_eligible_for_registration(&address));
}

TEST(dhcp6_address_registration_synchronization) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        Network network = {
                .dhcp6_register_addresses = true,
        };
        Link link = {
                .network = &network,
        };
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .in_addr.in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } },
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_OK(sd_dhcp6_client_new(&client));
        link.dhcp6_client = client;

        dhcp6_sync_address_registration(&link, &address);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 1U);

        usec_t preferred_usec = usec_add(now(CLOCK_BOOTTIME), USEC_PER_HOUR);
        usec_t valid_usec = usec_add(now(CLOCK_BOOTTIME), 2 * USEC_PER_HOUR);
        address.lifetime_preferred_usec = preferred_usec;
        address.lifetime_valid_usec = valid_usec;
        dhcp6_sync_address_registration(&link, &address);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &address.in_addr.in6));
        ASSERT_EQ(registration->lifetime_preferred_usec, preferred_usec);
        ASSERT_EQ(registration->lifetime_valid_usec, valid_usec);

        address.flags = IFA_F_TENTATIVE;
        dhcp6_sync_address_registration(&link, &address);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 0U);

        address.flags = 0;
        dhcp6_sync_address_registration(&link, &address);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 1U);
        dhcp6_remove_address_registration(&link, &address);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 0U);

        network.dhcp6_register_addresses = false;
        dhcp6_sync_address_registration(&link, &address);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 0U);
}

int dhcp6_address_registration_open_socket(int ifindex) {
        assert(ifindex > 0);

        return -EIO;
}

int dhcp6_address_registration_send(
                int fd,
                const struct in6_addr *source,
                int ifindex,
                const struct sockaddr_in6 *destination,
                const void *packet,
                size_t len) {

        return -EIO;
}

int dhcp6_address_registration_receive(
                int fd,
                void **ret_packet,
                size_t *ret_len,
                struct sockaddr_in6 *ret_sender,
                struct in6_addr *ret_destination,
                int *ret_ifindex,
                bool *ret_truncated) {

        return -EIO;
}

uint32_t dhcp6_address_registration_random_u32(void) {
        return 1;
}

uint64_t dhcp6_address_registration_random_u64_range(uint64_t upper_bound) {
        assert(upper_bound > 0);

        return 0;
}

TEST(dhcp6_address_registration_best_effort) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        Network network = {
                .dhcp6_register_addresses = true,
        };
        Link link = {
                .ifname = (char*) "test",
                .network = &network,
                .state = LINK_STATE_CONFIGURED,
        };
        Address address = {
                .link = &link,
                .family = AF_INET6,
                .scope = RT_SCOPE_UNIVERSE,
                .source = NETWORK_CONFIG_SOURCE_STATIC,
                .state = NETWORK_CONFIG_STATE_CONFIGURED,
                .in_addr.in6 = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } },
                .lifetime_preferred_usec = USEC_INFINITY,
                .lifetime_valid_usec = USEC_INFINITY,
        };

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_set_ifindex(client, 42));
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        link.dhcp6_client = client;

        dhcp6_sync_address_registration(&link, &address);
        ASSERT_EQ(link.state, LINK_STATE_CONFIGURED);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &address.in_addr.in6));
        ASSERT_TRUE(registration->transaction_active);
        ASSERT_FALSE(registration->registration_attempted);
        ASSERT_EQ(registration->transmission_count, 1U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
