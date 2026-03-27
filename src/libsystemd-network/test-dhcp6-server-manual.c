/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Manual DHCPv6 server+client test over veth.
 *
 * Run as root:
 *   ./build/test-dhcp6-server-manual
 *
 * It creates a veth pair in a network namespace, starts the DHCPv6 server
 * on one end and the DHCPv6 client on the other, then verifies the client
 * gets an address.
 */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sched.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-dhcp6-server.h"
#include "sd-event.h"

#include "dhcp6-lease-internal.h"
#include "in-addr-util.h"
#include "tests.h"

static bool got_address = false;

static void client_callback(sd_dhcp6_client *client, int event, void *userdata) {
        sd_event *e = userdata;

        log_info("Client event: %d", event);

        if (event == SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE) {
                _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
                struct in6_addr addr;

                assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);

                FOREACH_DHCP6_ADDRESS(lease) {
                        assert_se(sd_dhcp6_lease_get_address(lease, &addr) >= 0);

                        char buf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
                        log_info("Client acquired address: %s", buf);
                        got_address = true;
                }

                const struct in6_addr *dns;
                int n = sd_dhcp6_lease_get_dns(lease, &dns);
                if (n > 0) {
                        char buf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &dns[0], buf, sizeof(buf));
                        log_info("Client got DNS: %s", buf);
                }

                /* Stop the event loop */
                sd_event_exit(e, 0);
        }
}

static int timeout_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_event *e = userdata;

        log_error("Test timed out!");
        sd_event_exit(e, -ETIMEDOUT);
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_dhcp6_server_unrefp) sd_dhcp6_server *server = NULL;
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0) {
                log_notice("Skipping test, not running as root.");
                return EXIT_TEST_SKIP;
        }

        /* Enter new network namespace for isolation */
        if (unshare(CLONE_NEWNET) < 0) {
                log_notice_errno(errno, "Failed to create network namespace, skipping: %m");
                return EXIT_TEST_SKIP;
        }

        /* Bring up loopback */
        assert_se(system("ip link set lo up") == 0);

        /* Create veth pair */
        assert_se(system("ip link add veth-srv type veth peer name veth-cli") == 0);
        assert_se(system("ip link set veth-srv up") == 0);
        assert_se(system("ip link set veth-cli up") == 0);
        assert_se(system("ip addr add 2001:db8::1/64 dev veth-srv") == 0);

        /* Wait for DAD to complete and address to become ready */
        assert_se(system("sleep 2") == 0);
        assert_se(system("ip addr show dev veth-srv") == 0);

        int srv_ifindex = (int) if_nametoindex("veth-srv");
        int cli_ifindex = (int) if_nametoindex("veth-cli");
        assert_se(srv_ifindex > 0);
        assert_se(cli_ifindex > 0);

        log_info("veth-srv ifindex=%d, veth-cli ifindex=%d", srv_ifindex, cli_ifindex);

        assert_se(sd_event_default(&event) >= 0);

        /* === Set up DHCPv6 server === */
        assert_se(sd_dhcp6_server_new(&server, srv_ifindex) >= 0);
        assert_se(sd_dhcp6_server_set_ifname(server, "veth-srv") >= 0);
        assert_se(sd_dhcp6_server_attach_event(server, event, 0) >= 0);

        struct in6_addr srv_addr, dns_addr;
        inet_pton(AF_INET6, "2001:db8::1", &srv_addr);
        inet_pton(AF_INET6, "2001:4860:4860::8888", &dns_addr);

        assert_se(sd_dhcp6_server_set_address(server, &srv_addr, 64) >= 0);
        assert_se(sd_dhcp6_server_configure_pool(server, &srv_addr, 64, 10, 200) >= 0);
        assert_se(sd_dhcp6_server_set_dns(server, &dns_addr, 1) >= 0);

        r = sd_dhcp6_server_start(server);
        if (r < 0) {
                log_notice_errno(r, "Failed to start DHCPv6 server (maybe missing caps?), skipping: %m");
                return EXIT_TEST_SKIP;
        }

        log_info("DHCPv6 server started on veth-srv");

        /* === Set up DHCPv6 client === */
        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, cli_ifindex) >= 0);
        assert_se(sd_dhcp6_client_set_ifname(client, "veth-cli") >= 0);
        assert_se(sd_dhcp6_client_attach_event(client, event, 0) >= 0);

        /* Get the real MAC and link-local address from veth-cli */
        {
                struct ifaddrs *ifaddr, *ifa;
                bool found_ll = false, found_mac = false;

                assert_se(getifaddrs(&ifaddr) >= 0);

                for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, "veth-cli") != 0)
                                continue;

                        if (ifa->ifa_addr->sa_family == AF_INET6) {
                                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ifa->ifa_addr;
                                if (in6_addr_is_link_local(&sin6->sin6_addr)) {
                                        char buf[INET6_ADDRSTRLEN];
                                        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
                                        log_info("Client link-local: %s", buf);
                                        assert_se(sd_dhcp6_client_set_local_address(client, &sin6->sin6_addr) >= 0);
                                        found_ll = true;
                                }
                        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
                                struct sockaddr_ll *sll = (struct sockaddr_ll *) ifa->ifa_addr;
                                if (sll->sll_halen == 6) {
                                        log_info("Client MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                                                 sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
                                                 sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
                                        assert_se(sd_dhcp6_client_set_mac(client, sll->sll_addr, sll->sll_halen, ARPHRD_ETHER) >= 0);
                                        found_mac = true;
                                }
                        }
                }
                freeifaddrs(ifaddr);
                assert_se(found_ll);
                assert_se(found_mac);
        }

        /* Request addresses (IA_NA) */
        assert_se(sd_dhcp6_client_set_address_request(client, true) >= 0);
        assert_se(sd_dhcp6_client_set_callback(client, client_callback, event) >= 0);

        r = sd_dhcp6_client_start(client);
        if (r < 0) {
                log_notice_errno(r, "Failed to start DHCPv6 client, skipping: %m");
                return EXIT_TEST_SKIP;
        }

        log_info("DHCPv6 client started on veth-cli");

        /* Set a 30 second timeout */
        sd_event_source *timeout_source = NULL;
        assert_se(sd_event_add_time_relative(event, &timeout_source,
                                             CLOCK_MONOTONIC, 30 * USEC_PER_SEC, 0,
                                             timeout_handler, event) >= 0);

        /* Run event loop */
        r = sd_event_loop(event);
        sd_event_source_unref(timeout_source);

        if (r == -ETIMEDOUT) {
                log_error("Test timed out - DHCPv6 client did not get an address");
                return 1;
        }

        if (!got_address) {
                log_error("Client did not acquire an address!");
                return 1;
        }

        log_info("TEST PASSED: DHCPv6 client successfully acquired an address from the server!");

        return 0;
}
