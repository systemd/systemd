/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "sd-dhcp-lease.h"

#include "bond-util.h"
#include "dhcp6-protocol.h"
#include "ethtool-util.h"
#include "ipvlan-util.h"
#include "lldp-rx-internal.h"
#include "macvlan-util.h"
#include "ndisc-internal.h"
#include "networkd-dns.h"
#include "networkd-lldp-rx.h"
#include "networkd-radv.h"
#include "networkd-sysctl.h"
#include "test-tables.h"
#include "tests.h"
#include "tunnel.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(BondAdSelect, bond_ad_select, NETDEV_BOND_AD_SELECT);
        test_table(BondArpAllTargets, bond_arp_all_targets, NETDEV_BOND_ARP_ALL_TARGETS);
        test_table(BondArpValidate, bond_arp_validate, NETDEV_BOND_ARP_VALIDATE);
        test_table(BondFailOverMac, bond_fail_over_mac, NETDEV_BOND_FAIL_OVER_MAC);
        test_table(BondLacpRate, bond_lacp_rate, NETDEV_BOND_LACP_RATE);
        test_table(BondMode, bond_mode, NETDEV_BOND_MODE);
        test_table(BondPrimaryReselect, bond_primary_reselect, NETDEV_BOND_PRIMARY_RESELECT);
        test_table(BondXmitHashPolicy, bond_xmit_hash_policy, NETDEV_BOND_XMIT_HASH_POLICY);
        test_table(DHCP6Status, dhcp6_message_status, DHCP6_STATUS);
        test_table_sparse(DHCP6MessageType, dhcp6_message_type, DHCP6_MESSAGE_TYPE); /* enum starts from 1 */
        test_table(UseDomains, use_domains, USE_DOMAINS);
        test_table(Duplex, duplex, DUP);
        test_table(TunnelMode, tunnel_mode, TUNNEL_MODE);
        test_table(IPv6PrivacyExtensions, ipv6_privacy_extensions, IPV6_PRIVACY_EXTENSIONS);
        test_table(IPVlanFlags, ipvlan_flags, NETDEV_IPVLAN_FLAGS);
        test_table(LinkOperationalState, link_operstate, LINK_OPERSTATE);
        /* test_table(link_state, LINK_STATE);  — not a reversible mapping */
        test_table(LLDPMode, lldp_mode, LLDP_MODE);
        test_table(NetDevKind, netdev_kind, NETDEV_KIND);
        test_table(RADVPrefixDelegation, radv_prefix_delegation, RADV_PREFIX_DELEGATION);
        test_table(sd_lldp_rx_event_t, lldp_rx_event, SD_LLDP_RX_EVENT);
        test_table(sd_ndisc_event_t, ndisc_event, SD_NDISC_EVENT);
        test_table(sd_dhcp_lease_server_type_t, dhcp_lease_server_type, SD_DHCP_LEASE_SERVER_TYPE);

        test_table_sparse(IPVlanMode, ipvlan_mode, NETDEV_IPVLAN_MODE);
        test_table_sparse(MacVlanMode, macvlan_mode, NETDEV_MACVLAN_MODE);
        test_table_sparse(AddressFamily, address_family, ADDRESS_FAMILY);

        assert_cc(sizeof(sd_lldp_rx_event_t) == sizeof(int64_t));
        assert_cc(sizeof(sd_ndisc_event_t) == sizeof(int64_t));
        assert_cc(sizeof(sd_dhcp_lease_server_type_t) == sizeof(int64_t));

        return EXIT_SUCCESS;
}
