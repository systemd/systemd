/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bond.h"
#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "ethtool-util.h"
#include "ipvlan.h"
#include "lldp-rx-internal.h"
#include "macvlan.h"
#include "ndisc-internal.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "test-tables.h"
#include "tunnel.h"

int main(int argc, char **argv) {
        test_table(bond_ad_select, NETDEV_BOND_AD_SELECT);
        test_table(bond_arp_all_targets, NETDEV_BOND_ARP_ALL_TARGETS);
        test_table(bond_arp_validate, NETDEV_BOND_ARP_VALIDATE);
        test_table(bond_fail_over_mac, NETDEV_BOND_FAIL_OVER_MAC);
        test_table(bond_lacp_rate, NETDEV_BOND_LACP_RATE);
        test_table(bond_mode, NETDEV_BOND_MODE);
        test_table(bond_primary_reselect, NETDEV_BOND_PRIMARY_RESELECT);
        test_table(bond_xmit_hash_policy, NETDEV_BOND_XMIT_HASH_POLICY);
        test_table(dhcp6_message_status, DHCP6_STATUS);
        test_table_sparse(dhcp6_message_type, DHCP6_MESSAGE_TYPE); /* enum starts from 1 */
        test_table(dhcp_use_domains, DHCP_USE_DOMAINS);
        test_table(duplex, DUP);
        test_table(ip6tnl_mode, NETDEV_IP6_TNL_MODE);
        test_table(ipv6_privacy_extensions, IPV6_PRIVACY_EXTENSIONS);
        test_table(ipvlan_flags, NETDEV_IPVLAN_FLAGS);
        test_table(link_operstate, LINK_OPERSTATE);
        /* test_table(link_state, LINK_STATE);  — not a reversible mapping */
        test_table(lldp_mode, LLDP_MODE);
        test_table(netdev_kind, NETDEV_KIND);
        test_table(radv_prefix_delegation, RADV_PREFIX_DELEGATION);
        test_table(lldp_rx_event, SD_LLDP_RX_EVENT);
        test_table(ndisc_event, SD_NDISC_EVENT);
        test_table(dhcp_lease_server_type, SD_DHCP_LEASE_SERVER_TYPE);

        test_table_sparse(ipvlan_mode, NETDEV_IPVLAN_MODE);
        test_table_sparse(macvlan_mode, NETDEV_MACVLAN_MODE);
        test_table_sparse(address_family, ADDRESS_FAMILY);

        assert_cc(sizeof(sd_lldp_rx_event_t) == sizeof(int64_t));
        assert_cc(sizeof(sd_ndisc_event_t) == sizeof(int64_t));
        assert_cc(sizeof(sd_dhcp_lease_server_type_t) == sizeof(int64_t));

        return EXIT_SUCCESS;
}
