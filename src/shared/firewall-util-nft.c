/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "firewall-util.h"
#include "firewall-util-private.h"
#include "in-addr-util.h"
#include "macro.h"
#include "netlink-internal.h"
#include "netlink-util.h"
#include "socket-util.h"
#include "time-util.h"

#define NFT_SYSTEMD_DNAT_MAP_NAME "map_port_ipport"
#define NFT_SYSTEMD_TABLE_NAME    "io.systemd.nat"
#define NFT_SYSTEMD_MASQ_SET_NAME "masq_saddr"

#define NFNL_DEFAULT_TIMEOUT_USECS (1ULL * USEC_PER_SEC)

#define UDP_DPORT_OFFSET 2

static sd_netlink_message **netlink_message_unref_many(sd_netlink_message **m) {
        if (!m)
                return NULL;

        /* This does not free array. The end of the array must be NULL. */

        for (sd_netlink_message **p = m; *p; p++)
                *p = sd_netlink_message_unref(*p);

        return m;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_netlink_message**, netlink_message_unref_many);

static int nfnl_open_expr_container(sd_netlink_message *m, const char *name) {
        int r;

        assert(m);
        assert(name);

        r = sd_netlink_message_open_array(m, NFTA_LIST_ELEM);
        if (r < 0)
                return r;

        return sd_netlink_message_open_container_union(m, NFTA_EXPR_DATA, name);
}

static int nfnl_close_expr_container(sd_netlink_message *m) {
        int r;

        assert(m);

        r = sd_netlink_message_close_container(m); /* NFTA_EXPR_DATA */
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* NFTA_LIST_ELEM */
}

static int nfnl_add_expr_fib(
                sd_netlink_message *m,
                uint32_t nft_fib_flags,
                enum nft_fib_result result,
                enum nft_registers dreg) {

        int r;

        assert(m);

        r = nfnl_open_expr_container(m, "fib");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_FIB_FLAGS, htobe32(nft_fib_flags));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_FIB_RESULT, htobe32(result));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_FIB_DREG, htobe32(dreg));
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_meta(
                sd_netlink_message *m,
                enum nft_meta_keys key,
                enum nft_registers dreg) {

        int r;

        assert(m);

        r = nfnl_open_expr_container(m, "meta");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_META_KEY, htobe32(key));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_META_DREG, htobe32(dreg));
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_payload(
                sd_netlink_message *m,
                enum nft_payload_bases pb,
                uint32_t offset,
                uint32_t len,
                enum nft_registers dreg) {

        int r;

        assert(m);

        r = nfnl_open_expr_container(m, "payload");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_PAYLOAD_DREG, htobe32(dreg));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_PAYLOAD_BASE, htobe32(pb));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_PAYLOAD_OFFSET, htobe32(offset));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_PAYLOAD_LEN, htobe32(len));
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_lookup(
                sd_netlink_message *m,
                const char *set_name,
                enum nft_registers sreg,
                enum nft_registers dreg) {

        int r;

        assert(m);
        assert(set_name);

        r = nfnl_open_expr_container(m, "lookup");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_LOOKUP_SET, set_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_LOOKUP_SREG, htobe32(sreg));
        if (r < 0)
                return r;

        if (dreg != 0) {
                r = sd_netlink_message_append_u32(m, NFTA_LOOKUP_DREG, htobe32(dreg));
                if (r < 0)
                        return r;
        }

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_cmp(
                sd_netlink_message *m,
                enum nft_cmp_ops cmp_op,
                enum nft_registers sreg,
                const void *data,
                size_t dlen) {

        int r;

        assert(m);
        assert(data);

        r = nfnl_open_expr_container(m, "cmp");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_CMP_OP, htobe32(cmp_op));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_CMP_SREG, htobe32(sreg));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_container_data(m, NFTA_CMP_DATA, NFTA_DATA_VALUE, data, dlen);
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_bitwise(
                sd_netlink_message *m,
                enum nft_registers sreg,
                enum nft_registers dreg,
                const void *and,
                const void *xor,
                uint32_t len) {

        int r;

        assert(m);
        assert(and);
        assert(xor);

        r = nfnl_open_expr_container(m, "bitwise");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_BITWISE_SREG, htobe32(sreg));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_BITWISE_DREG, htobe32(dreg));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_BITWISE_LEN, htobe32(len));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_container_data(m, NFTA_BITWISE_MASK, NFTA_DATA_VALUE, and, len);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_container_data(m, NFTA_BITWISE_XOR, NFTA_DATA_VALUE, xor, len);
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_dnat(
                sd_netlink_message *m,
                int family,
                enum nft_registers areg,
                enum nft_registers preg) {

        int r;

        assert(m);

        r = nfnl_open_expr_container(m, "nat");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_NAT_TYPE, htobe32(NFT_NAT_DNAT));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_NAT_FAMILY, htobe32(family));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_NAT_REG_ADDR_MIN, htobe32(areg));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_NAT_REG_PROTO_MIN, htobe32(preg));
        if (r < 0)
                return r;

        return nfnl_close_expr_container(m);
}

static int nfnl_add_expr_masq(sd_netlink_message *m) {
        int r;

        r = sd_netlink_message_open_array(m, NFTA_LIST_ELEM);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(m, NFTA_EXPR_NAME, "masq");
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* NFTA_LIST_ELEM */
}

static int sd_nfnl_message_new_masq_rule(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *chain) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        /* -t nat -A POSTROUTING -p protocol -s source/pflen -o out_interface -d destination/pflen -j MASQUERADE */

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(chain);

        r = sd_nfnl_nft_message_new_rule(nfnl, &m, family, NFT_SYSTEMD_TABLE_NAME, chain);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_RULE_EXPRESSIONS);
        if (r < 0)
                return r;

        /* 1st statement: ip saddr @masq_saddr. Place iph->saddr in reg1, resp. ipv6 in reg1..reg4. */
        if (family == AF_INET)
                r = nfnl_add_expr_payload(m, NFT_PAYLOAD_NETWORK_HEADER, offsetof(struct iphdr, saddr),
                                          sizeof(uint32_t), NFT_REG32_01);
        else
                r = nfnl_add_expr_payload(m, NFT_PAYLOAD_NETWORK_HEADER, offsetof(struct ip6_hdr, ip6_src.s6_addr),
                                          sizeof(struct in6_addr), NFT_REG32_01);
        if (r < 0)
                return r;

        /* 1st statement: use reg1 content to make lookup in @masq_saddr set. */
        r = nfnl_add_expr_lookup(m, NFT_SYSTEMD_MASQ_SET_NAME, NFT_REG32_01, 0);
        if (r < 0)
                return r;

        /* 2nd statement: masq.  Only executed by kernel if the previous lookup was successful. */
        r = nfnl_add_expr_masq(m);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m); /* NFTA_RULE_EXPRESSIONS */
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int sd_nfnl_message_new_dnat_rule_pre(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *chain) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        enum nft_registers proto_reg;
        uint32_t local = RTN_LOCAL;
        int r;

        /* -t nat -A PREROUTING -p protocol --dport local_port -i in_interface -s source/pflen
         * -d destination/pflen -j DNAT --to-destination remote_addr:remote_port */

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(chain);

        r = sd_nfnl_nft_message_new_rule(nfnl, &m, family, NFT_SYSTEMD_TABLE_NAME, chain);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_RULE_EXPRESSIONS);
        if (r < 0)
                return r;

        /* 1st statement: fib daddr type local */
        r = nfnl_add_expr_fib(m, NFTA_FIB_F_DADDR, NFT_FIB_RESULT_ADDRTYPE, NFT_REG32_01);
        if (r < 0)
                return r;

        /* 1st statement (cont.): compare RTN_LOCAL */
        r = nfnl_add_expr_cmp(m, NFT_CMP_EQ, NFT_REG32_01, &local, sizeof(local));
        if (r < 0)
                return r;

        /* 2nd statement: lookup local port in map, fetch address:dport to map to */
        r = nfnl_add_expr_meta(m, NFT_META_L4PROTO, NFT_REG32_01);
        if (r < 0)
                return r;

        r = nfnl_add_expr_payload(m, NFT_PAYLOAD_TRANSPORT_HEADER, UDP_DPORT_OFFSET,
                                  sizeof(uint16_t), NFT_REG32_02);
        if (r < 0)
                return r;

        /* 3rd statement: lookup 'l4proto . dport', e.g. 'tcp . 22' as key and
         * store address and port for the dnat mapping in REG1/REG2. */
        r = nfnl_add_expr_lookup(m, NFT_SYSTEMD_DNAT_MAP_NAME, NFT_REG32_01, NFT_REG32_01);
        if (r < 0)
                return r;

        proto_reg = family == AF_INET ? NFT_REG32_02 : NFT_REG32_05;
        r = nfnl_add_expr_dnat(m, family, NFT_REG32_01, proto_reg);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m); /* NFTA_RULE_EXPRESSIONS */
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int sd_nfnl_message_new_dnat_rule_out(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *chain) {

        static const uint32_t zero = 0, one = 1;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        enum nft_registers proto_reg;
        int r;

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(chain);

        r = sd_nfnl_nft_message_new_rule(nfnl, &m, family, NFT_SYSTEMD_TABLE_NAME, chain);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_RULE_EXPRESSIONS);
        if (r < 0)
                return r;

        /* 1st statement: exclude 127.0.0.1/8: ip daddr != 127.0.0.1/8, resp. avoid ::1 */
        if (family == AF_INET) {
                uint32_t lonet = htobe32(UINT32_C(0x7F000000)), lomask = htobe32(UINT32_C(0xff000000));

                r = nfnl_add_expr_payload(m, NFT_PAYLOAD_NETWORK_HEADER, offsetof(struct iphdr, daddr),
                                          sizeof(lonet), NFT_REG32_01);
                if (r < 0)
                        return r;
                /* 1st statement (cont.): bitops/prefix */
                r = nfnl_add_expr_bitwise(m, NFT_REG32_01, NFT_REG32_01, &lomask, &zero, sizeof(lomask));
                if (r < 0)
                        return r;

                /* 1st statement (cont.): compare reg1 with 127/8 */
                r = nfnl_add_expr_cmp(m, NFT_CMP_NEQ, NFT_REG32_01, &lonet, sizeof(lonet));
        } else {
                struct in6_addr loaddr = IN6ADDR_LOOPBACK_INIT;

                r = nfnl_add_expr_payload(m, NFT_PAYLOAD_NETWORK_HEADER, offsetof(struct ip6_hdr, ip6_dst.s6_addr),
                                          sizeof(loaddr), NFT_REG32_01);
                if (r < 0)
                        return r;

                r = nfnl_add_expr_cmp(m, NFT_CMP_NEQ, NFT_REG32_01, &loaddr, sizeof(loaddr));
        }
        if (r < 0)
                return r;

        /* 2nd statement: meta oif lo */
        r = nfnl_add_expr_meta(m, NFT_META_OIF, NFT_REG32_01);
        if (r < 0)
                return r;

        /* 2nd statement (cont.): compare to lo ifindex (1) */
        r = nfnl_add_expr_cmp(m, NFT_CMP_EQ, NFT_REG32_01, &one, sizeof(one));
        if (r < 0)
                return r;

        /* 3rd statement: meta l4proto . th dport dnat ip . port to map @map_port_ipport */
        r = nfnl_add_expr_meta(m, NFT_META_L4PROTO, NFT_REG32_01);
        if (r < 0)
                return r;

        /* 3rd statement (cont): store the port number in reg2 */
        r = nfnl_add_expr_payload(m, NFT_PAYLOAD_TRANSPORT_HEADER, UDP_DPORT_OFFSET,
                                  sizeof(uint16_t), NFT_REG32_02);
        if (r < 0)
                return r;

        /* 3rd statement (cont): use reg1 and reg2 and retrieve
         * the new destination ip and port number.
         *
         * reg1 and reg2 are clobbered and will then contain the new
         * address/port number. */
        r = nfnl_add_expr_lookup(m, NFT_SYSTEMD_DNAT_MAP_NAME, NFT_REG32_01, NFT_REG32_01);
        if (r < 0)
                return r;

        /* 4th statement: dnat connection to address/port retrieved by the
         * preceding expression. */
        proto_reg = family == AF_INET ? NFT_REG32_02 : NFT_REG32_05;
        r = nfnl_add_expr_dnat(m, family, NFT_REG32_01, proto_reg);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m); /* NFTA_RULE_EXPRESSIONS */
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int nft_new_set(
                struct sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *set_name,
                uint32_t set_id,
                uint32_t flags,
                uint32_t type,
                uint32_t klen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(set_name);

        r = sd_nfnl_nft_message_new_set(nfnl, &m, family, NFT_SYSTEMD_TABLE_NAME, set_name, set_id, klen);
        if (r < 0)
                return r;

        if (flags != 0) {
                r = sd_netlink_message_append_u32(m, NFTA_SET_FLAGS, htobe32(flags));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u32(m, NFTA_SET_KEY_TYPE, htobe32(type));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return r;
}

static int nft_new_map(
                struct sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *set_name,
                uint32_t set_id,
                uint32_t flags,
                uint32_t type,
                uint32_t klen,
                uint32_t dtype,
                uint32_t dlen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(set_name);

        r = nft_new_set(nfnl, &m, family, set_name, set_id, flags | NFT_SET_MAP, type, klen);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, NFTA_SET_DATA_TYPE, htobe32(dtype));
        if (r < 0)
               return r;

        r = sd_netlink_message_append_u32(m, NFTA_SET_DATA_LEN, htobe32(dlen));
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int nft_add_element(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *set_name,
                const void *key,
                uint32_t klen,
                const void *data,
                uint32_t dlen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(set_name);
        assert(key);
        assert(data);

        /*
         * Ideally there would be an API that provides:
         *
         * 1) an init function to add the main ruleset skeleton
         * 2) a function that populates the sets with all known address/port pairs to s/dnat for
         * 3) a function that can remove address/port pairs again.
         *
         * At this time, the existing API is used which is built on a
         * 'add/delete a rule' paradigm.
         *
         * This replicated here and each element gets added to the set
         * one-by-one.
         */
        r = sd_nfnl_nft_message_new_setelems(nfnl, &m, /* add = */ true, family, NFT_SYSTEMD_TABLE_NAME, set_name);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_append_setelem(m, 0, key, klen, data, dlen, 0);
        if (r < 0)
                return r;

        /* could theoretically append more set elements to add here */

        r = sd_netlink_message_close_container(m); /* NFTA_SET_ELEM_LIST_ELEMENTS */
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

static int nft_del_element(
                sd_netlink *nfnl,
                sd_netlink_message **ret,
                int family,
                const char *set_name,
                const void *key,
                uint32_t klen,
                const void *data,
                uint32_t dlen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nfnl);
        assert(ret);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(set_name);
        assert(key);
        assert(data);

        r = sd_nfnl_nft_message_new_setelems(nfnl, &m, /* add = */ false, family, NFT_SYSTEMD_TABLE_NAME, set_name);
        if (r < 0)
               return r;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_append_setelem(m, 0, key, klen, data, dlen, 0);
        if (r < 0)
               return r;

        r = sd_netlink_message_close_container(m); /* NFTA_SET_ELEM_LIST_ELEMENTS */
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}

/* This is needed so 'nft' userspace tool can properly format the contents
 * of the set/map when someone uses 'nft' to inspect their content.
 *
 * The values cannot be changed, they are part of the nft tool type identifier ABI. */
#define TYPE_BITS 6

enum nft_key_types {
        TYPE_IPADDR        = 7,
        TYPE_IP6ADDR       = 8,
        TYPE_INET_PROTOCOL = 12,
        TYPE_INET_SERVICE  = 13,
};

static uint32_t concat_types2(enum nft_key_types a, enum nft_key_types b) {
        uint32_t type = (uint32_t)a;

        type <<= TYPE_BITS;
        type |= (uint32_t)b;

        return type;
}

static int fw_nftables_init_family(sd_netlink *nfnl, int family) {
        sd_netlink_message *messages[10] = {};
        _unused_ _cleanup_(netlink_message_unref_manyp) sd_netlink_message **unref = messages;
        size_t msgcnt = 0, ip_type_size;
        uint32_t set_id = 0;
        int ip_type, r;

        assert(nfnl);
        assert(IN_SET(family, AF_INET, AF_INET6));

        /* Set F_EXCL so table add fails if the table already exists. */
        r = sd_nfnl_nft_message_new_table(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_TABLE_NAME);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_new_basechain(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_TABLE_NAME,
                                              "prerouting", "nat",
                                              NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST + 1);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_new_basechain(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_TABLE_NAME,
                                              "output", "nat",
                                              NF_INET_LOCAL_OUT, NF_IP_PRI_NAT_DST + 1);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_new_basechain(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_TABLE_NAME,
                                              "postrouting", "nat",
                                              NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC + 1);
        if (r < 0)
                return r;

        if (family == AF_INET) {
                ip_type_size = sizeof(uint32_t);
                ip_type = TYPE_IPADDR;
        } else {
                assert(family == AF_INET6);
                ip_type_size = sizeof(struct in6_addr);
                ip_type = TYPE_IP6ADDR;
        }
        /* set to store ip address ranges we should masquerade for */
        r = nft_new_set(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_MASQ_SET_NAME, ++set_id, NFT_SET_INTERVAL, ip_type, ip_type_size);
        if (r < 0)
                return r;

        /*
         * map to store ip address:port pair to dnat to.  elements in concatenation
         * are rounded up to 4 bytes.
         *
         * Example: ip protocol . tcp daddr is sizeof(uint32_t) + sizeof(uint32_t), not
         * sizeof(uint8_t) + sizeof(uint16_t).
         */
        r = nft_new_map(nfnl, &messages[msgcnt++], family, NFT_SYSTEMD_DNAT_MAP_NAME, ++set_id, 0,
                        concat_types2(TYPE_INET_PROTOCOL, TYPE_INET_SERVICE), sizeof(uint32_t) * 2,
                        concat_types2(ip_type, TYPE_INET_SERVICE), ip_type_size + sizeof(uint32_t));
        if (r < 0)
                return r;

        r = sd_nfnl_message_new_dnat_rule_pre(nfnl, &messages[msgcnt++], family, "prerouting");
        if (r < 0)
                return r;

        r = sd_nfnl_message_new_dnat_rule_out(nfnl, &messages[msgcnt++], family, "output");
        if (r < 0)
                return r;

        r = sd_nfnl_message_new_masq_rule(nfnl, &messages[msgcnt++], family, "postrouting");
        if (r < 0)
                return r;

        assert(msgcnt < ELEMENTSOF(messages));
        r = sd_nfnl_call_batch(nfnl, messages, msgcnt, NFNL_DEFAULT_TIMEOUT_USECS, NULL);
        if (r < 0 && r != -EEXIST)
                return r;

        return 0;
}

int fw_nftables_init(FirewallContext *ctx) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *nfnl = NULL;
        int r;

        assert(ctx);
        assert(!ctx->nfnl);

        r = sd_nfnl_socket_open(&nfnl);
        if (r < 0)
                return r;

        r = fw_nftables_init_family(nfnl, AF_INET);
        if (r < 0)
                return r;

        if (socket_ipv6_is_supported()) {
                r = fw_nftables_init_family(nfnl, AF_INET6);
                if (r < 0)
                        log_debug_errno(r, "Failed to init ipv6 NAT: %m");
        }

        ctx->nfnl = TAKE_PTR(nfnl);
        return 0;
}

void fw_nftables_exit(FirewallContext *ctx) {
        assert(ctx);

        ctx->nfnl = sd_netlink_unref(ctx->nfnl);
}

static int nft_message_append_setelem_iprange(
                sd_netlink_message *m,
                const union in_addr_union *source,
                unsigned int prefixlen) {

        uint32_t mask, start, end;
        unsigned int nplen;
        int r;

        assert(m);
        assert(source);
        assert(prefixlen <= 32);

        nplen = 32 - prefixlen;

        mask = (1U << nplen) - 1U;
        mask = htobe32(~mask);
        start = source->in.s_addr & mask;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_append_setelem(m, 0, &start, sizeof(start), NULL, 0, 0);
        if (r < 0)
                return r;

        end = be32toh(start) + (1U << nplen);
        if (end < be32toh(start))
                end = 0U;
        end = htobe32(end);

        r = sd_nfnl_nft_message_append_setelem(m, 1, &end, sizeof(end), NULL, 0, NFT_SET_ELEM_INTERVAL_END);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* NFTA_SET_ELEM_LIST_ELEMENTS */
}

static int nft_message_append_setelem_ip6range(
                sd_netlink_message *m,
                const union in_addr_union *source,
                unsigned int prefixlen) {

        union in_addr_union start, end;
        int r;

        assert(m);
        assert(source);

        r = in_addr_prefix_range(AF_INET6, source, prefixlen, &start, &end);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, NFTA_SET_ELEM_LIST_ELEMENTS);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_append_setelem(m, 0, &start.in6, sizeof(start.in6), NULL, 0, 0);
        if (r < 0)
                return r;

        r = sd_nfnl_nft_message_append_setelem(m, 1, &end.in6, sizeof(end.in6), NULL, 0, NFT_SET_ELEM_INTERVAL_END);
        if (r < 0)
                return r;

        return sd_netlink_message_close_container(m); /* NFTA_SET_ELEM_LIST_ELEMENTS */
}

static int fw_nftables_add_masquerade_internal(
                sd_netlink *nfnl,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned int source_prefixlen) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        int r;

        assert(nfnl);
        assert(IN_SET(af, AF_INET, AF_INET6));

        if (!source || source_prefixlen == 0)
                return -EINVAL;

        if (af == AF_INET6 && source_prefixlen < 8)
                return -EINVAL;

        r = sd_nfnl_nft_message_new_setelems(nfnl, &m, add, af, NFT_SYSTEMD_TABLE_NAME, NFT_SYSTEMD_MASQ_SET_NAME);
        if (r < 0)
                return r;

        if (af == AF_INET)
                 r = nft_message_append_setelem_iprange(m, source, source_prefixlen);
        else
                 r = nft_message_append_setelem_ip6range(m, source, source_prefixlen);
        if (r < 0)
                return r;

        return sd_nfnl_call_batch(nfnl, &m, 1, NFNL_DEFAULT_TIMEOUT_USECS, NULL);
}

int fw_nftables_add_masquerade(
                FirewallContext *ctx,
                bool add,
                int af,
                const union in_addr_union *source,
                unsigned int source_prefixlen) {

        int r;

        assert(ctx);
        assert(ctx->nfnl);
        assert(IN_SET(af, AF_INET, AF_INET6));

        if (!socket_ipv6_is_supported() && af == AF_INET6)
                return -EOPNOTSUPP;

        r = fw_nftables_add_masquerade_internal(ctx->nfnl, add, af, source, source_prefixlen);
        if (r != -ENOENT)
                return r;

        /* When someone runs 'nft flush ruleset' in the same net namespace this will also tear down the
         * systemd nat table.
         *
         * Unlike iptables -t nat -F (which will remove all rules added by the systemd iptables
         * backend, iptables has builtin chains that cannot be deleted -- the next add operation will
         * 'just work'.
         *
         * In the nftables case, everything gets removed. The next add operation will yield -ENOENT.
         *
         * If we see -ENOENT on add, replay the initial table setup. If that works, re-do the add
         * operation.
         *
         * Note that this doesn't protect against external sabotage such as a
         * 'while true; nft flush ruleset; done'. There is nothing that could be done about that short
         * of extending the kernel to allow tables to be owned by stystemd-networkd and making them
         * non-deleteable except by the 'owning process'. */

        r = fw_nftables_init_family(ctx->nfnl, af);
        if (r < 0)
                return r;

        return fw_nftables_add_masquerade_internal(ctx->nfnl, add, af, source, source_prefixlen);
}

static int fw_nftables_add_local_dnat_internal(
                sd_netlink *nfnl,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {

        sd_netlink_message *messages[3] = {};
        _unused_ _cleanup_(netlink_message_unref_manyp) sd_netlink_message **unref = messages;
        static bool ipv6_supported = true;
        uint32_t data[5], key[2], dlen;
        size_t msgcnt = 0;
        int r;

        assert(nfnl);
        assert(add || !previous_remote);
        assert(IN_SET(af, AF_INET, AF_INET6));

        if (!ipv6_supported && af == AF_INET6)
                return -EOPNOTSUPP;

        if (!IN_SET(protocol, IPPROTO_TCP, IPPROTO_UDP))
                return -EPROTONOSUPPORT;

        if (local_port <= 0)
                return -EINVAL;

        key[0] = protocol;
        key[1] = htobe16(local_port);

        if (!remote)
                return -EOPNOTSUPP;

        if (remote_port <= 0)
                return -EINVAL;

        if (af == AF_INET) {
                dlen = 8;
                data[1] = htobe16(remote_port);
        } else {
                assert(af == AF_INET6);
                dlen = sizeof(data);
                data[4] = htobe16(remote_port);
        }

        /* If a previous remote is set, remove its entry */
        if (add && previous_remote && !in_addr_equal(af, previous_remote, remote)) {
                if (af == AF_INET)
                        data[0] = previous_remote->in.s_addr;
                else
                        memcpy(data, &previous_remote->in6, sizeof(previous_remote->in6));

                r = nft_del_element(nfnl, &messages[msgcnt++], af, NFT_SYSTEMD_DNAT_MAP_NAME, key, sizeof(key), data, dlen);
                if (r < 0)
                        return r;
        }

        if (af == AF_INET)
                data[0] = remote->in.s_addr;
        else
                memcpy(data, &remote->in6, sizeof(remote->in6));

        if (add)
                r = nft_add_element(nfnl, &messages[msgcnt++], af, NFT_SYSTEMD_DNAT_MAP_NAME, key, sizeof(key), data, dlen);
        else
                r = nft_del_element(nfnl, &messages[msgcnt++], af, NFT_SYSTEMD_DNAT_MAP_NAME, key, sizeof(key), data, dlen);
        if (r < 0)
                return r;

        assert(msgcnt < ELEMENTSOF(messages));
        r = sd_nfnl_call_batch(nfnl, messages, msgcnt, NFNL_DEFAULT_TIMEOUT_USECS, NULL);
        if (r == -EOVERFLOW && af == AF_INET6) {
                /* The current implementation of DNAT in systemd requires kernel's
                 * fdb9c405e35bdc6e305b9b4e20ebc141ed14fc81 (v5.8), and the older kernel returns
                 * -EOVERFLOW. Let's treat the error as -EOPNOTSUPP. */
                log_debug_errno(r, "The current implementation of IPv6 DNAT in systemd requires kernel 5.8 or newer, ignoring: %m");
                ipv6_supported = false;
                return -EOPNOTSUPP;
        }
        if (r < 0)
                return r;

        return 0;
}

int fw_nftables_add_local_dnat(
                FirewallContext *ctx,
                bool add,
                int af,
                int protocol,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {

        int r;

        assert(ctx);
        assert(ctx->nfnl);
        assert(IN_SET(af, AF_INET, AF_INET6));

        if (!socket_ipv6_is_supported() && af == AF_INET6)
                return -EOPNOTSUPP;

        r = fw_nftables_add_local_dnat_internal(ctx->nfnl, add, af, protocol, local_port, remote, remote_port, previous_remote);
        if (r != -ENOENT)
                return r;

        /* See comment in fw_nftables_add_masquerade(). */
        r = fw_nftables_init_family(ctx->nfnl, af);
        if (r < 0)
                return r;

        /* table created anew; previous address already gone */
        return fw_nftables_add_local_dnat_internal(ctx->nfnl, add, af, protocol, local_port, remote, remote_port, NULL);
}
