/* SPDX-License-Identifier: LGPL-2.1+ */

/* Temporary work-around for broken glibc vs. linux kernel header definitions
 * This is already fixed upstream, remove this when distributions have updated.
 */
#define _NET_IF_H 1

#include <alloca.h>
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#include <linux/if.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_addrtype.h>
#include <libiptc/libiptc.h>

#include "alloc-util.h"
#include "firewall-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "socket-util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct xtc_handle*, iptc_free);

static int entry_fill_basics(
                struct ipt_entry *entry,
                int protocol,
                const char *in_interface,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const char *out_interface,
                const union in_addr_union *destination,
                unsigned destination_prefixlen) {

        assert(entry);

        if (out_interface && !ifname_valid(out_interface))
                return -EINVAL;
        if (in_interface && !ifname_valid(in_interface))
                return -EINVAL;

        entry->ip.proto = protocol;

        if (in_interface) {
                size_t l;

                l = strlen(in_interface);
                assert(l < sizeof entry->ip.iniface);
                assert(l < sizeof entry->ip.iniface_mask);

                strcpy(entry->ip.iniface, in_interface);
                memset(entry->ip.iniface_mask, 0xFF, l + 1);
        }
        if (source) {
                entry->ip.src = source->in;
                in4_addr_prefixlen_to_netmask(&entry->ip.smsk, source_prefixlen);
        }

        if (out_interface) {
                size_t l = strlen(out_interface);
                assert(l < sizeof entry->ip.outiface);
                assert(l < sizeof entry->ip.outiface_mask);

                strcpy(entry->ip.outiface, out_interface);
                memset(entry->ip.outiface_mask, 0xFF, l + 1);
        }
        if (destination) {
                entry->ip.dst = destination->in;
                in4_addr_prefixlen_to_netmask(&entry->ip.dmsk, destination_prefixlen);
        }

        return 0;
}

int fw_add_masquerade(
                bool add,
                int af,
                int protocol,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const char *out_interface,
                const union in_addr_union *destination,
                unsigned destination_prefixlen) {

        static const xt_chainlabel chain = "POSTROUTING";
        _cleanup_(iptc_freep) struct xtc_handle *h = NULL;
        struct ipt_entry *entry, *mask;
        struct ipt_entry_target *t;
        size_t sz;
        struct nf_nat_ipv4_multi_range_compat *mr;
        int r;

        if (af != AF_INET)
                return -EOPNOTSUPP;

        if (!IN_SET(protocol, 0, IPPROTO_TCP, IPPROTO_UDP))
                return -EOPNOTSUPP;

        h = iptc_init("nat");
        if (!h)
                return -errno;

        sz = XT_ALIGN(sizeof(struct ipt_entry)) +
             XT_ALIGN(sizeof(struct ipt_entry_target)) +
             XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat));

        /* Put together the entry we want to add or remove */
        entry = alloca0(sz);
        entry->next_offset = sz;
        entry->target_offset = XT_ALIGN(sizeof(struct ipt_entry));
        r = entry_fill_basics(entry, protocol, NULL, source, source_prefixlen, out_interface, destination, destination_prefixlen);
        if (r < 0)
                return r;

        /* Fill in target part */
        t = ipt_get_target(entry);
        t->u.target_size =
                XT_ALIGN(sizeof(struct ipt_entry_target)) +
                XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat));
        strncpy(t->u.user.name, "MASQUERADE", sizeof(t->u.user.name));
        mr = (struct nf_nat_ipv4_multi_range_compat*) t->data;
        mr->rangesize = 1;

        /* Create a search mask entry */
        mask = alloca(sz);
        memset(mask, 0xFF, sz);

        if (add) {
                if (iptc_check_entry(chain, entry, (unsigned char*) mask, h))
                        return 0;
                if (errno != ENOENT) /* if other error than not existing yet, fail */
                        return -errno;

                if (!iptc_insert_entry(chain, entry, 0, h))
                        return -errno;
        } else {
                if (!iptc_delete_entry(chain, entry, (unsigned char*) mask, h)) {
                        if (errno == ENOENT) /* if it's already gone, all is good! */
                                return 0;

                        return -errno;
                }
        }

        if (!iptc_commit(h))
                return -errno;

        return 0;
}

int fw_add_local_dnat(
                bool add,
                int af,
                int protocol,
                const char *in_interface,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const union in_addr_union *destination,
                unsigned destination_prefixlen,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {

        static const xt_chainlabel chain_pre = "PREROUTING", chain_output = "OUTPUT";
        _cleanup_(iptc_freep) struct xtc_handle *h = NULL;
        struct ipt_entry *entry, *mask;
        struct ipt_entry_target *t;
        struct ipt_entry_match *m;
        struct xt_addrtype_info_v1 *at;
        struct nf_nat_ipv4_multi_range_compat *mr;
        size_t sz, msz;
        int r;

        assert(add || !previous_remote);

        if (af != AF_INET)
                return -EOPNOTSUPP;

        if (!IN_SET(protocol, IPPROTO_TCP, IPPROTO_UDP))
                return -EOPNOTSUPP;

        if (local_port <= 0)
                return -EINVAL;

        if (remote_port <= 0)
                return -EINVAL;

        h = iptc_init("nat");
        if (!h)
                return -errno;

        sz = XT_ALIGN(sizeof(struct ipt_entry)) +
             XT_ALIGN(sizeof(struct ipt_entry_match)) +
             XT_ALIGN(sizeof(struct xt_addrtype_info_v1)) +
             XT_ALIGN(sizeof(struct ipt_entry_target)) +
             XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat));

        if (protocol == IPPROTO_TCP)
                msz = XT_ALIGN(sizeof(struct ipt_entry_match)) +
                      XT_ALIGN(sizeof(struct xt_tcp));
        else
                msz = XT_ALIGN(sizeof(struct ipt_entry_match)) +
                      XT_ALIGN(sizeof(struct xt_udp));

        sz += msz;

        /* Fill in basic part */
        entry = alloca0(sz);
        entry->next_offset = sz;
        entry->target_offset =
                XT_ALIGN(sizeof(struct ipt_entry)) +
                XT_ALIGN(sizeof(struct ipt_entry_match)) +
                XT_ALIGN(sizeof(struct xt_addrtype_info_v1)) +
                msz;
        r = entry_fill_basics(entry, protocol, in_interface, source, source_prefixlen, NULL, destination, destination_prefixlen);
        if (r < 0)
                return r;

        /* Fill in first match */
        m = (struct ipt_entry_match*) ((uint8_t*) entry + XT_ALIGN(sizeof(struct ipt_entry)));
        m->u.match_size = msz;
        if (protocol == IPPROTO_TCP) {
                struct xt_tcp *tcp;

                strncpy(m->u.user.name, "tcp", sizeof(m->u.user.name));
                tcp = (struct xt_tcp*) m->data;
                tcp->dpts[0] = tcp->dpts[1] = local_port;
                tcp->spts[0] = 0;
                tcp->spts[1] = 0xFFFF;

        } else {
                struct xt_udp *udp;

                strncpy(m->u.user.name, "udp", sizeof(m->u.user.name));
                udp = (struct xt_udp*) m->data;
                udp->dpts[0] = udp->dpts[1] = local_port;
                udp->spts[0] = 0;
                udp->spts[1] = 0xFFFF;
        }

        /* Fill in second match */
        m = (struct ipt_entry_match*) ((uint8_t*) entry + XT_ALIGN(sizeof(struct ipt_entry)) + msz);
        m->u.match_size =
                XT_ALIGN(sizeof(struct ipt_entry_match)) +
                XT_ALIGN(sizeof(struct xt_addrtype_info_v1));
        strncpy(m->u.user.name, "addrtype", sizeof(m->u.user.name));
        m->u.user.revision = 1;
        at = (struct xt_addrtype_info_v1*) m->data;
        at->dest = XT_ADDRTYPE_LOCAL;

        /* Fill in target part */
        t = ipt_get_target(entry);
        t->u.target_size =
                XT_ALIGN(sizeof(struct ipt_entry_target)) +
                XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat));
        strncpy(t->u.user.name, "DNAT", sizeof(t->u.user.name));
        mr = (struct nf_nat_ipv4_multi_range_compat*) t->data;
        mr->rangesize = 1;
        mr->range[0].flags = NF_NAT_RANGE_PROTO_SPECIFIED|NF_NAT_RANGE_MAP_IPS;
        mr->range[0].min_ip = mr->range[0].max_ip = remote->in.s_addr;
        if (protocol == IPPROTO_TCP)
                mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = htobe16(remote_port);
        else
                mr->range[0].min.udp.port = mr->range[0].max.udp.port = htobe16(remote_port);

        mask = alloca0(sz);
        memset(mask, 0xFF, sz);

        if (add) {
                /* Add the PREROUTING rule, if it is missing so far */
                if (!iptc_check_entry(chain_pre, entry, (unsigned char*) mask, h)) {
                        if (errno != ENOENT)
                                return -EINVAL;

                        if (!iptc_insert_entry(chain_pre, entry, 0, h))
                                return -errno;
                }

                /* If a previous remote is set, remove its entry */
                if (previous_remote && previous_remote->in.s_addr != remote->in.s_addr) {
                        mr->range[0].min_ip = mr->range[0].max_ip = previous_remote->in.s_addr;

                        if (!iptc_delete_entry(chain_pre, entry, (unsigned char*) mask, h)) {
                                if (errno != ENOENT)
                                        return -errno;
                        }

                        mr->range[0].min_ip = mr->range[0].max_ip = remote->in.s_addr;
                }

                /* Add the OUTPUT rule, if it is missing so far */
                if (!in_interface) {

                        /* Don't apply onto loopback addresses */
                        if (!destination) {
                                entry->ip.dst.s_addr = htobe32(0x7F000000);
                                entry->ip.dmsk.s_addr = htobe32(0xFF000000);
                                entry->ip.invflags = IPT_INV_DSTIP;
                        }

                        if (!iptc_check_entry(chain_output, entry, (unsigned char*) mask, h)) {
                                if (errno != ENOENT)
                                        return -errno;

                                if (!iptc_insert_entry(chain_output, entry, 0, h))
                                        return -errno;
                        }

                        /* If a previous remote is set, remove its entry */
                        if (previous_remote && previous_remote->in.s_addr != remote->in.s_addr) {
                                mr->range[0].min_ip = mr->range[0].max_ip = previous_remote->in.s_addr;

                                if (!iptc_delete_entry(chain_output, entry, (unsigned char*) mask, h)) {
                                        if (errno != ENOENT)
                                                return -errno;
                                }
                        }
                }
        } else {
                if (!iptc_delete_entry(chain_pre, entry, (unsigned char*) mask, h)) {
                        if (errno != ENOENT)
                                return -errno;
                }

                if (!in_interface) {
                        if (!destination) {
                                entry->ip.dst.s_addr = htobe32(0x7F000000);
                                entry->ip.dmsk.s_addr = htobe32(0xFF000000);
                                entry->ip.invflags = IPT_INV_DSTIP;
                        }

                        if (!iptc_delete_entry(chain_output, entry, (unsigned char*) mask, h)) {
                                if (errno != ENOENT)
                                        return -errno;
                        }
                }
        }

        if (!iptc_commit(h))
                return -errno;

        return 0;
}
