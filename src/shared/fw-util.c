/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter/xt_addrtype.h>
#include <libiptc/libiptc.h>

#include "util.h"
#include "fw-util.h"

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

        if (out_interface && strlen(out_interface) >= IFNAMSIZ)
                return -EINVAL;

        if (in_interface && strlen(in_interface) >= IFNAMSIZ)
                return -EINVAL;

        entry->ip.proto = protocol;

        if (in_interface) {
                strcpy(entry->ip.iniface, in_interface);
                memset(entry->ip.iniface_mask, 0xFF, strlen(in_interface)+1);
        }
        if (source) {
                entry->ip.src = source->in;
                in_addr_prefixlen_to_netmask(&entry->ip.smsk, source_prefixlen);
        }

        if (out_interface) {
                strcpy(entry->ip.outiface, out_interface);
                memset(entry->ip.outiface_mask, 0xFF, strlen(out_interface)+1);
        }
        if (destination) {
                entry->ip.dst = destination->in;
                in_addr_prefixlen_to_netmask(&entry->ip.dmsk, destination_prefixlen);
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

        _cleanup_(iptc_freep) struct xtc_handle *h = NULL;
        struct ipt_entry *entry, *mask;
        struct ipt_entry_target *t;
        size_t sz;
        struct nf_nat_ipv4_multi_range_compat *mr;
        int r;

        if (af != AF_INET)
                return -EOPNOTSUPP;

        if (protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
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
                if (iptc_check_entry("POSTROUTING", entry, (unsigned char*) mask, h))
                        return 0;
                if (errno != ENOENT) /* if other error than not existing yet, fail */
                        return -errno;

                if (!iptc_insert_entry("POSTROUTING", entry, 0, h))
                        return -errno;
        } else {
                if (!iptc_delete_entry("POSTROUTING", entry, (unsigned char*) mask, h)) {
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

        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
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
                mr->range[0].min.tcp.port = mr->range[0].max.tcp.port = htons(remote_port);
        else
                mr->range[0].min.udp.port = mr->range[0].max.udp.port = htons(remote_port);

        mask = alloca0(sz);
        memset(mask, 0xFF, sz);

        if (add) {
                /* Add the PREROUTING rule, if it is missing so far */
                if (!iptc_check_entry("PREROUTING", entry, (unsigned char*) mask, h)) {
                        if (errno != ENOENT)
                                return -EINVAL;

                        if (!iptc_insert_entry("PREROUTING", entry, 0, h))
                                return -errno;
                }

                /* If a previous remote is set, remove its entry */
                if (previous_remote && previous_remote->in.s_addr != remote->in.s_addr) {
                        mr->range[0].min_ip = mr->range[0].max_ip = previous_remote->in.s_addr;

                        if (!iptc_delete_entry("PREROUTING", entry, (unsigned char*) mask, h)) {
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

                        if (!iptc_check_entry("OUTPUT", entry, (unsigned char*) mask, h)) {
                                if (errno != ENOENT)
                                        return -errno;

                                if (!iptc_insert_entry("OUTPUT", entry, 0, h))
                                        return -errno;
                        }

                        /* If a previous remote is set, remove its entry */
                        if (previous_remote && previous_remote->in.s_addr != remote->in.s_addr) {
                                mr->range[0].min_ip = mr->range[0].max_ip = previous_remote->in.s_addr;

                                if (!iptc_delete_entry("OUTPUT", entry, (unsigned char*) mask, h)) {
                                        if (errno != ENOENT)
                                                return -errno;
                                }
                        }
                }
        } else {
                if (!iptc_delete_entry("PREROUTING", entry, (unsigned char*) mask, h)) {
                        if (errno != ENOENT)
                                return -errno;
                }

                if (!in_interface) {
                        if (!destination) {
                                entry->ip.dst.s_addr = htobe32(0x7F000000);
                                entry->ip.dmsk.s_addr = htobe32(0xFF000000);
                                entry->ip.invflags = IPT_INV_DSTIP;
                        }

                        if (!iptc_delete_entry("OUTPUT", entry, (unsigned char*) mask, h)) {
                                if (errno != ENOENT)
                                        return -errno;
                        }
                }
        }

        if (!iptc_commit(h))
                return -errno;

        return 0;
}
