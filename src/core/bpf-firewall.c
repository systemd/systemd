/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack

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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/libbpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bpf-program.h"
#include "fd-util.h"
#include "ip-address-access.h"
#include "unit.h"

enum {
        MAP_KEY_PACKETS,
        MAP_KEY_BYTES,
};

enum {
        ACCESS_ALLOWED = 1,
        ACCESS_DENIED  = 2,
};

/* Compile instructions for one list of addresses, one direction and one specific verdict on matches. */

static int add_lookup_instructions(
                BPFProgram *p,
                int map_fd,
                int protocol,
                bool is_ingress,
                int verdict) {

        int r, addr_offset, addr_size;

        assert(p);
        assert(map_fd >= 0);

        switch (protocol) {

        case ETH_P_IP:
                addr_size = sizeof(uint32_t);
                addr_offset = is_ingress ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);
                break;

        case ETH_P_IPV6:
                addr_size = 4 * sizeof(uint32_t);
                addr_offset = is_ingress ?
                        offsetof(struct ip6_hdr, ip6_src.s6_addr) :
                        offsetof(struct ip6_hdr, ip6_dst.s6_addr);
                break;

        default:
                return -EAFNOSUPPORT;
        }

        do {
                /* Compare IPv4 with one word instruction (32bit) */
                struct bpf_insn insn[] = {
                        /* If skb->protocol != ETH_P_IP, skip this whole block. The offset will be set later. */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(protocol), 0),

                        /*
                         * Call into BPF_FUNC_skb_load_bytes to load the dst/src IP address
                         *
                         * R1: Pointer to the skb
                         * R2: Data offset
                         * R3: Destination buffer on the stack (r10 - 4)
                         * R4: Number of bytes to read (4)
                         */

                        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
                        BPF_MOV32_IMM(BPF_REG_2, addr_offset),

                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -addr_size),

                        BPF_MOV32_IMM(BPF_REG_4, addr_size),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                        /*
                         * Call into BPF_FUNC_map_lookup_elem to see if the address matches any entry in the
                         * LPM trie map. For this to work, the prefixlen field of 'struct bpf_lpm_trie_key'
                         * has to be set to the maximum possible value.
                         *
                         * On success, the looked up value is stored in R0. For this application, the actual
                         * value doesn't matter, however; we just set the bit in @verdict in R8 if we found any
                         * matching value.
                         */

                        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -addr_size - sizeof(uint32_t)),
                        BPF_ST_MEM(BPF_W, BPF_REG_2, 0, addr_size * 8),

                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
                        BPF_ALU32_IMM(BPF_OR, BPF_REG_8, verdict),
                };

                /* Jump label fixup */
                insn[0].off = ELEMENTSOF(insn) - 1;

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;

        } while (false);

        return 0;
}

static int bpf_firewall_compile_bpf(
                Unit *u,
                bool is_ingress,
                BPFProgram **ret) {

        struct bpf_insn pre_insn[] = {
                /*
                 * When the eBPF program is entered, R1 contains the address of the skb.
                 * However, R1-R5 are scratch registers that are not preserved when calling
                 * into kernel functions, so we need to save anything that's supposed to
                 * stay around to R6-R9. Save the skb to R6.
                 */
                BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),

                /*
                 * Although we cannot access the skb data directly from eBPF programs used in this
                 * scenario, the kernel has prepared some fields for us to access through struct __sk_buff.
                 * Load the protocol (IPv4, IPv6) used by the packet in flight once and cache it in R7
                 * for later use.
                 */
                BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct __sk_buff, protocol)),

                /*
                 * R8 is used to keep track of whether any address check has explicitly allowed or denied the packet
                 * through ACCESS_DENIED or ACCESS_ALLOWED bits. Reset them both to 0 in the beginning.
                 */
                BPF_MOV32_IMM(BPF_REG_8, 0),
        };

        /*
         * The access checkers compiled for the configured allowance and denial lists
         * write to R8 at runtime. The following code prepares for an early exit that
         * skip the accounting if the packet is denied.
         *
         * R0 = 1
         * if (R8 == ACCESS_DENIED)
         *     R0 = 0
         *
         * This means that if both ACCESS_DENIED and ACCESS_ALLOWED are set, the packet
         * is allowed to pass.
         */
        struct bpf_insn post_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_JMP_IMM(BPF_JNE, BPF_REG_8, ACCESS_DENIED, 1),
                BPF_MOV64_IMM(BPF_REG_0, 0),
        };

        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;
        int accounting_map_fd, r;
        bool access_enabled;

        assert(u);
        assert(ret);

        accounting_map_fd = is_ingress ?
                u->ip_accounting_ingress_map_fd :
                u->ip_accounting_egress_map_fd;

        access_enabled =
                u->ipv4_allow_map_fd >= 0 ||
                u->ipv6_allow_map_fd >= 0 ||
                u->ipv4_deny_map_fd >= 0 ||
                u->ipv6_deny_map_fd >= 0;

        if (accounting_map_fd < 0 && !access_enabled) {
                *ret = NULL;
                return 0;
        }

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, &p);
        if (r < 0)
                return r;

        r = bpf_program_add_instructions(p, pre_insn, ELEMENTSOF(pre_insn));
        if (r < 0)
                return r;

        if (access_enabled) {
                /*
                 * The simple rule this function translates into eBPF instructions is:
                 *
                 * - Access will be granted when an address matches an entry in @list_allow
                 * - Otherwise, access will be denied when an address matches an entry in @list_deny
                 * - Otherwise, access will be granted
                 */

                if (u->ipv4_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv4_deny_map_fd, ETH_P_IP, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv6_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv6_deny_map_fd, ETH_P_IPV6, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv4_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv4_allow_map_fd, ETH_P_IP, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv6_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv6_allow_map_fd, ETH_P_IPV6, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }
        }

        r = bpf_program_add_instructions(p, post_insn, ELEMENTSOF(post_insn));
        if (r < 0)
                return r;

        if (accounting_map_fd >= 0) {
                struct bpf_insn insn[] = {
                        /*
                         * If R0 == 0, the packet will be denied; skip the accounting instructions in this case.
                         * The jump label will be fixed up later.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0),

                        /* Count packets */
                        BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_PACKETS), /* r0 = 0 */
                        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
                        BPF_LD_MAP_FD(BPF_REG_1, accounting_map_fd), /* load map fd to r1 */
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
                        BPF_MOV64_IMM(BPF_REG_1, 1), /* r1 = 1 */
                        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */

                        /* Count bytes */
                        BPF_MOV64_IMM(BPF_REG_0, MAP_KEY_BYTES), /* r0 = 1 */
                        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), /* *(u32 *)(fp - 4) = r0 */
                        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), /* r2 = fp - 4 */
                        BPF_LD_MAP_FD(BPF_REG_1, accounting_map_fd),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
                        BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offsetof(struct __sk_buff, len)), /* r1 = skb->len */
                        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), /* xadd r0 += r1 */

                        /* Allow the packet to pass */
                        BPF_MOV64_IMM(BPF_REG_0, 1),
                };

                /* Jump label fixup */
                insn[0].off = ELEMENTSOF(insn) - 1;

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;
        }

        do {
                /*
                 * Exit from the eBPF program, R0 contains the verdict.
                 * 0 means the packet is denied, 1 means the packet may pass.
                 */
                struct bpf_insn insn[] = {
                        BPF_EXIT_INSN()
                };

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;
        } while (false);

        *ret = p;
        p = NULL;

        return 0;
}

static int bpf_firewall_count_access_items(IPAddressAccessItem *list, size_t *n_ipv4, size_t *n_ipv6) {
        IPAddressAccessItem *a;

        assert(n_ipv4);
        assert(n_ipv6);

        LIST_FOREACH(items, a, list) {
                switch (a->family) {

                case AF_INET:
                        (*n_ipv4)++;
                        break;

                case AF_INET6:
                        (*n_ipv6)++;
                        break;

                default:
                        return -EAFNOSUPPORT;
                }
        }

        return 0;
}

static int bpf_firewall_add_access_items(
                IPAddressAccessItem *list,
                int ipv4_map_fd,
                int ipv6_map_fd,
                int verdict) {

        struct bpf_lpm_trie_key *key_ipv4, *key_ipv6;
        uint64_t value = verdict;
        IPAddressAccessItem *a;
        int r;

        key_ipv4 = alloca0(offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t));
        key_ipv6 = alloca0(offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t) * 4);

        LIST_FOREACH(items, a, list) {
                switch (a->family) {

                case AF_INET:
                        key_ipv4->prefixlen = a->prefixlen;
                        memcpy(key_ipv4->data, &a->address, sizeof(uint32_t));

                        r = bpf_map_update_element(ipv4_map_fd, key_ipv4, &value);
                        if (r < 0)
                                return r;

                        break;

                case AF_INET6:
                        key_ipv6->prefixlen = a->prefixlen;
                        memcpy(key_ipv6->data, &a->address, 4 * sizeof(uint32_t));

                        r = bpf_map_update_element(ipv6_map_fd, key_ipv6, &value);
                        if (r < 0)
                                return r;

                        break;

                default:
                        return -EAFNOSUPPORT;
                }
        }

        return 0;
}

static int bpf_firewall_prepare_access_maps(
                Unit *u,
                int verdict,
                int *ret_ipv4_map_fd,
                int *ret_ipv6_map_fd) {

        _cleanup_close_ int ipv4_map_fd = -1, ipv6_map_fd = -1;
        size_t n_ipv4 = 0, n_ipv6 = 0;
        Unit *p;
        int r;

        assert(ret_ipv4_map_fd);
        assert(ret_ipv6_map_fd);

        for (p = u; p; p = UNIT_DEREF(p->slice)) {
                CGroupContext *cc;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                bpf_firewall_count_access_items(verdict == ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny, &n_ipv4, &n_ipv6);
        }

        if (n_ipv4 > 0) {
                ipv4_map_fd = bpf_map_new(
                                BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t),
                                sizeof(uint64_t),
                                n_ipv4,
                                BPF_F_NO_PREALLOC);
                if (ipv4_map_fd < 0)
                        return ipv4_map_fd;
        }

        if (n_ipv6 > 0) {
                ipv6_map_fd = bpf_map_new(
                                BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t)*4,
                                sizeof(uint64_t),
                                n_ipv6,
                                BPF_F_NO_PREALLOC);
                if (ipv6_map_fd < 0)
                        return ipv6_map_fd;
        }

        for (p = u; p; p = UNIT_DEREF(p->slice)) {
                CGroupContext *cc;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                r = bpf_firewall_add_access_items(verdict == ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny,
                                                  ipv4_map_fd, ipv6_map_fd, verdict);
                if (r < 0)
                        return r;
        }

        *ret_ipv4_map_fd = ipv4_map_fd;
        *ret_ipv6_map_fd = ipv6_map_fd;

        ipv4_map_fd = ipv6_map_fd = -1;
        return 0;
}

static int bpf_firewall_prepare_accounting_maps(bool enabled, int *fd_ingress, int *fd_egress) {
        int r;

        assert(fd_ingress);
        assert(fd_egress);

        if (enabled) {
                if (*fd_ingress < 0) {
                        r = bpf_map_new(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2, 0);
                        if (r < 0)
                                return r;

                        *fd_ingress = r;
                }

                if (*fd_egress < 0) {

                        r = bpf_map_new(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2, 0);
                        if (r < 0)
                                return r;

                        *fd_egress = r;
                }
        } else {
                *fd_ingress = safe_close(*fd_ingress);
                *fd_egress = safe_close(*fd_egress);
        }

        return 0;
}

int bpf_firewall_compile(Unit *u) {
        CGroupContext *cc;
        int r;

        assert(u);

        r = bpf_firewall_supported();
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("BPF firewalling not supported on this systemd, proceeding without.");
                return -EOPNOTSUPP;
        }

        /* Note that when we compile a new firewall we first flush out the access maps and the BPF programs themselves,
         * but we reuse the the accounting maps. That way the firewall in effect always maps to the actual
         * configuration, but we don't flush out the accounting unnecessarily */

        u->ip_bpf_ingress = bpf_program_unref(u->ip_bpf_ingress);
        u->ip_bpf_egress = bpf_program_unref(u->ip_bpf_egress);

        u->ipv4_allow_map_fd = safe_close(u->ipv4_allow_map_fd);
        u->ipv4_deny_map_fd = safe_close(u->ipv4_deny_map_fd);

        u->ipv6_allow_map_fd = safe_close(u->ipv6_allow_map_fd);
        u->ipv6_deny_map_fd = safe_close(u->ipv6_deny_map_fd);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return -EINVAL;

        r = bpf_firewall_prepare_access_maps(u, ACCESS_ALLOWED, &u->ipv4_allow_map_fd, &u->ipv6_allow_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF allow maps failed: %m");

        r = bpf_firewall_prepare_access_maps(u, ACCESS_DENIED, &u->ipv4_deny_map_fd, &u->ipv6_deny_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF deny maps failed: %m");

        r = bpf_firewall_prepare_accounting_maps(cc->ip_accounting, &u->ip_accounting_ingress_map_fd, &u->ip_accounting_egress_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF accounting maps failed: %m");

        r = bpf_firewall_compile_bpf(u, true, &u->ip_bpf_ingress);
        if (r < 0)
                return log_error_errno(r, "Compilation for ingress BPF program failed: %m");

        r = bpf_firewall_compile_bpf(u, false, &u->ip_bpf_egress);
        if (r < 0)
                return log_error_errno(r, "Compilation for egress BPF program failed: %m");

        return 0;
}

int bpf_firewall_install(Unit *u) {
        _cleanup_free_ char *path = NULL;
        CGroupContext *cc;
        int r;

        assert(u);

        if (!u->cgroup_path)
                return -EINVAL;

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return -EINVAL;

        r = bpf_firewall_supported();
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("BPF firewalling not supported on this systemd, proceeding without.");
                return -EOPNOTSUPP;
        }

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, u->cgroup_path, NULL, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup path: %m");

        if (u->ip_bpf_egress) {
                r = bpf_program_load_kernel(u->ip_bpf_egress, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Kernel upload of egress BPF program failed: %m");

                r = bpf_program_cgroup_attach(u->ip_bpf_egress, BPF_CGROUP_INET_EGRESS, path, cc->delegate ? BPF_F_ALLOW_OVERRIDE : 0);
                if (r < 0)
                        return log_error_errno(r, "Attaching egress BPF program to cgroup %s failed: %m", path);
        } else {
                r = bpf_program_cgroup_detach(BPF_CGROUP_INET_EGRESS, path);
                if (r < 0)
                        return log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_ERR, r,
                                              "Detaching egress BPF program from cgroup failed: %m");
        }

        if (u->ip_bpf_ingress) {
                r = bpf_program_load_kernel(u->ip_bpf_ingress, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Kernel upload of ingress BPF program failed: %m");

                r = bpf_program_cgroup_attach(u->ip_bpf_ingress, BPF_CGROUP_INET_INGRESS, path, cc->delegate ? BPF_F_ALLOW_OVERRIDE : 0);
                if (r < 0)
                        return log_error_errno(r, "Attaching ingress BPF program to cgroup %s failed: %m", path);
        } else {
                r = bpf_program_cgroup_detach(BPF_CGROUP_INET_INGRESS, path);
                if (r < 0)
                        return log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_ERR, r,
                                              "Detaching ingress BPF program from cgroup failed: %m");
        }

        return 0;
}

int bpf_firewall_read_accounting(int map_fd, uint64_t *ret_bytes, uint64_t *ret_packets) {
        uint64_t key, packets;
        int r;

        if (map_fd < 0)
                return -EBADF;

        if (ret_packets) {
                key = MAP_KEY_PACKETS;
                r = bpf_map_lookup_element(map_fd, &key, &packets);
                if (r < 0)
                        return r;
        }

        if (ret_bytes) {
                key = MAP_KEY_BYTES;
                r = bpf_map_lookup_element(map_fd, &key, ret_bytes);
                if (r < 0)
                        return r;
        }

        if (ret_packets)
                *ret_packets = packets;

        return 0;
}

int bpf_firewall_reset_accounting(int map_fd) {
        uint64_t key, value = 0;
        int r;

        if (map_fd < 0)
                return -EBADF;

        key = MAP_KEY_PACKETS;
        r = bpf_map_update_element(map_fd, &key, &value);
        if (r < 0)
                return r;

        key = MAP_KEY_BYTES;
        return bpf_map_update_element(map_fd, &key, &value);
}


int bpf_firewall_supported(void) {
        struct bpf_insn trivial[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        _cleanup_(bpf_program_unrefp) BPFProgram *program = NULL;
        static int supported = -1;
        union bpf_attr attr;
        int fd, r;

        /* Checks whether BPF firewalling is supported. For this, we check five things:
         *
         * a) whether we are privileged
         * b) whether the unified hierarchy is being used
         * c) the BPF implementation in the kernel supports BPF LPM TRIE maps, which we require
         * d) the BPF implementation in the kernel supports BPF_PROG_TYPE_CGROUP_SKB programs, which we require
         * e) the BPF implementation in the kernel supports the BPF_PROG_ATTACH call, which we require
         *
         */

        if (supported >= 0)
                return supported;

        if (geteuid() != 0) {
                log_debug("Not enough privileges, BPF firewalling is not supported.");
                return supported = false;
        }

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "Can't determine whether the unified hierarchy is used: %m");
        if (r == 0) {
                log_debug("Not running with unified cgroups, BPF firewalling is not supported.");
                return supported = false;
        }

        fd = bpf_map_new(BPF_MAP_TYPE_LPM_TRIE,
                         offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint64_t),
                         sizeof(uint64_t),
                         1,
                         BPF_F_NO_PREALLOC);
        if (fd < 0) {
                log_debug_errno(r, "Can't allocate BPF LPM TRIE map, BPF firewalling is not supported: %m");
                return supported = false;
        }

        safe_close(fd);

        if (bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, &program) < 0) {
                log_debug_errno(r, "Can't allocate CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = false;
        }

        r = bpf_program_add_instructions(program, trivial, ELEMENTSOF(trivial));
        if (r < 0) {
                log_debug_errno(r, "Can't add trivial instructions to CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = false;
        }

        r = bpf_program_load_kernel(program, NULL, 0);
        if (r < 0) {
                log_debug_errno(r, "Can't load kernel CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = false;
        }

        /* Unfortunately the kernel allows us to create BPF_PROG_TYPE_CGROUP_SKB programs even when CONFIG_CGROUP_BPF
         * is turned off at kernel compilation time. This sucks of course: why does it allow us to create a cgroup BPF
         * program if we can't do a thing with it later?
         *
         * We detect this case by issuing the BPF_PROG_ATTACH bpf() call with invalid file descriptors: if
         * CONFIG_CGROUP_BPF is turned off, then the call will fail early with EINVAL. If it is turned on the
         * parameters are validated however, and that'll fail with EBADF then. */

        attr = (union bpf_attr) {
                .attach_type = BPF_CGROUP_INET_EGRESS,
                .target_fd = -1,
                .attach_bpf_fd = -1,
        };

        r = bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
        if (r < 0) {
                if (errno == EBADF) /* YAY! */
                        return supported = true;

                log_debug_errno(errno, "Didn't get EBADF from BPF_PROG_ATTACH, BPF firewalling is not supported: %m");
        } else
                log_debug("Wut? kernel accepted our invalid BPF_PROG_ATTACH call? Something is weird, assuming BPF firewalling is broken and hence not supported.");

        return supported = false;
}
