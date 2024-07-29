/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf_insn.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-firewall.h"
#include "bpf-program.h"
#include "fd-util.h"
#include "in-addr-prefix-util.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "unit.h"
#include "strv.h"
#include "virt.h"

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
                /* Compare IPv4 with one word instruction (32-bit) */
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

static int add_instructions_for_ip_any(
                BPFProgram *p,
                int verdict) {
        int r;

        assert(p);

        const struct bpf_insn insn[] = {
                BPF_ALU32_IMM(BPF_OR, BPF_REG_8, verdict),
        };

        r = bpf_program_add_instructions(p, insn, 1);
        if (r < 0)
                return r;

        return 0;
}

static int bpf_firewall_compile_bpf(
                Unit *u,
                const char *prog_name,
                bool is_ingress,
                BPFProgram **ret,
                bool ip_allow_any,
                bool ip_deny_any) {

        const struct bpf_insn pre_insn[] = {
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
        const struct bpf_insn post_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_JMP_IMM(BPF_JNE, BPF_REG_8, ACCESS_DENIED, 1),
                BPF_MOV64_IMM(BPF_REG_0, 0),
        };

        _cleanup_(bpf_program_freep) BPFProgram *p = NULL;
        int accounting_map_fd, r;
        bool access_enabled;
        CGroupRuntime *crt;

        assert(u);
        assert(ret);

        crt = unit_get_cgroup_runtime(u);
        if (!crt) {
                *ret = NULL;
                return 0;
        }

        accounting_map_fd = is_ingress ?
                crt->ip_accounting_ingress_map_fd :
                crt->ip_accounting_egress_map_fd;

        access_enabled =
                crt->ipv4_allow_map_fd >= 0 ||
                crt->ipv6_allow_map_fd >= 0 ||
                crt->ipv4_deny_map_fd >= 0 ||
                crt->ipv6_deny_map_fd >= 0 ||
                ip_allow_any ||
                ip_deny_any;

        if (accounting_map_fd < 0 && !access_enabled) {
                *ret = NULL;
                return 0;
        }

        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, prog_name, &p);
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

                if (crt->ipv4_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, crt->ipv4_deny_map_fd, ETH_P_IP, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (crt->ipv6_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, crt->ipv6_deny_map_fd, ETH_P_IPV6, is_ingress, ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (crt->ipv4_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, crt->ipv4_allow_map_fd, ETH_P_IP, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (crt->ipv6_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, crt->ipv6_allow_map_fd, ETH_P_IPV6, is_ingress, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (ip_allow_any) {
                        r = add_instructions_for_ip_any(p, ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (ip_deny_any) {
                        r = add_instructions_for_ip_any(p, ACCESS_DENIED);
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
                const struct bpf_insn insn[] = {
                        BPF_EXIT_INSN()
                };

                r = bpf_program_add_instructions(p, insn, ELEMENTSOF(insn));
                if (r < 0)
                        return r;
        } while (false);

        *ret = TAKE_PTR(p);

        return 0;
}

static int bpf_firewall_count_access_items(Set *prefixes, size_t *n_ipv4, size_t *n_ipv6) {
        struct in_addr_prefix *a;

        assert(n_ipv4);
        assert(n_ipv6);

        SET_FOREACH(a, prefixes)
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

        return 0;
}

static int bpf_firewall_add_access_items(
                Set *prefixes,
                int ipv4_map_fd,
                int ipv6_map_fd,
                int verdict) {

        struct bpf_lpm_trie_key *key_ipv4, *key_ipv6;
        struct in_addr_prefix *a;
        uint64_t value = verdict;
        int r;

        key_ipv4 = alloca0(offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t));
        key_ipv6 = alloca0(offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t) * 4);

        SET_FOREACH(a, prefixes)
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

        return 0;
}

static int bpf_firewall_prepare_access_maps(
                Unit *u,
                int verdict,
                int *ret_ipv4_map_fd,
                int *ret_ipv6_map_fd,
                bool *ret_has_any) {

        _cleanup_close_ int ipv4_map_fd = -EBADF, ipv6_map_fd = -EBADF;
        size_t n_ipv4 = 0, n_ipv6 = 0;
        int r;

        assert(ret_ipv4_map_fd);
        assert(ret_ipv6_map_fd);
        assert(ret_has_any);

        for (Unit *p = u; p; p = UNIT_GET_SLICE(p)) {
                CGroupContext *cc;
                Set *prefixes;
                bool *reduced;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                prefixes = verdict == ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny;
                reduced = verdict == ACCESS_ALLOWED ? &cc->ip_address_allow_reduced : &cc->ip_address_deny_reduced;

                if (!*reduced) {
                        r = in_addr_prefixes_reduce(prefixes);
                        if (r < 0)
                                return r;

                        *reduced = true;
                }

                bpf_firewall_count_access_items(prefixes, &n_ipv4, &n_ipv6);

                /* Skip making the LPM trie map in cases where we are using "any" in order to hack around
                 * needing CAP_SYS_ADMIN for allocating LPM trie map. */
                if (in_addr_prefixes_is_any(prefixes)) {
                        *ret_has_any = true;
                        return 0;
                }
        }

        if (n_ipv4 > 0) {
                const char *name = strjoina("4_", u->id);
                ipv4_map_fd = bpf_map_new(
                                name,
                                BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t),
                                sizeof(uint64_t),
                                n_ipv4,
                                BPF_F_NO_PREALLOC);
                if (ipv4_map_fd < 0)
                        return ipv4_map_fd;
        }

        if (n_ipv6 > 0) {
                const char *name = strjoina("6_", u->id);
                ipv6_map_fd = bpf_map_new(
                                name,
                                BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint32_t)*4,
                                sizeof(uint64_t),
                                n_ipv6,
                                BPF_F_NO_PREALLOC);
                if (ipv6_map_fd < 0)
                        return ipv6_map_fd;
        }

        for (Unit *p = u; p; p = UNIT_GET_SLICE(p)) {
                CGroupContext *cc;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                r = bpf_firewall_add_access_items(verdict == ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny,
                                                  ipv4_map_fd, ipv6_map_fd, verdict);
                if (r < 0)
                        return r;
        }

        *ret_ipv4_map_fd = TAKE_FD(ipv4_map_fd);
        *ret_ipv6_map_fd = TAKE_FD(ipv6_map_fd);
        *ret_has_any = false;
        return 0;
}

static int bpf_firewall_prepare_accounting_maps(Unit *u, bool enabled, CGroupRuntime *crt) {
        int r;

        assert(u);
        assert(crt);

        if (enabled) {
                if (crt->ip_accounting_ingress_map_fd < 0) {
                        const char *name = strjoina("I_", u->id);
                        r = bpf_map_new(name, BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2, 0);
                        if (r < 0)
                                return r;

                        crt->ip_accounting_ingress_map_fd = r;
                }

                if (crt->ip_accounting_egress_map_fd < 0) {
                        const char *name = strjoina("E_", u->id);
                        r = bpf_map_new(name, BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(uint64_t), 2, 0);
                        if (r < 0)
                                return r;

                        crt->ip_accounting_egress_map_fd = r;
                }

        } else {
                crt->ip_accounting_ingress_map_fd = safe_close(crt->ip_accounting_ingress_map_fd);
                crt->ip_accounting_egress_map_fd = safe_close(crt->ip_accounting_egress_map_fd);

                zero(crt->ip_accounting_extra);
        }

        return 0;
}

int bpf_firewall_compile(Unit *u) {
        const char *ingress_name = NULL, *egress_name = NULL;
        bool ip_allow_any = false, ip_deny_any = false;
        CGroupContext *cc;
        CGroupRuntime *crt;
        int r, supported;

        assert(u);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return -EINVAL;

        crt = unit_setup_cgroup_runtime(u);
        if (!crt)
                return -ENOMEM;

        supported = bpf_firewall_supported();
        if (supported < 0)
                return supported;
        if (supported == BPF_FIREWALL_UNSUPPORTED)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF firewalling not supported, proceeding without.");
        if (supported != BPF_FIREWALL_SUPPORTED_WITH_MULTI && u->type == UNIT_SLICE)
                /* If BPF_F_ALLOW_MULTI is not supported we don't support any BPF magic on inner nodes (i.e. on slice
                 * units), since that would mean leaf nodes couldn't do any BPF anymore at all. Under the assumption
                 * that BPF is more interesting on leaf nodes we hence avoid it on inner nodes in that case. This is
                 * consistent with old systemd behaviour from before v238, where BPF wasn't supported in inner nodes at
                 * all, either. */
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF_F_ALLOW_MULTI is not supported, not doing BPF firewall on slice units.");

        /* If BPF_F_ALLOW_MULTI flag is supported program name is also supported (both were added to v4.15
         * kernel). */
        if (supported == BPF_FIREWALL_SUPPORTED_WITH_MULTI) {
                ingress_name = "sd_fw_ingress";
                egress_name = "sd_fw_egress";
        }

        /* Note that when we compile a new firewall we first flush out the access maps and the BPF programs themselves,
         * but we reuse the accounting maps. That way the firewall in effect always maps to the actual
         * configuration, but we don't flush out the accounting unnecessarily */

        crt->ip_bpf_ingress = bpf_program_free(crt->ip_bpf_ingress);
        crt->ip_bpf_egress = bpf_program_free(crt->ip_bpf_egress);

        crt->ipv4_allow_map_fd = safe_close(crt->ipv4_allow_map_fd);
        crt->ipv4_deny_map_fd = safe_close(crt->ipv4_deny_map_fd);

        crt->ipv6_allow_map_fd = safe_close(crt->ipv6_allow_map_fd);
        crt->ipv6_deny_map_fd = safe_close(crt->ipv6_deny_map_fd);

        if (u->type != UNIT_SLICE) {
                /* In inner nodes we only do accounting, we do not actually bother with access control. However, leaf
                 * nodes will incorporate all IP access rules set on all their parent nodes. This has the benefit that
                 * they can optionally cancel out system-wide rules. Since inner nodes can't contain processes this
                 * means that all configure IP access rules *will* take effect on processes, even though we never
                 * compile them for inner nodes. */

                r = bpf_firewall_prepare_access_maps(u, ACCESS_ALLOWED, &crt->ipv4_allow_map_fd, &crt->ipv6_allow_map_fd, &ip_allow_any);
                if (r < 0)
                        return log_unit_error_errno(u, r, "bpf-firewall: Preparation of BPF allow maps failed: %m");

                r = bpf_firewall_prepare_access_maps(u, ACCESS_DENIED, &crt->ipv4_deny_map_fd, &crt->ipv6_deny_map_fd, &ip_deny_any);
                if (r < 0)
                        return log_unit_error_errno(u, r, "bpf-firewall: Preparation of BPF deny maps failed: %m");
        }

        r = bpf_firewall_prepare_accounting_maps(u, cc->ip_accounting, crt);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-firewall: Preparation of BPF accounting maps failed: %m");

        r = bpf_firewall_compile_bpf(u, ingress_name, true, &crt->ip_bpf_ingress, ip_allow_any, ip_deny_any);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-firewall: Compilation of ingress BPF program failed: %m");

        r = bpf_firewall_compile_bpf(u, egress_name, false, &crt->ip_bpf_egress, ip_allow_any, ip_deny_any);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-firewall: Compilation of egress BPF program failed: %m");

        return 0;
}

static int load_bpf_progs_from_fs_to_set(Unit *u, char **filter_paths, Set **set) {
        set_clear(*set);

        STRV_FOREACH(bpf_fs_path, filter_paths) {
                _cleanup_(bpf_program_freep) BPFProgram *prog = NULL;
                int r;

                r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, NULL, &prog);
                if (r < 0)
                        return log_unit_error_errno(u, r, "bpf-firewall: Allocation of SKB BPF program failed: %m");

                r = bpf_program_load_from_bpf_fs(prog, *bpf_fs_path);
                if (r < 0)
                        return log_unit_error_errno(u, r, "bpf-firewall: Loading of ingress BPF program %s failed: %m", *bpf_fs_path);

                r = set_ensure_consume(set, &bpf_program_hash_ops, TAKE_PTR(prog));
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

int bpf_firewall_load_custom(Unit *u) {
        CGroupContext *cc;
        CGroupRuntime *crt;
        int r, supported;

        assert(u);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return 0;
        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return 0;

        if (!(cc->ip_filters_ingress || cc->ip_filters_egress))
                return 0;

        supported = bpf_firewall_supported();
        if (supported < 0)
                return supported;

        if (supported != BPF_FIREWALL_SUPPORTED_WITH_MULTI)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF_F_ALLOW_MULTI not supported, cannot attach custom BPF programs.");

        r = load_bpf_progs_from_fs_to_set(u, cc->ip_filters_ingress, &crt->ip_bpf_custom_ingress);
        if (r < 0)
                return r;
        r = load_bpf_progs_from_fs_to_set(u, cc->ip_filters_egress, &crt->ip_bpf_custom_egress);
        if (r < 0)
                return r;

        return 0;
}

static int attach_custom_bpf_progs(Unit *u, const char *path, int attach_type, Set **set, Set **set_installed) {
        BPFProgram *prog;
        int r;

        assert(u);

        set_clear(*set_installed);
        r = set_ensure_allocated(set_installed, &bpf_program_hash_ops);
        if (r < 0)
                return log_oom();

        SET_FOREACH_MOVE(prog, *set_installed, *set) {
                r = bpf_program_cgroup_attach(prog, attach_type, path, BPF_F_ALLOW_MULTI);
                if (r < 0)
                        return log_unit_error_errno(u, r, "bpf-firewall: Attaching custom egress BPF program to cgroup %s failed: %m", path);
        }
        return 0;
}

int bpf_firewall_install(Unit *u) {
        _cleanup_(bpf_program_freep) BPFProgram *ip_bpf_ingress_uninstall = NULL, *ip_bpf_egress_uninstall = NULL;
        _cleanup_free_ char *path = NULL;
        CGroupContext *cc;
        CGroupRuntime *crt;
        int r, supported;
        uint32_t flags;

        assert(u);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return -EINVAL;
        crt = unit_get_cgroup_runtime(u);
        if (!crt)
                return -EINVAL;
        if (!crt->cgroup_path)
                return -EINVAL;
        if (!crt->cgroup_realized)
                return -EINVAL;

        supported = bpf_firewall_supported();
        if (supported < 0)
                return supported;
        if (supported == BPF_FIREWALL_UNSUPPORTED)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF firewalling not supported, proceeding without.");
        if (supported != BPF_FIREWALL_SUPPORTED_WITH_MULTI && u->type == UNIT_SLICE)
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF_F_ALLOW_MULTI not supported, not doing BPF firewall on slice units.");
        if (supported != BPF_FIREWALL_SUPPORTED_WITH_MULTI &&
            (!set_isempty(crt->ip_bpf_custom_ingress) || !set_isempty(crt->ip_bpf_custom_egress)))
                return log_unit_debug_errno(u, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "bpf-firewall: BPF_F_ALLOW_MULTI not supported, cannot attach custom BPF programs.");

        r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, crt->cgroup_path, NULL, &path);
        if (r < 0)
                return log_unit_error_errno(u, r, "bpf-firewall: Failed to determine cgroup path: %m");

        flags = supported == BPF_FIREWALL_SUPPORTED_WITH_MULTI ? BPF_F_ALLOW_MULTI : 0;

        if (FLAGS_SET(flags, BPF_F_ALLOW_MULTI)) {
                /* If we have BPF_F_ALLOW_MULTI, then let's clear the fields, but destroy the programs only
                 * after attaching the new programs, so that there's no time window where neither program is
                 * attached. (There will be a program where both are attached, but that's OK, since this is a
                 * security feature where we rather want to lock down too much than too little */
                ip_bpf_egress_uninstall = TAKE_PTR(crt->ip_bpf_egress_installed);
                ip_bpf_ingress_uninstall = TAKE_PTR(crt->ip_bpf_ingress_installed);
        } else {
                /* If we don't have BPF_F_ALLOW_MULTI then unref the old BPF programs (which will implicitly
                 * detach them) right before attaching the new program, to minimize the time window when we
                 * don't account for IP traffic. */
                crt->ip_bpf_egress_installed = bpf_program_free(crt->ip_bpf_egress_installed);
                crt->ip_bpf_ingress_installed = bpf_program_free(crt->ip_bpf_ingress_installed);
        }

        if (crt->ip_bpf_egress) {
                r = bpf_program_cgroup_attach(crt->ip_bpf_egress, BPF_CGROUP_INET_EGRESS, path, flags);
                if (r < 0)
                        return log_unit_error_errno(u, r,
                                "bpf-firewall: Attaching egress BPF program to cgroup %s failed: %m", path);

                /* Remember that this BPF program is installed now. */
                crt->ip_bpf_egress_installed = TAKE_PTR(crt->ip_bpf_egress);
        }

        if (crt->ip_bpf_ingress) {
                r = bpf_program_cgroup_attach(crt->ip_bpf_ingress, BPF_CGROUP_INET_INGRESS, path, flags);
                if (r < 0)
                        return log_unit_error_errno(u, r,
                                "bpf-firewall: Attaching ingress BPF program to cgroup %s failed: %m", path);

                crt->ip_bpf_ingress_installed = TAKE_PTR(crt->ip_bpf_ingress);
        }

        /* And now, definitely get rid of the old programs, and detach them */
        ip_bpf_egress_uninstall = bpf_program_free(ip_bpf_egress_uninstall);
        ip_bpf_ingress_uninstall = bpf_program_free(ip_bpf_ingress_uninstall);

        r = attach_custom_bpf_progs(u, path, BPF_CGROUP_INET_EGRESS, &crt->ip_bpf_custom_egress, &crt->ip_bpf_custom_egress_installed);
        if (r < 0)
                return r;

        r = attach_custom_bpf_progs(u, path, BPF_CGROUP_INET_INGRESS, &crt->ip_bpf_custom_ingress, &crt->ip_bpf_custom_ingress_installed);
        if (r < 0)
                return r;

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

static int bpf_firewall_unsupported_reason = 0;

int bpf_firewall_supported(void) {
        const struct bpf_insn trivial[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),
                BPF_EXIT_INSN()
        };

        _cleanup_(bpf_program_freep) BPFProgram *program = NULL;
        static int supported = -1;
        union bpf_attr attr;
        int r;

        /* Checks whether BPF firewalling is supported. For this, we check the following things:
         *
         * - whether the unified hierarchy is being used
         * - the BPF implementation in the kernel supports BPF_PROG_TYPE_CGROUP_SKB programs, which we require
         * - the BPF implementation in the kernel supports the BPF_PROG_DETACH call, which we require
         */
        if (supported >= 0)
                return supported;

        r = cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER);
        if (r < 0)
                return log_error_errno(r, "bpf-firewall: Can't determine whether the unified hierarchy is used: %m");
        if (r == 0) {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(SYNTHETIC_ERRNO(EUCLEAN),
                                        "bpf-firewall: Not running with unified cgroup hierarchy, BPF firewalling is not supported.");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }

        /* prog_name is NULL since it is supported only starting from v4.15 kernel. */
        r = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB, NULL, &program);
        if (r < 0) {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(r, "bpf-firewall: Can't allocate CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }

        r = bpf_program_add_instructions(program, trivial, ELEMENTSOF(trivial));
        if (r < 0) {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(r, "bpf-firewall: Can't add trivial instructions to CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }

        r = bpf_program_load_kernel(program, NULL, 0);
        if (r < 0) {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(r, "bpf-firewall: Can't load kernel CGROUP SKB BPF program, BPF firewalling is not supported: %m");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }

        /* Unfortunately the kernel allows us to create BPF_PROG_TYPE_CGROUP_SKB programs even when CONFIG_CGROUP_BPF
         * is turned off at kernel compilation time. This sucks of course: why does it allow us to create a cgroup BPF
         * program if we can't do a thing with it later?
         *
         * We detect this case by issuing the BPF_PROG_DETACH bpf() call with invalid file descriptors: if
         * CONFIG_CGROUP_BPF is turned off, then the call will fail early with EINVAL. If it is turned on the
         * parameters are validated however, and that'll fail with EBADF then. */

        // FIXME: Clang doesn't 0-pad with structured initialization, causing
        // the kernel to reject the bpf_attr as invalid. See:
        // https://github.com/torvalds/linux/blob/v5.9/kernel/bpf/syscall.c#L65
        // Ideally it should behave like GCC, so that we can remove these workarounds.
        zero(attr);
        attr.attach_type = BPF_CGROUP_INET_EGRESS;
        attr.target_fd = -EBADF;
        attr.attach_bpf_fd = -EBADF;

        if (bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) < 0) {
                if (errno != EBADF) {
                        bpf_firewall_unsupported_reason =
                                log_debug_errno(errno, "bpf-firewall: Didn't get EBADF from BPF_PROG_DETACH, BPF firewalling is not supported: %m");
                        return supported = BPF_FIREWALL_UNSUPPORTED;
                }

                /* YAY! */
        } else {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(SYNTHETIC_ERRNO(EBADE),
                                        "bpf-firewall: Wut? Kernel accepted our invalid BPF_PROG_DETACH call? "
                                        "Something is weird, assuming BPF firewalling is broken and hence not supported.");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }

        /* So now we know that the BPF program is generally available, let's see if BPF_F_ALLOW_MULTI is also supported
         * (which was added in kernel 4.15). We use a similar logic as before, but this time we use the BPF_PROG_ATTACH
         * bpf() call and the BPF_F_ALLOW_MULTI flags value. Since the flags are checked early in the system call we'll
         * get EINVAL if it's not supported, and EBADF as before if it is available.
         * Use probe result as the indicator that program name is also supported since they both were
         * added in kernel 4.15. */

        zero(attr);
        attr.attach_type = BPF_CGROUP_INET_EGRESS;
        attr.target_fd = -EBADF;
        attr.attach_bpf_fd = -EBADF;
        attr.attach_flags = BPF_F_ALLOW_MULTI;

        if (bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
                if (errno == EBADF) {
                        log_debug_errno(errno, "bpf-firewall: Got EBADF when using BPF_F_ALLOW_MULTI, which indicates it is supported. Yay!");
                        return supported = BPF_FIREWALL_SUPPORTED_WITH_MULTI;
                }

                if (errno == EINVAL)
                        log_debug_errno(errno, "bpf-firewall: Got EINVAL error when using BPF_F_ALLOW_MULTI, which indicates it's not supported.");
                else
                        log_debug_errno(errno, "bpf-firewall: Got unexpected error when using BPF_F_ALLOW_MULTI, assuming it's not supported: %m");

                return supported = BPF_FIREWALL_SUPPORTED;
        } else {
                bpf_firewall_unsupported_reason =
                        log_debug_errno(SYNTHETIC_ERRNO(EBADE),
                                        "bpf-firewall: Wut? Kernel accepted our invalid BPF_PROG_ATTACH+BPF_F_ALLOW_MULTI call? "
                                        "Something is weird, assuming BPF firewalling is broken and hence not supported.");
                return supported = BPF_FIREWALL_UNSUPPORTED;
        }
}

void emit_bpf_firewall_warning(Unit *u) {
        static bool warned = false;

        assert(u);
        assert(u->manager);

        if (warned || MANAGER_IS_TEST_RUN(u->manager))
                return;

        bool quiet = ERRNO_IS_PRIVILEGE(bpf_firewall_unsupported_reason) && detect_container() > 0;

        log_unit_full_errno(u, quiet ? LOG_DEBUG : LOG_WARNING, bpf_firewall_unsupported_reason,
                            "unit configures an IP firewall, but %s.\n"
                            "(This warning is only shown for the first unit using IP firewalling.)",
                            getuid() != 0 ? "not running as root" :
                            "the local system does not support BPF/cgroup firewalling");
        warned = true;
}

void bpf_firewall_close(CGroupRuntime *crt) {
        assert(crt);

        crt->ip_accounting_ingress_map_fd = safe_close(crt->ip_accounting_ingress_map_fd);
        crt->ip_accounting_egress_map_fd = safe_close(crt->ip_accounting_egress_map_fd);

        crt->ipv4_allow_map_fd = safe_close(crt->ipv4_allow_map_fd);
        crt->ipv6_allow_map_fd = safe_close(crt->ipv6_allow_map_fd);
        crt->ipv4_deny_map_fd = safe_close(crt->ipv4_deny_map_fd);
        crt->ipv6_deny_map_fd = safe_close(crt->ipv6_deny_map_fd);

        crt->ip_bpf_ingress = bpf_program_free(crt->ip_bpf_ingress);
        crt->ip_bpf_ingress_installed = bpf_program_free(crt->ip_bpf_ingress_installed);
        crt->ip_bpf_egress = bpf_program_free(crt->ip_bpf_egress);
        crt->ip_bpf_egress_installed = bpf_program_free(crt->ip_bpf_egress_installed);

        crt->ip_bpf_custom_ingress = set_free(crt->ip_bpf_custom_ingress);
        crt->ip_bpf_custom_egress = set_free(crt->ip_bpf_custom_egress);
        crt->ip_bpf_custom_ingress_installed = set_free(crt->ip_bpf_custom_ingress_installed);
        crt->ip_bpf_custom_egress_installed = set_free(crt->ip_bpf_custom_egress_installed);
}
