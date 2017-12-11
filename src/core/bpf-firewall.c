/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack
  Copyright 2017 Intel Corporation.

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
#include <netinet/tcp.h>
#include <netinet/udp.h>
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
#include "port-range-access.h"
#include "unit.h"

enum {
        MAP_KEY_PACKETS,
        MAP_KEY_BYTES,
};

enum {
        ADDRESS_ACCESS_ALLOWED = (1 << 0),
        ADDRESS_ACCESS_DENIED  = (1 << 1),
        PORT_ACCESS_ALLOWED    = (1 << 2),
        PORT_ACCESS_DENIED     = (1 << 3),
};

static void fix_jumps(struct bpf_insn *prog, uint length, uint offset) {
        uint i;

        /* Make all -1-length jumps go to the end of the block. */
        for (i = 0; i < length; i++)
                if ((prog[i].code & BPF_JMP) && (prog[i].off == -1))
                        prog[i].off = offset - i - 1;
}

static int add_port_lookup_instructions(
                BPFProgram *p,
                int map_fd,
                int protocol,
                bool is_ingress,
                int verdict) {
        /*
         * We are interested only in destination port regardless of ingress or
         * egress -- source port is typically ephemeral. TCP and UDP have the
         * ports in the same place in header structure.
         */
        size_t tcp_port_offset = offsetof(struct tcphdr, dest);

        struct bpf_insn port_check_insn[] = {
                /*
                 * Assumptions: R2 contains the IP header length. R9 has the
                 * transport layer protocol. R6 has the SKB.
                 */

                /*
                 * Check for TCP or UDP. If either is not found, jump to the
                 * end or the block. This means that we don't protect unknown
                 * protocols.
                 */
                BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_TCP, 1),
                BPF_JMP_IMM(BPF_JNE, BPF_REG_9, IPPROTO_UDP, -1),

                /*
                 * This starts the TCP/UDP processing. First load port bytes
                 * from the skb.
                 */
                BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),

                /*
                 * Add destination port offset to R2.
                 */
                BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, tcp_port_offset),

                /*
                 * R7 = destination buffer in the stack. The destination port
                 * data is two bytes long.
                 */
                BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
                BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -2),
                BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),

                /*
                 * Read the destination port bytes.
                 */
                BPF_MOV64_IMM(BPF_REG_4, 2),
                BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                /*
                 * R3 = destination port number.
                 */
                BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_7, 0),

                /*
                 * Next check if the port number in the packet happens to be
                 * inside any of the port range elements in the port map.
                 */

                BPF_LD_MAP_FD(BPF_REG_1, map_fd),
                BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),

                /*
                 * Copy the prefix, the port number, and the protocol to stack.
                 * They take 8 bytes in total. Write prefix to R2, padding to
                 * R2+4, protocol to R2+5, and port number to R2+6. The port
                 * number is stored in R3 and protocol is still in R9. Prefix is
                 * always 32, since port number is 16 bits and padded protocol
                 * is 16 bits.
                 *
                 * The access has to be done in an aligned way (eight bytes) for
                 * kernels whose version < 4.14.
                 */
                BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
                /* prefix word */
                BPF_ST_MEM(BPF_W, BPF_REG_2, 0, 32),
                /* padding byte */
                BPF_ST_MEM(BPF_B, BPF_REG_2, 4, 0),
                /* protocol byte */
                BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_9, 5),
                /* port half word */
                BPF_STX_MEM(BPF_H, BPF_REG_2, BPF_REG_3, 6),

                BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

                /*
                 * R0 contains the return value. If it's 0, no match -> jump to
                 * the end of the block. Otherwise, apply the verdict. Note that
                 * we might as well read the verdict from the map if needed.
                 */
                BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -1),
                BPF_ALU32_IMM(BPF_OR, BPF_REG_8, verdict),
        };

        struct bpf_insn footer_insn[] = {
                /*
                 * Restore R7, which was needed as a scratch register during the
                 * port retrieval.
                 */
                BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct __sk_buff, protocol)),
        };

        struct bpf_insn header_insn[] = {
                /*
                 * Check if the packet was already denied by the address check.
                 * Jump over the port checking if it was. The jump offset is
                 * fixed later.
                 */
                BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, ADDRESS_ACCESS_DENIED, -1),
        };

        int r;

        assert(p);
        assert(map_fd >= 0);
        assert_cc(offsetof(struct tcphdr, dest) == offsetof(struct udphdr, dest));

        if (protocol == ETH_P_IP) {
                size_t protocol_offset = offsetof(struct iphdr, protocol);

                struct bpf_insn ipv4_insn[] = {
                        /*
                         * If skb->protocol != ETH_P_IP, skip this whole block.
                         * The jump offset is fixed later.
                         */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(protocol), -1),

                        /*
                         * Load IP header beginning from the skb into stack. R7
                         * is the destination buffer in the stack.
                         */
                        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
                        BPF_MOV64_IMM(BPF_REG_2, 0),
                        BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),

                        /*
                         * Reserve 12 bytes of space in the stack. Then read 12
                         * bytes to get the values we are interested in: the
                         * IP header length and the transport layer protocol.
                         * We do this in one long read instead of two short
                         * reads.
                         */
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -12),
                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),
                        BPF_MOV32_IMM(BPF_REG_4, 12),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                        /*
                         * R2 = IHL, header length is (IHL * 32 / 8) bytes. IHL
                         * bits are located in the first byte (offset 0).
                         */
                        BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_7, 0),
                        BPF_ALU32_IMM(BPF_AND, BPF_REG_9, 0xf),
                        BPF_ALU32_IMM(BPF_MUL, BPF_REG_9, 4),
                        BPF_MOV32_REG(BPF_REG_2, BPF_REG_9),

                        /*
                         * R9 = transport layer protocol.
                         */
                        BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_7, protocol_offset),
                };

                /*
                 * Fix the jumps to the end of the block.
                 */
                size_t prog_len = ELEMENTSOF(header_insn) + ELEMENTSOF(ipv4_insn) + ELEMENTSOF(port_check_insn);

                fix_jumps(header_insn, ELEMENTSOF(header_insn), prog_len);
                fix_jumps(ipv4_insn, ELEMENTSOF(ipv4_insn), prog_len-ELEMENTSOF(header_insn));
                fix_jumps(port_check_insn, ELEMENTSOF(port_check_insn), prog_len-ELEMENTSOF(ipv4_insn)-ELEMENTSOF(header_insn));

                r = bpf_program_add_instructions(p, header_insn, ELEMENTSOF(header_insn));
                if (r < 0)
                        return r;

                r = bpf_program_add_instructions(p, ipv4_insn, ELEMENTSOF(ipv4_insn));
                if (r < 0)
                        return r;

        } else if (protocol == ETH_P_IPV6) {
                size_t protocol_offset = offsetof(struct ip6_hdrctl, ip6_un1_nxt);

                struct bpf_insn ipv6_insn[] = {
                        /*
                         * If skb->protocol != ETH_P_IPV6, skip this whole
                         * block. The jump offset is fixed later.
                         */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(protocol), -1),

                        /*
                         * Load "Next Header" field from the IPv6 header into
                         * the stack. R7 is the destination buffer in the stack.
                         */
                        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
                        BPF_MOV64_IMM(BPF_REG_2, protocol_offset),
                        BPF_MOV64_REG(BPF_REG_7, BPF_REG_10),
                        /*
                         * Make room in the stack for one byte.
                         */
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -1),
                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),

                        /*
                         * Read one byte from the skb to get the transport
                         * layer protocol.
                         */
                        BPF_MOV32_IMM(BPF_REG_4, 1),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                        /*
                         * IPv6 header is always 40 bytes long.
                         */
                        BPF_MOV32_IMM(BPF_REG_2, 40),

                        /*
                         * R9 = next header (extension header or transport layer
                         * protocol).
                         */
                        BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_7, 0),
                };

                struct bpf_insn ipv6_eh_insn_template[] = {
                        /*
                         * Next check the protocol -- there might be extension
                         * headers in the way. Assumptions: R2 contains the IP
                         * header length. R9 has the transport layer protocol.
                         * R6 has the SKB.
                         *
                         * If there is an extension header, parse the header and
                         * run this check again. Else jump over the extension
                         * header check.
                         */

                        /*
                         * First see if we have standard TCP or UDP. Jump over
                         * the extension header processing if that's the case.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_TCP, -1),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_UDP, -1),

                        /*
                         * Start looking at the other known header types (see
                         * https://tools.ietf.org/html/rfc8200).
                         */

                        /*
                         * Hop-by-hop extension header has the same layout as
                         * routing extension header and destination options
                         * header, so they can be processed using the same code.
                         */

                        /* Fragmentation extension header. */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_FRAGMENT, 4),

                        /*
                         * Hop-by-hop extension header. It is required to be the
                         * first extension header, but we don't check that.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_HOPOPTS, 3),
                        /*
                         * Routing extension header.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_ROUTING, 2),
                        /*
                         * Authentication header. This should be removed by the
                         * kernel, but the comments there say that this might
                         * change in the future.
                         */
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_AH, 1),
                        /*
                         * Destination options extension header. This is the
                         * last extension header we know, so jump over the
                         * extension check if this isn't the case.
                         */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_9, IPPROTO_DSTOPTS, -1),

                        /*
                         * Save the length, because we will lose R2 during the
                         * skb_load_bytes call.
                         */
                        BPF_MOV64_REG(BPF_REG_7, BPF_REG_2),

                        BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
                        /*
                         * Make room in the stack for two bytes.
                         */
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -2),

                        /*
                         * Read two bytes from the skb to get the next header
                         * and length.
                         */
                        BPF_MOV64_IMM(BPF_REG_4, 2),
                        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),

                        /*
                         * Set R3 to point at the stack where the values were
                         * loaded.
                         */
                        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -2),

                        /*
                         * Update the length to R2. Fragmentation header has a
                         * fixed length (8 octets), so we set the length to be 0
                         * (because 8 is always added). Otherwise take the value
                         * from stack and multiply it with 8 (since the value
                         * is the EH length in octets).
                         */
                        BPF_MOV64_IMM(BPF_REG_2, 0),
                        BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, IPPROTO_FRAGMENT, 2),
                        BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_3, 1),
                        BPF_ALU64_IMM(BPF_MUL, BPF_REG_2, 8),

                        /*
                         * AH length requires different processing.
                         *
                         * The AH payload length is in 32-bit words, so still
                         * multiply with 4. We need again to add the first
                         * two words (8 octets) to the result.
                         */
                        BPF_JMP_IMM(BPF_JNE, BPF_REG_9, IPPROTO_AH, 1),
                        BPF_ALU64_IMM(BPF_MUL, BPF_REG_2, 4),

                        /*
                         * Length value doesn't include the first 8 octets. Add
                         * that data.
                         */
                        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 8),

                        /*
                         * Add the saved length back to R2.
                         */
                        BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_7),

                        /*
                         * Set the next header to R9.
                         */
                        BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_3, 0),
                };

                struct bpf_insn ipv6_eh_insn[ELEMENTSOF(ipv6_eh_insn_template)*8];
                size_t prog_len = ELEMENTSOF(header_insn) +
                                ELEMENTSOF(ipv6_insn) +
                                ELEMENTSOF(ipv6_eh_insn) +
                                ELEMENTSOF(port_check_insn);
                size_t i;

                fix_jumps(header_insn, ELEMENTSOF(header_insn), prog_len);
                fix_jumps(ipv6_insn, ELEMENTSOF(ipv6_insn), prog_len-ELEMENTSOF(header_insn));

                /*
                 * Since there may be a bunch of extension headers (and we
                 * can't have loops), do extension header check eight times.
                 * Eight is the max number of extension headers, because every
                 * header can be present only once except for the Destination
                 * Options, which can be present twice.
                 */

                for (i = 0; i < 8; i++)
                        memcpy(ipv6_eh_insn + i * ELEMENTSOF(ipv6_eh_insn_template), ipv6_eh_insn_template, sizeof(ipv6_eh_insn_template));

                /* Fix jumps only to the end of the current block */
                fix_jumps(ipv6_eh_insn, ELEMENTSOF(ipv6_eh_insn), ELEMENTSOF(ipv6_eh_insn));

                fix_jumps(port_check_insn, ELEMENTSOF(port_check_insn), prog_len-ELEMENTSOF(ipv6_eh_insn)-ELEMENTSOF(ipv6_insn)-ELEMENTSOF(header_insn));

                r = bpf_program_add_instructions(p, header_insn, ELEMENTSOF(header_insn));
                if (r < 0)
                        return r;

                r = bpf_program_add_instructions(p, ipv6_insn, ELEMENTSOF(ipv6_insn));
                if (r < 0)
                        return r;

                r = bpf_program_add_instructions(p, ipv6_eh_insn, ELEMENTSOF(ipv6_eh_insn));
                if (r < 0)
                        return r;
        } else
                return -EAFNOSUPPORT;

        r = bpf_program_add_instructions(p, port_check_insn, ELEMENTSOF(port_check_insn));
        if (r < 0)
                return r;

        r = bpf_program_add_instructions(p, footer_insn, ELEMENTSOF(footer_insn));
        if (r < 0)
                return r;

        return 0;
}

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
                 * R8 is used to keep track of whether any access check has explicitly allowed or denied the packet
                 * through ADDRESS_ACCESS_DENIED, ADDRESS_ACCESS_ALLOWED, PORT_ACCESS_DENIED and PORT_ACCESS_ALLOWED
                 * bits. Reset them all to 0 in the beginning.
                 */
                BPF_MOV32_IMM(BPF_REG_8, 0),
        };

        /*
         * The access checkers compiled for the configured allowance and denial lists
         * write to R8 at runtime. The following code prepares for an early exit that
         * skip the accounting if the packet is denied.
         *
         * R0 = 1
         * R1 = R8
         * R1 &= (ADDRESS_ACCESS_DENIED | ADDRESS_ACCESS_ALLOWED)
         * if (R1 == ADDRESS_ACCESS_DENIED)
         *     R0 = 0
         * R1 = R8
         * R1 &= (PORT_ACCESS_DENIED | PORT_ACCESS_ALLOWED)
         * if (R1 == PORT_ACCESS_DENIED)
         *     R0 = 0
         *
         * This means that if both ADDRESS_ACCESS_DENIED and ADDRESS_ACCESS_ALLOWED are
         * set, the packet is allowed to pass, unless it fails the similar port check.
         */
        struct bpf_insn post_insn[] = {
                BPF_MOV64_IMM(BPF_REG_0, 1),

                BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
                BPF_ALU64_IMM(BPF_AND, BPF_REG_1, (ADDRESS_ACCESS_ALLOWED | ADDRESS_ACCESS_DENIED)),
                BPF_JMP_IMM(BPF_JNE, BPF_REG_1, ADDRESS_ACCESS_DENIED, 1),
                BPF_MOV64_IMM(BPF_REG_0, 0),

                BPF_MOV64_REG(BPF_REG_1, BPF_REG_8),
                BPF_ALU64_IMM(BPF_AND, BPF_REG_1, (PORT_ACCESS_ALLOWED | PORT_ACCESS_DENIED)),
                BPF_JMP_IMM(BPF_JNE, BPF_REG_1, PORT_ACCESS_DENIED, 1),
                BPF_MOV64_IMM(BPF_REG_0, 0),
        };

        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;
        int accounting_map_fd, r;
        bool access_enabled, port_filter_enabled, address_filter_enabled;

        assert(u);
        assert(ret);

        accounting_map_fd = is_ingress ?
                u->ip_accounting_ingress_map_fd :
                u->ip_accounting_egress_map_fd;

        address_filter_enabled = u->ipv4_allow_map_fd >= 0 ||
                u->ipv6_allow_map_fd >= 0 ||
                u->ipv4_deny_map_fd >= 0 ||
                u->ipv6_deny_map_fd >= 0;

        port_filter_enabled = u->port_allow_map_ingress_fd >= 0 ||
                u->port_allow_map_egress_fd >= 0 ||
                u->port_deny_map_ingress_fd >= 0 ||
                u->port_deny_map_egress_fd >= 0;

        access_enabled = address_filter_enabled || port_filter_enabled;

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
                        r = add_lookup_instructions(p, u->ipv4_deny_map_fd, ETH_P_IP, is_ingress, ADDRESS_ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv6_deny_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv6_deny_map_fd, ETH_P_IPV6, is_ingress, ADDRESS_ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv4_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv4_allow_map_fd, ETH_P_IP, is_ingress, ADDRESS_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (u->ipv6_allow_map_fd >= 0) {
                        r = add_lookup_instructions(p, u->ipv6_allow_map_fd, ETH_P_IPV6, is_ingress, ADDRESS_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                /*
                 * The same processing for port-based filtering. Run first allow
                 * and only then deny program for both ingress and egress, so
                 * that we can skip processing if address check returns a deny
                 * verdict.
                 */

                if (u->port_allow_map_ingress_fd >= 0 && is_ingress) {
                        r = add_port_lookup_instructions(p, u->port_allow_map_ingress_fd, ETH_P_IP, is_ingress, PORT_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;

                        r = add_port_lookup_instructions(p, u->port_allow_map_ingress_fd, ETH_P_IPV6, is_ingress, PORT_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (u->port_deny_map_ingress_fd >= 0 && is_ingress) {
                        r = add_port_lookup_instructions(p, u->port_deny_map_ingress_fd, ETH_P_IP, is_ingress, PORT_ACCESS_DENIED);
                        if (r < 0)
                                return r;

                        r = add_port_lookup_instructions(p, u->port_deny_map_ingress_fd, ETH_P_IPV6, is_ingress, PORT_ACCESS_DENIED);
                        if (r < 0)
                                return r;
                }

                if (u->port_allow_map_egress_fd >= 0 && !is_ingress) {
                        r = add_port_lookup_instructions(p, u->port_allow_map_egress_fd, ETH_P_IP, is_ingress, PORT_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;

                        r = add_port_lookup_instructions(p, u->port_allow_map_egress_fd, ETH_P_IPV6, is_ingress, PORT_ACCESS_ALLOWED);
                        if (r < 0)
                                return r;
                }

                if (u->port_deny_map_egress_fd >= 0 && !is_ingress) {
                        r = add_port_lookup_instructions(p, u->port_deny_map_egress_fd, ETH_P_IP, is_ingress, PORT_ACCESS_DENIED);
                        if (r < 0)
                                return r;

                        r = add_port_lookup_instructions(p, u->port_deny_map_egress_fd, ETH_P_IPV6, is_ingress, PORT_ACCESS_DENIED);
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

static int bpf_firewall_count_port_range_access_items(PortRangeAccessItem *list, size_t *n) {
        PortRangeAccessItem *a;

        assert(n);

        LIST_FOREACH(items, a, list)
                (*n)++;

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

static int bpf_firewall_add_port_range_access_items(
                PortRangeAccessItem *list,
                int map_fd,
                int verdict) {

        struct bpf_lpm_trie_key *key;
        uint64_t value = verdict;
        PortRangeAccessItem *a;
        int r;
        uint16_t port;
        uint8_t protocol;
        uint8_t padding = 0;

        if (map_fd < 0)
                return 0;

        /*
         * The protocol (one byte) is the MSB of the key. However, some kernel
         * versions require word access to be aligned, so we pad the protocol
         * to be 16 bits.
         *
         * We then add 16 to the prefix length, causing the prefix matching
         * always take the protocol into account regardless of the port prefix.
         * So, even if all ports are matching (port number and prefix are 0/0),
         * the protocol can't be ignored.
         */

        key = alloca0(offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint8_t) * 2 + sizeof(uint16_t));

        LIST_FOREACH(items, a, list) {
                port = htobe16(a->port);
                protocol = a->protocol;
                key->prefixlen = a->prefixlen + 16; /* 16 = padded protocol bits */
                memcpy(key->data, &padding, sizeof(uint8_t));
                memcpy(key->data + sizeof(uint8_t), &protocol, sizeof(uint8_t));
                memcpy(key->data + sizeof(uint8_t) * 2, &port, sizeof(uint16_t));

                r = bpf_map_update_element(map_fd, key, &value);
                if (r < 0)
                        return r;
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

static int bpf_firewall_prepare_address_maps(
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

                bpf_firewall_count_access_items(verdict == ADDRESS_ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny, &n_ipv4, &n_ipv6);
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

                r = bpf_firewall_add_access_items(verdict == ADDRESS_ACCESS_ALLOWED ? cc->ip_address_allow : cc->ip_address_deny,
                                                  ipv4_map_fd, ipv6_map_fd, verdict);
                if (r < 0)
                        return r;
        }

        *ret_ipv4_map_fd = ipv4_map_fd;
        *ret_ipv6_map_fd = ipv6_map_fd;

        ipv4_map_fd = ipv6_map_fd = -1;
        return 0;
}

static int bpf_firewall_prepare_port_maps(
                Unit *u,
                int verdict,
                int *ret_port_map_ingress_fd,
                int *ret_port_map_egress_fd) {

        size_t n_ingress_ports = 0, n_egress_ports = 0;
        Unit *p;
        int r;

        assert(ret_port_map_ingress_fd);
        assert(ret_port_map_egress_fd);

        for (p = u; p; p = UNIT_DEREF(p->slice)) {
                CGroupContext *cc;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                bpf_firewall_count_port_range_access_items(verdict == PORT_ACCESS_ALLOWED ? cc->port_ingress_allow : cc->port_ingress_deny, &n_ingress_ports);
                bpf_firewall_count_port_range_access_items(verdict == PORT_ACCESS_ALLOWED ? cc->port_egress_allow : cc->port_egress_deny, &n_egress_ports);
        }

        if (n_ingress_ports > 0) {
                r = bpf_map_new(BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint8_t) * 2 + sizeof(uint16_t),
                                sizeof(uint32_t),
                                n_ingress_ports,
                                BPF_F_NO_PREALLOC);
                if (r < 0)
                        return r;

                *ret_port_map_ingress_fd = r;
        }

        if (n_egress_ports > 0) {
                r = bpf_map_new(BPF_MAP_TYPE_LPM_TRIE,
                                offsetof(struct bpf_lpm_trie_key, data) + sizeof(uint8_t) * 2 + sizeof(uint16_t),
                                sizeof(uint32_t),
                                n_egress_ports,
                                BPF_F_NO_PREALLOC);
                if (r < 0)
                        return r;

                *ret_port_map_egress_fd = r;
        }

        for (p = u; p; p = UNIT_DEREF(p->slice)) {
                CGroupContext *cc;

                cc = unit_get_cgroup_context(p);
                if (!cc)
                        continue;

                if (verdict == PORT_ACCESS_ALLOWED) {
                        r = bpf_firewall_add_port_range_access_items(cc->port_ingress_allow, *ret_port_map_ingress_fd, verdict);
                        if (r < 0)
                                return r;

                        r = bpf_firewall_add_port_range_access_items(cc->port_egress_allow, *ret_port_map_egress_fd, verdict);
                        if (r < 0)
                                return r;
                } else {
                        r = bpf_firewall_add_port_range_access_items(cc->port_ingress_deny, *ret_port_map_ingress_fd, verdict);
                        if (r < 0)
                                return r;

                         r = bpf_firewall_add_port_range_access_items(cc->port_egress_deny, *ret_port_map_egress_fd, verdict);
                         if (r < 0)
                                return r;
                }
        }

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

        u->port_allow_map_ingress_fd = safe_close(u->port_allow_map_ingress_fd);
        u->port_allow_map_egress_fd = safe_close(u->port_allow_map_egress_fd);
        u->port_deny_map_ingress_fd = safe_close(u->port_deny_map_ingress_fd);
        u->port_deny_map_egress_fd = safe_close(u->port_deny_map_egress_fd);

        cc = unit_get_cgroup_context(u);
        if (!cc)
                return -EINVAL;

        r = bpf_firewall_prepare_address_maps(u, ADDRESS_ACCESS_ALLOWED, &u->ipv4_allow_map_fd, &u->ipv6_allow_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF allow maps failed: %m");

        r = bpf_firewall_prepare_address_maps(u, ADDRESS_ACCESS_DENIED, &u->ipv4_deny_map_fd, &u->ipv6_deny_map_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF deny maps failed: %m");

        r = bpf_firewall_prepare_port_maps(u, PORT_ACCESS_ALLOWED, &u->port_allow_map_ingress_fd, &u->port_allow_map_egress_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF allow port map failed: %m");

        r = bpf_firewall_prepare_port_maps(u, PORT_ACCESS_DENIED, &u->port_deny_map_ingress_fd, &u->port_deny_map_egress_fd);
        if (r < 0)
                return log_error_errno(r, "Preparation of eBPF deny port map failed: %m");

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
