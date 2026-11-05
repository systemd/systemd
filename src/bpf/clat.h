/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Configuration of the BPF program, which userspace fills in through the skeleton's BSS data before the
 * program is attached.
 *
 * The variable in the BPF program is declared with an anonymous struct built from these fields, so that
 * the generated skeleton carries the full definition and does not depend on this header. The named
 * struct is only used by the BPF program to get a non-volatile view of the variable.
 *
 * Raw byte arrays are used to avoid header conflicts between the BPF context (vmlinux.h) and the
 * userspace context (netinet/in.h). */
#define CLAT_CONFIG_FIELDS                                                                      \
        unsigned char local_v6[16];   /* CLAT IPv6 source address */                            \
        unsigned char pref64[16];     /* NAT64 PREF64 prefix */                                 \
        unsigned char local_v4[4];    /* CLAT IPv4 address (192.0.0.1) */                       \
        unsigned int  pref64_len;     /* PREF64 prefix length (32/40/48/56/64/96) */

struct clat_config {
        CLAT_CONFIG_FIELDS
};
