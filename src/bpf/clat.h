/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Configuration shared between BPF program and userspace.
 * This struct lives in the BPF program's BSS section and is updated
 * by userspace before the program starts processing packets.
 *
 * Uses raw byte arrays to avoid header conflicts between BPF context
 * (vmlinux.h) and userspace context (netinet/in.h). */
struct clat_config {
        unsigned char local_v6[16];   /* CLAT IPv6 source address */
        unsigned char pref64[16];     /* NAT64 PREF64 prefix */
        unsigned char local_v4[4];    /* CLAT IPv4 address (192.0.0.1) */
        unsigned int  pref64_len;     /* PREF64 prefix length (32/40/48/56/64/96) */
};
