/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/filter.h>
#include <netinet/if_ether.h>

#include "fd-util.h"
#include "lldp-network.h"
#include "missing_network.h"
#include "socket-util.h"

int lldp_network_bind_raw_socket(int ifindex) {
        static const struct sock_filter filter[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ethhdr, h_dest)),      /* A <- 4 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0180c200, 1, 0),                    /* A != 01:80:c2:00 */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ethhdr, h_dest) + 4),  /* A <- remaining 2 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0000, 3, 0),                        /* A != 00:00 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0003, 2, 0),                        /* A != 00:03 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x000e, 1, 0),                        /* A != 00:0e */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ethhdr, h_proto)),     /* A <- protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_LLDP, 1, 0),                /* A != ETHERTYPE_LLDP */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                    /* accept packet */
        };
        static const struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = (struct sock_filter*) filter,
        };
        struct packet_mreq mreq = {
                .mr_ifindex = ifindex,
                .mr_type = PACKET_MR_MULTICAST,
                .mr_alen = ETH_ALEN,
                .mr_address = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 }
        };
        union sockaddr_union saddrll = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_ifindex = ifindex,
        };
        _cleanup_close_ int fd = -1;

        assert(ifindex > 0);

        fd = socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,
                    htobe16(ETHERTYPE_LLDP));
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
                return -errno;

        /* customer bridge */
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                return -errno;

        /* non TPMR bridge */
        mreq.mr_address[ETH_ALEN - 1] = 0x03;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                return -errno;

        /* nearest bridge */
        mreq.mr_address[ETH_ALEN - 1] = 0x0E;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
                return -errno;

        if (bind(fd, &saddrll.sa, sizeof(saddrll.ll)) < 0)
                return -errno;

        return TAKE_FD(fd);
}
