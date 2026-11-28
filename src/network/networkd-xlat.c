/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/fib_rules.h>
#include <linux/filter.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-netlink.h"

#if ENABLE_CLAT_BPF
#include <linux/bpf.h>
#include <sys/syscall.h>

#include "bpf-util.h"
#include "clat-skel.h"
#endif

#include "alloc-util.h"
#include "clat.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "in-addr-util.h"
#include "iovec-util.h"
#include "log-ratelimit.h"
#include "networkd-address.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-ndisc.h"
#include "networkd-neighbor.h"
#include "networkd-network.h"
#include "networkd-queue.h"
#include "networkd-route.h"
#include "networkd-routing-policy-rule.h"
#include "networkd-xlat.h"
#include "networkd-xlat-packet.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "unaligned.h"

#define TUN_DEV "/dev/net/tun"

/* Metric of the IPv4 default route, high enough to not take precedence over native routes */
#define CLAT_ROUTE_METRIC UINT32_C(2048)

/* The TUN backend: mark of the packets we send, and priority of the policy rule that drops all others sent
 * from the CLAT address */
#define CLAT_FWMARK UINT32_C(0x434c4154) /* "CLAT" */
#define CLAT_RULE_PRIORITY UINT32_C(1000)

/* How often another CLAT address is tried after duplicate address detection failed (cf. RFC 7217) */
#define CLAT_DAD_RETRIES 3U

typedef enum ClatState {
        CLAT_PREPARING,         /* waiting for the CLAT IPv6 address (and the policy rule) */
        CLAT_CONFIGURING,       /* waiting for the IPv4 configuration */
        CLAT_RUNNING,
} ClatState;

struct Clat {
        ClatState state;
        bool use_bpf;
        XlatPacketParams params;

#if ENABLE_CLAT_BPF
        struct clat_bpf *obj;
        int ingress_fd;
        int egress_fd;
#endif

        /* TUN backend */
        int tun_ifindex;
        int tun_fd;
        int send_fd;
        int recv_fd;
        sd_event_source *tun_event_source;
        sd_event_source *recv_event_source;
        uint8_t *input;
        uint8_t *output;
};

/* The link layer address of the IPv4 gateway in BPF mode. It never appears on the wire: the BPF program
 * replaces the Ethernet addresses of translated packets, and drops other packets sent to it. It is locally
 * administered, so that a leaked packet is ignored. */
static const struct ether_addr clat_gateway_mac = { .ether_addr_octet = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } };

static struct in_addr clat_ipv4_address(void) {
        return (struct in_addr) { .s_addr = htobe32(CLAT_IPV4_ADDRESS) };
}

static struct in_addr clat_ipv4_gateway(void) {
        return (struct in_addr) { .s_addr = htobe32(CLAT_IPV4_GATEWAY) };
}

static bool link_xlat_enabled(Link *link) {
        assert(link);

        return link->network && link->network->clat;
}

/* The MTU of IPv4 packets, so that they, and fragments of them, fit into the link MTU once translated */
static uint32_t clat_ipv4_mtu(Link *link) {
        assert(link);

        return CLAMP(link->mtu, CLAT_IPV6_MIN_MTU, (uint32_t) UINT16_MAX) - CLAT_MTU_OVERHEAD;
}

#if ENABLE_CLAT_BPF
static struct clat_bpf* clat_bpf_free(struct clat_bpf *obj) {
        clat_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct clat_bpf*, clat_bpf_free);
#endif

static Clat* clat_free(Clat *clat) {
        if (!clat)
                return NULL;

#if ENABLE_CLAT_BPF
        safe_close(clat->ingress_fd);
        safe_close(clat->egress_fd);
        clat_bpf_free(clat->obj);
#endif

        sd_event_source_disable_unref(clat->tun_event_source);
        sd_event_source_disable_unref(clat->recv_event_source);

        /* Closing the file descriptor removes the TUN device, along with its address and route */
        safe_close(clat->tun_fd);
        safe_close(clat->send_fd);
        safe_close(clat->recv_fd);

        free(clat->input);
        free(clat->output);

        return mfree(clat);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Clat*, clat_free);

static int clat_new(Clat **ret) {
        Clat *clat;

        assert(ret);

        clat = new(Clat, 1);
        if (!clat)
                return -ENOMEM;

        *clat = (Clat) {
#if ENABLE_CLAT_BPF
                .ingress_fd = -EBADF,
                .egress_fd = -EBADF,
#endif
                .tun_fd = -EBADF,
                .send_fd = -EBADF,
                .recv_fd = -EBADF,
        };

        *ret = clat;
        return 0;
}

bool xlat_manager_owns_ifindex(Manager *manager, int ifindex) {
        Link *link;

        assert(manager);

        if (ifindex <= 0)
                return false;

        HASHMAP_FOREACH(link, manager->links_by_index)
                if (link->clat && link->clat->tun_ifindex == ifindex)
                        return true;

        return false;
}

/* ---- Selection of the CLAT IPv6 address ---- */

/* RFC 6877 section 6.3 asks for an IPv6 address dedicated to the translated traffic. Otherwise replies to
 * native IPv6 connections of the host to NAT64 addresses (e.g. synthesized by DNS64) are mistaken for CLAT
 * traffic. It is derived from an address of the host, so that it is within an on-link prefix: of the /64
 * around it, or of its own prefix if that is smaller. For a /128 address (e.g. from DHCPv6) the on-link
 * prefix is taken from the routes of the link. */
static int clat_prefix_length(Link *link, const Address *address) {
        Route *route;
        int best = -ENOENT;

        assert(link);
        assert(link->manager);
        assert(address);

        if (address->prefixlen <= 64)
                return 64;
        if (address->prefixlen <= 112)
                return address->prefixlen;

        SET_FOREACH(route, link->manager->routes) {
                if (route->family != AF_INET6 ||
                    route->nexthop.ifindex != link->ifindex ||
                    !route_exists(route))
                        continue;
                if (route->table != RT_TABLE_MAIN || route->type != RTN_UNICAST ||
                    in_addr_is_set(route->nexthop.family, &route->nexthop.gw))
                        continue;
                if (route->dst_prefixlen == 0 || route->dst_prefixlen > 112)
                        continue;
                if (in6_addr_prefix_covers(&route->dst.in6, route->dst_prefixlen, &address->in_addr.in6) <= 0)
                        continue;

                best = MAX(best, MAX((int) route->dst_prefixlen, 64));
        }

        return best;
}

/* The host bits are derived from the machine ID, the interface name and the prefix, so that the address is
 * stable (cf. RFC 7217) and does not clash with SLAAC addresses */
static int clat_derive_address(Link *link, const Address *host, struct in6_addr *ret) {
        static const sd_id128_t app_id =
                SD_ID128_MAKE(5e,2c,9a,31,b0,47,4c,d6,a1,8f,3d,72,e4,0b,96,5a);
        struct in6_addr prefix;
        sd_id128_t key;
        uint64_t mask;
        int r, len;

        assert(link);
        assert(host);
        assert(ret);

        len = clat_prefix_length(link, host);
        if (len < 0)
                return len;

        r = sd_id128_get_machine_app_specific(app_id, &key);
        if (r < 0)
                return r;

        prefix = host->in_addr.in6;
        r = in6_addr_mask(&prefix, len);
        if (r < 0)
                return r;

        mask = len == 64 ? UINT64_MAX : (UINT64_C(1) << (128 - len)) - 1;

        for (uint8_t attempt = 0; attempt < UINT8_MAX; attempt++) {
                struct siphash state;
                uint64_t iid;

                siphash24_init(&state, key.bytes);
                siphash24_compress_string(link->ifname, &state);
                siphash24_compress_typesafe(prefix, &state);
                siphash24_compress_typesafe(len, &state);
                siphash24_compress_typesafe(link->clat_dad_failures, &state);
                siphash24_compress_typesafe(attempt, &state);
                iid = siphash24_finalize(&state) & mask;

                /* Skip the subnet-router anycast address and the reserved anycast addresses (RFC 2526) */
                if (iid == 0 || iid >= mask - 127)
                        continue;

                *ret = prefix;
                unaligned_write_be64(ret->s6_addr + 8, unaligned_read_be64(prefix.s6_addr + 8) | iid);

                if (in6_addr_equal(ret, &host->in_addr.in6))
                        continue;

                return 0;
        }

        return -EADDRNOTAVAIL;
}

/* An address of the host that a CLAT address can be derived from */
static bool clat_address_is_candidate(const Address *address) {
        assert(address);

        return address->family == AF_INET6 &&
                address->source != NETWORK_CONFIG_SOURCE_CLAT &&
                !in6_addr_is_link_local(&address->in_addr.in6) &&
                !in6_addr_is_multicast(&address->in_addr.in6) &&
                !FLAGS_SET(address->flags, IFA_F_DADFAILED);
}

static bool in6_addr_is_unique_local(const struct in6_addr *a) {
        return (a->s6_addr[0] & 0xfe) == 0xfc;
}

static int clat_select_address(Link *link, struct in6_addr *ret) {
        const Address *a, *best = NULL;
        struct in6_addr derived, best_derived = {};
        int r, error = -ENOENT;

        assert(link);
        assert(ret);

        SET_FOREACH(a, link->addresses) {
                if (!clat_address_is_candidate(a) || !address_is_ready(a))
                        continue;

                /* Deprecated addresses are not for new uses */
                if (FLAGS_SET(a->flags, IFA_F_DEPRECATED))
                        continue;

                r = clat_derive_address(link, a, &derived);
                if (r < 0) {
                        error = r == -ENOENT ? -EADDRNOTAVAIL : r;
                        continue;
                }

                /* Prefer global over unique local addresses, and make the choice independent of the order
                 * of the set */
                if (best) {
                        int c = CMP(in6_addr_is_unique_local(&a->in_addr.in6),
                                    in6_addr_is_unique_local(&best->in_addr.in6));
                        if (c == 0)
                                c = memcmp(&a->in_addr.in6, &best->in_addr.in6, sizeof(struct in6_addr));
                        if (c > 0)
                                continue;
                }

                best = a;
                best_derived = derived;
        }

        if (!best)
                return error;

        *ret = best_derived;
        return 0;
}

/* Whether the host still has an address that the CLAT address in use belongs to. Any address within the same
 * prefix gives the same CLAT address, so e.g. rotating privacy addresses do not interrupt CLAT. */
static bool clat_address_is_still_valid(Link *link) {
        const Address *a;

        assert(link);
        assert(link->clat);

        SET_FOREACH(a, link->addresses) {
                struct in6_addr derived;

                if (!clat_address_is_candidate(a) || !address_exists(a))
                        continue;
                if (clat_derive_address(link, a, &derived) < 0)
                        continue;
                if (in6_addr_equal(&derived, &link->clat->params.address))
                        return true;
        }

        return false;
}

/* ---- The in-kernel (eBPF) translation ---- */

#if ENABLE_CLAT_BPF
/* Attach a BPF program to a TC hook using the raw BPF syscall. This avoids requiring
 * bpf_program__attach_tcx() from libbpf >= 1.3. */
static int clat_bpf_attach_tcx(int prog_fd, int ifindex, enum bpf_attach_type attach_type) {
        union bpf_attr attr = {
                .link_create = {
                        .prog_fd        = (__u32) prog_fd,
                        .target_ifindex = (__u32) ifindex,
                        .attach_type    = attach_type,
                },
        };

        return RET_NERRNO((int) syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr)));
}

static int clat_setup_bpf(Link *link, Clat *clat) {
        _cleanup_(clat_bpf_freep) struct clat_bpf *obj = NULL;
        _cleanup_close_ int egress_fd = -EBADF, ingress_fd = -EBADF;
        static const struct in6_addr well_known = { .s6_addr = { 0x00, 0x64, 0xff, 0x9b } };
        struct in_addr v4 = clat_ipv4_address();
        int r;

        assert(link);
        assert(clat);

        if (secure_getenv_bool("SYSTEMD_NETWORK_CLAT_BPF") == 0)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "CLAT: BPF translation is disabled by $SYSTEMD_NETWORK_CLAT_BPF.");

        /* The programs parse an Ethernet header; raw IP links (WireGuard, PPP, WWAN, …) have none. */
        if (link->iftype != ARPHRD_ETHER || link->hw_addr.length != ETH_ALEN)
                return log_link_debug_errno(link, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                            "CLAT: BPF translation needs an Ethernet link.");

        r = dlopen_bpf(LOG_DEBUG);
        if (r < 0)
                return log_link_debug_errno(link, r, "CLAT: libbpf is not available: %m");

        obj = clat_bpf__open();
        if (!obj)
                return log_link_debug_errno(link, errno_or_else(EOPNOTSUPP),
                                            "CLAT: failed to open the BPF programs: %m");

        /* Configure the BPF program through the BSS section before loading it */
        memcpy(obj->bss->clat_cfg.local_v6, &clat->params.address, 16);
        memcpy(obj->bss->clat_cfg.pref64, &clat->params.pref64, 16);
        memset(obj->bss->clat_cfg.pref64_mask, 0xff, clat->params.pref64_len / 8);
        memcpy(obj->bss->clat_cfg.local_v4, &v4, 4);
        memcpy(obj->bss->clat_cfg.gateway_mac, &clat_gateway_mac, ETH_ALEN);
        obj->bss->clat_cfg.drop_udp_zero_checksum = clat->params.drop_udp_zero_checksum;
        obj->bss->clat_cfg.pref64_is_well_known =
                clat->params.pref64_len == 96 && in6_addr_equal(&clat->params.pref64, &well_known);
        obj->bss->clat_cfg.pref64_len = clat->params.pref64_len;
        obj->bss->clat_cfg.mtu = clat->params.mtu;
        obj->bss->clat_cfg.ipv4_id_seed = random_u32();

        r = clat_bpf__load(obj);
        if (r < 0)
                return log_link_debug_errno(link, r, "CLAT: failed to load the BPF programs: %m");

        egress_fd = clat_bpf_attach_tcx(sym_bpf_program__fd(obj->progs.clat_egress),
                                        link->ifindex, BPF_TCX_EGRESS);
        if (egress_fd < 0)
                return log_link_debug_errno(link, egress_fd, "CLAT: failed to attach the BPF egress program: %m");

        ingress_fd = clat_bpf_attach_tcx(sym_bpf_program__fd(obj->progs.clat_ingress),
                                         link->ifindex, BPF_TCX_INGRESS);
        if (ingress_fd < 0)
                return log_link_debug_errno(link, ingress_fd, "CLAT: failed to attach the BPF ingress program: %m");

        clat->obj = TAKE_PTR(obj);
        clat->egress_fd = TAKE_FD(egress_fd);
        clat->ingress_fd = TAKE_FD(ingress_fd);
        clat->use_bpf = true;

        return 0;
}
#endif

/* ---- The userspace (TUN device) translation ---- */

static void clat_tun_failed(Link *link, int error, const char *what) {
        /* E.g. the TUN device was removed from outside. The file descriptor then keeps reporting errors,
         * so stop CLAT instead of spinning on it. */
        log_link_warning_errno(link, error, "CLAT: failed to read from %s, stopping: %m", what);
        xlat_stop(link);
}

static void clat_log_zero_checksum_drop(Link *link, const uint8_t *packet, size_t size) {
        struct in_addr src, dst;
        size_t hlen;

        assert(link);
        assert(packet);

        /* RFC 7915 section 4.5 asks to report at least the addresses and ports. The translator verified
         * the lengths already. */
        hlen = (size_t) (packet[0] & 0x0f) * 4;
        if (size < hlen + sizeof(struct udphdr))
                return;

        memcpy(&src, packet + offsetof(struct iphdr, saddr), sizeof(src));
        memcpy(&dst, packet + offsetof(struct iphdr, daddr), sizeof(dst));

        log_ratelimit_info(((const RateLimit) { .interval = USEC_PER_MINUTE, .burst = 5 }),
                           "%s: CLAT: dropping UDP datagram without checksum from %s:%u to %s:%u.",
                           link->ifname,
                           IN4_ADDR_TO_STRING(&src), unaligned_read_be16(packet + hlen),
                           IN4_ADDR_TO_STRING(&dst), unaligned_read_be16(packet + hlen + 2));
}

static int clat_tun_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        Clat *clat = ASSERT_PTR(link->clat);
        struct sockaddr_in6 sa = { .sin6_family = AF_INET6 };
        size_t size;
        ssize_t n;
        int r;

        n = read(fd, clat->input, XLAT_PACKET_SIZE_MAX);
        if (n < 0) {
                if (!ERRNO_IS_TRANSIENT(errno))
                        clat_tun_failed(link, errno, "the TUN device");
                return 0;
        }

        r = xlat_packet_4to6(&clat->params, clat->input, n,
                             clat->output, XLAT_PACKET_SIZE_MAX, &size, &sa.sin6_addr);
        if (r == -ENODATA)
                clat_log_zero_checksum_drop(link, clat->input, n);
        if (r < 0) {
                log_link_debug_errno(link, r, "CLAT: not translating IPv4 packet: %m");
                return 0;
        }

        if (sendto(clat->send_fd, clat->output, size, 0, (struct sockaddr*) &sa, sizeof(sa)) < 0)
                log_link_debug_errno(link, errno, "CLAT: failed to send translated packet, ignoring: %m");

        return 0;
}

static int clat_recv_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        Clat *clat = ASSERT_PTR(link->clat);
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct tpacket_auxdata))) control;
        struct iovec iov = IOVEC_MAKE(clat->input, XLAT_PACKET_SIZE_MAX);
        struct msghdr mh = {
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        bool partial = false;
        size_t size;
        ssize_t n;
        int r;

        /* The socket filter only lets IPv6 packets to the CLAT address through. */

        n = recvmsg_safe(fd, &mh, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(n) || IN_SET(n, -EXFULL, -ECHRNG))
                return 0;
        if (n == -ENETDOWN) /* reported once when the interface goes down */
                return 0;
        if (n < 0) {
                clat_tun_failed(link, (int) n, "the packet socket");
                return 0;
        }

        /* Locally generated packets, e.g. from virtual machines or containers, may carry a checksum that
         * only covers the pseudo-header yet */
        struct tpacket_auxdata *aux = CMSG_FIND_DATA(&mh, SOL_PACKET, PACKET_AUXDATA, struct tpacket_auxdata);
        if (aux)
                partial = FLAGS_SET(aux->tp_status, TP_STATUS_CSUMNOTREADY);

        r = xlat_packet_6to4(&clat->params, clat->input, n, partial,
                             clat->output, XLAT_PACKET_SIZE_MAX, &size);
        if (r < 0) {
                log_link_debug_errno(link, r, "CLAT: not translating IPv6 packet: %m");
                return 0;
        }

        if (write(clat->tun_fd, clat->output, size) < 0)
                log_link_debug_errno(link, errno, "CLAT: failed to write translated packet, ignoring: %m");

        return 0;
}

static int clat_create_tun(Link *link, Clat *clat) {
        _cleanup_close_ int fd = -EBADF;
        struct ifreq ifr = {};
        char fallback_name[IFNAMSIZ];
        const char *name;
        int r;

        assert(link);
        assert(link->ifname);
        assert(clat);

        name = strjoina("cl-", link->ifname);
        if (strlen(name) >= IFNAMSIZ) {
                /* E.g. predictable names of USB NICs are 15 characters long. Name the device after the
                 * ifindex instead. */
                xsprintf(fallback_name, "clat%i", link->ifindex);
                name = fallback_name;
        }

        fd = xopenat(AT_FDCWD, TUN_DEV, O_RDWR|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return log_link_warning_errno(link, fd, "CLAT: failed to open " TUN_DEV ": %m");

        /* IFF_TUN_EXCL: never attach to an already existing (persistent) device of that name, which may
         * be owned by somebody else and would then carry our IPv4 default route. */
        ifr.ifr_flags = (short) (IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
        strncpy_exact(ifr.ifr_name, name, sizeof(ifr.ifr_name));

        if (ioctl(fd, TUNSETIFF, &ifr) < 0)
                return log_link_warning_errno(link, errno, "CLAT: failed to create TUN device '%s': %m", name);

        /* Without TUNSETPERSIST the device is removed when the file descriptor is closed */

        unsigned ifindex = if_nametoindex(ifr.ifr_name);
        if (ifindex == 0)
                return log_link_warning_errno(link, SYNTHETIC_ERRNO(ENODEV),
                                              "CLAT: failed to get the index of TUN device '%s'.", ifr.ifr_name);

        r = sd_event_add_io(link->manager->event, &clat->tun_event_source, fd, EPOLLIN, clat_tun_handler, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to add TUN event source: %m");

        (void) sd_event_source_set_description(clat->tun_event_source, "network-clat-tun");

        clat->tun_fd = TAKE_FD(fd);
        clat->tun_ifindex = (int) ifindex;

        log_link_debug(link, "CLAT: created TUN device '%s' (ifindex=%u).", ifr.ifr_name, ifindex);
        return 0;
}

static int clat_create_send_socket(Link *link, Clat *clat) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(link);
        assert(clat);

        fd = socket(AF_INET6, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_RAW);
        if (fd < 0)
                return log_link_warning_errno(link, errno, "CLAT: failed to create raw IPv6 socket: %m");

        r = setsockopt_int(fd, IPPROTO_IPV6, IPV6_HDRINCL, 1);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to set IPV6_HDRINCL: %m");

        /* Exempt the translated packets from the rule that drops what else is sent from the CLAT address */
        r = setsockopt_int(fd, SOL_SOCKET, SO_MARK, (int) CLAT_FWMARK);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to set SO_MARK: %m");

        r = socket_bind_to_ifindex(fd, link->ifindex);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to bind raw socket to the interface: %m");

        clat->send_fd = TAKE_FD(fd);
        return 0;
}

/* Attach a classic BPF filter to the packet socket, which receives IPv6 packets starting at the IPv6 header.
 * It accepts packets to the CLAT address that are ICMPv6 errors from anywhere, or TCP, UDP, ICMPv6 and
 * fragments from the NAT64 prefix. */
static int clat_attach_socket_filter(Link *link, Clat *clat, int fd) {
        enum { JUMP_PREFIX = 0xfd, JUMP_ACCEPT = 0xfe, JUMP_REJECT = 0xff };
        /* The longest program, for a /96 prefix: destination (4 * 2), next header (7), prefix (3 * 2), and
         * accept and reject (2) */
        struct sock_filter insns[23];
        size_t i = 0;

        assert(link);
        assert(clat);

        /* The destination address (at offset 24) */
        for (size_t w = 0; w < 4; w++) {
                insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 24 + w * 4);
                insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                           unaligned_read_be32(clat->params.address.s6_addr + w * 4),
                                                           0, JUMP_REJECT);
        }

        /* The next header (at offset 6), and for ICMPv6 the type (at offset 40) */
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 2);
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 40);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 128, JUMP_PREFIX, JUMP_ACCEPT);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, JUMP_PREFIX, 0);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, JUMP_PREFIX, 0);
        insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_FRAGMENT,
                                                   JUMP_PREFIX, JUMP_REJECT);

        /* The source address (at offset 8) has to be within the prefix */
        size_t prefix_start = i;
        for (size_t offset = 0; offset < clat->params.pref64_len / 8u; offset += 4) {
                size_t len = MIN(clat->params.pref64_len / 8u - offset, 4u);
                uint32_t mask = len == 4 ? UINT32_MAX : ~(UINT32_MAX >> (len * 8)),
                         word = unaligned_read_be32(clat->params.pref64.s6_addr + offset) & mask;

                insns[i++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8 + offset);
                if (len < 4)
                        insns[i++] = (struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask);
                insns[i++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, word, 0, JUMP_REJECT);
        }

        size_t accept = i;
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, UINT32_MAX);
        size_t reject = i;
        insns[i++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, 0);

        assert(i <= ELEMENTSOF(insns));

        /* Resolve the symbolic jump targets, which are relative to the next instruction */
        for (size_t j = 0; j < accept; j++) {
                if (BPF_CLASS(insns[j].code) != BPF_JMP)
                        continue;

                uint8_t *targets[] = { &insns[j].jt, &insns[j].jf };
                FOREACH_ELEMENT(t, targets) {
                        if (**t == JUMP_ACCEPT)
                                **t = (uint8_t) (accept - j - 1);
                        else if (**t == JUMP_REJECT)
                                **t = (uint8_t) (reject - j - 1);
                        else if (**t == JUMP_PREFIX)
                                **t = (uint8_t) (prefix_start - j - 1);
                }
        }

        struct sock_fprog prog = {
                .len = (unsigned short) i,
                .filter = insns,
        };

        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
                return log_link_warning_errno(link, errno, "CLAT: failed to attach filter to packet socket: %m");

        return 0;
}

static int clat_create_recv_socket(Link *link, Clat *clat) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(link);
        assert(clat);

        /* Create the socket with protocol 0, so it is not hooked into the packet flow of all interfaces
         * yet, attach the filter, and only then bind it to the interface and ETH_P_IPV6. Otherwise
         * unfiltered IPv6 packets could queue up between socket() and the filter. */
        fd = socket(AF_PACKET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_link_warning_errno(link, errno, "CLAT: failed to create packet socket: %m");

        r = clat_attach_socket_filter(link, clat, fd);
        if (r < 0)
                return r;

        r = setsockopt_int(fd, SOL_PACKET, PACKET_AUXDATA, 1);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to enable PACKET_AUXDATA: %m");

        struct sockaddr_ll sll = {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IPV6),
                .sll_ifindex = link->ifindex,
        };

        if (bind(fd, (struct sockaddr*) &sll, sizeof(sll)) < 0)
                return log_link_warning_errno(link, errno, "CLAT: failed to bind packet socket to the interface: %m");

        r = sd_event_add_io(link->manager->event, &clat->recv_event_source, fd, EPOLLIN, clat_recv_handler, link);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to add packet socket event source: %m");

        (void) sd_event_source_set_description(clat->recv_event_source, "network-clat-recv");

        clat->recv_fd = TAKE_FD(fd);
        return 0;
}

static int clat_setup_tun(Link *link, Clat *clat) {
        int r;

        assert(link);
        assert(clat);

        clat->input = new(uint8_t, XLAT_PACKET_SIZE_MAX);
        clat->output = new(uint8_t, XLAT_PACKET_SIZE_MAX);
        if (!clat->input || !clat->output)
                return log_oom();

        r = clat_create_tun(link, clat);
        if (r < 0)
                return r;

        r = clat_create_send_socket(link, clat);
        if (r < 0)
                return r;

        return clat_create_recv_socket(link, clat);
}

/* Configure the TUN device. It is ours alone, and networkd leaves it unmanaged, hence this is not done with
 * Address and Route objects of a .network file. */
static int clat_configure_tun(Link *link, Clat *clat) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *up = NULL, *addr = NULL, *route = NULL;
        struct in_addr a = clat_ipv4_address();
        uint32_t mtu = clat_ipv4_mtu(link);
        sd_netlink *rtnl;
        int r;

        assert(link);
        assert(link->manager);
        assert(clat);

        rtnl = ASSERT_PTR(link->manager->rtnl);

        r = sd_rtnl_message_new_link(rtnl, &up, RTM_SETLINK, clat->tun_ifindex);
        if (r < 0)
                return r;
        r = sd_rtnl_message_link_set_flags(up, IFF_UP, IFF_UP);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_u32(up, IFLA_MTU, mtu);
        if (r < 0)
                return r;
        r = sd_netlink_call(rtnl, up, /* timeout= */ 0, /* ret= */ NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to bring up the TUN device: %m");

        r = sd_rtnl_message_new_addr_update(rtnl, &addr, clat->tun_ifindex, AF_INET);
        if (r < 0)
                return r;
        r = sd_rtnl_message_addr_set_prefixlen(addr, 32);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_in_addr(addr, IFA_LOCAL, &a);
        if (r < 0)
                return r;
        r = sd_netlink_call(rtnl, addr, /* timeout= */ 0, /* ret= */ NULL);
        if (r < 0)
                return log_link_warning_errno(link, r, "CLAT: failed to add the IPv4 address to the TUN device: %m");

        r = sd_rtnl_message_new_route(rtnl, &route, RTM_NEWROUTE, AF_INET, RTPROT_STATIC);
        if (r < 0)
                return r;
        r = sd_rtnl_message_route_set_type(route, RTN_UNICAST);
        if (r < 0)
                return r;
        r = sd_rtnl_message_route_set_scope(route, RT_SCOPE_LINK);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_u32(route, RTA_OIF, clat->tun_ifindex);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_u32(route, RTA_PRIORITY, CLAT_ROUTE_METRIC);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_in_addr(route, RTA_PREFSRC, &a);
        if (r < 0)
                return r;
        r = sd_netlink_message_open_container(route, RTA_METRICS);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_u32(route, RTAX_MTU, mtu);
        if (r < 0)
                return r;
        r = sd_netlink_message_append_u32(route, RTAX_ADVMSS, mtu - 40);
        if (r < 0)
                return r;
        r = sd_netlink_message_close_container(route);
        if (r < 0)
                return r;
        r = sd_netlink_call(rtnl, route, /* timeout= */ 0, /* ret= */ NULL);
        if (r < 0)
                return log_link_warning_errno(link, r,
                                              "CLAT: failed to add the IPv4 default route to the TUN device: %m");

        return 0;
}

/* ---- The configuration of the interface, through the request queue ---- */

static void clat_try_configure(Link *link);

static void clat_enter_running(Link *link) {
        assert(link);
        assert(link->clat);

        link->clat->state = CLAT_RUNNING;
        log_link_info(link, "CLAT: started using %s translation.",
                      link->clat->use_bpf ? "BPF TC" : "TUN device");
}

static void clat_check_configured(Link *link) {
        assert(link);

        if (link->clat && link->clat->state == CLAT_CONFIGURING && link->clat_messages == 0)
                clat_enter_running(link);
}

static int clat_address_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Address *address) {
        int r;

        assert(link);

        r = address_configure_handler_internal(m, link, address);
        if (r <= 0)
                return r;

        clat_try_configure(link);
        clat_check_configured(link);
        return 1;
}

static int clat_route_handler(sd_netlink *rtnl, sd_netlink_message *m, Request *req, Link *link, Route *route) {
        int r;

        r = route_configure_handler_internal(m, req, route);
        if (r <= 0)
                return r;

        clat_check_configured(link);
        return 1;
}

static int clat_neighbor_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                Neighbor *neighbor) {

        int r;

        assert(m);
        assert(link);

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_warning_errno(link, m, r, "CLAT: could not set neighbor");
                link_enter_failed(link);
                return 1;
        }

        clat_check_configured(link);
        return 1;
}

static int clat_rule_handler(
                sd_netlink *rtnl,
                sd_netlink_message *m,
                Request *req,
                Link *link,
                RoutingPolicyRule *rule) {

        int r;

        assert(m);
        assert(link);
        assert(rule);

        r = routing_policy_rule_configure_handler_internal(m, link, rule);
        if (r <= 0)
                return r;

        clat_try_configure(link);
        return 1;
}

static int clat_new_ipv6_address(const struct in6_addr *a, Address **ret) {
        _cleanup_(address_unrefp) Address *address = NULL;
        int r;

        assert(a);
        assert(ret);

        r = address_new(&address);
        if (r < 0)
                return r;

        address->source = NETWORK_CONFIG_SOURCE_CLAT;
        address->family = AF_INET6;
        address->in_addr.in6 = *a;
        address->prefixlen = 128;
        /* Deprecated, so that applications of the host never select it as a source address. The router
         * resolves it with neighbor discovery, and duplicate address detection is performed, as for any
         * other address (RFC 6877 section 6.3). */
        address->lifetime_preferred_usec = 0;

        *ret = TAKE_PTR(address);
        return 0;
}

static int clat_request_ipv6(Link *link) {
        _cleanup_(address_unrefp) Address *address = NULL;
        int r;

        assert(link);
        assert(link->clat);

        r = clat_new_ipv6_address(&link->clat->params.address, &address);
        if (r < 0)
                return r;

        r = link_request_address(link, address, &link->clat_messages, clat_address_handler, /* ret= */ NULL);
        if (r < 0)
                return r;

        if (link->clat->use_bpf)
                return 0;

        /* With the TUN backend the IPv6 stack sees the return traffic too, as it is addressed to a local
         * address, and would answer it with resets and ICMP errors. Hence drop what the host itself sends
         * from the CLAT address. The packets we send are marked, and do not match the rule. */
        _cleanup_(routing_policy_rule_unrefp) RoutingPolicyRule *rule = NULL;

        r = routing_policy_rule_new(&rule);
        if (r < 0)
                return r;

        rule->source = NETWORK_CONFIG_SOURCE_CLAT;
        rule->family = AF_INET6;
        rule->from.address.in6 = link->clat->params.address;
        rule->from.prefixlen = 128;
        rule->fwmark = 0;
        rule->fwmask = UINT32_MAX;
        rule->priority = CLAT_RULE_PRIORITY;
        rule->priority_set = true;
        rule->action = FR_ACT_BLACKHOLE;
        rule->table = RT_TABLE_UNSPEC;
        rule->protocol = RTPROT_STATIC;

        return link_request_routing_policy_rule(link, rule, AF_INET6, &link->clat_messages, clat_rule_handler);
}

/* BPF backend: the IPv4 address, and the default route through an on-link gateway with a permanent
 * neighbor entry, so that the kernel never tries to resolve it (a NAT64 router would not answer ARP) */
static int clat_request_ipv4(Link *link) {
        _cleanup_(address_unrefp) Address *address = NULL;
        _cleanup_(neighbor_unrefp) Neighbor *neighbor = NULL;
        _cleanup_(route_unrefp) Route *route = NULL;
        struct in_addr a = clat_ipv4_address(), gw = clat_ipv4_gateway();
        uint32_t mtu = clat_ipv4_mtu(link);
        int r;

        assert(link);

        r = address_new(&address);
        if (r < 0)
                return r;

        address->source = NETWORK_CONFIG_SOURCE_CLAT;
        address->family = AF_INET;
        address->in_addr.in = a;
        address->prefixlen = 32;
        address->duplicate_address_detection = ADDRESS_FAMILY_NO;

        r = link_request_address(link, address, &link->clat_messages, clat_address_handler, /* ret= */ NULL);
        if (r < 0)
                return r;

        r = neighbor_new(&neighbor);
        if (r < 0)
                return r;

        neighbor->source = NETWORK_CONFIG_SOURCE_CLAT;
        neighbor->dst_addr.family = AF_INET;
        neighbor->dst_addr.address.in = gw;
        neighbor->ll_addr.length = ETH_ALEN;
        neighbor->ll_addr.ether = clat_gateway_mac;

        r = link_request_neighbor(link, neighbor, &link->clat_messages, clat_neighbor_handler);
        if (r < 0)
                return r;

        r = route_new(&route);
        if (r < 0)
                return r;

        route->source = NETWORK_CONFIG_SOURCE_CLAT;
        route->family = AF_INET;
        route->protocol = RTPROT_STATIC;
        route->priority = CLAT_ROUTE_METRIC;
        route->priority_set = true;
        route->nexthop.family = AF_INET;
        route->nexthop.gw.in = gw;
        route->flags = RTNH_F_ONLINK;
        route->prefsrc.in = a;

        r = route_metric_set(&route->metric, RTAX_MTU, mtu);
        if (r < 0)
                return r;

        r = route_metric_set(&route->metric, RTAX_ADVMSS, mtu - 40);
        if (r < 0)
                return r;

        return link_request_route(link, route, &link->clat_messages, clat_route_handler);
}

/* The IPv4 side is configured once the IPv6 side is, so that the first packets can be answered */
static void clat_try_configure(Link *link) {
        Address *address;
        int r;

        assert(link);

        Clat *clat = link->clat;
        if (!clat || clat->state != CLAT_PREPARING || link->clat_messages > 0)
                return;

        if (link_get_ipv6_address(link, &clat->params.address, &address) < 0 || !address_is_ready(address))
                return;

        clat->state = CLAT_CONFIGURING;

        if (clat->use_bpf) {
                r = clat_request_ipv4(link);
                if (r < 0)
                        goto fail;

                clat_check_configured(link);
        } else {
                r = clat_configure_tun(link, clat);
                if (r < 0)
                        goto fail;

                clat_enter_running(link);
        }

        return;

fail:
        log_link_warning_errno(link, r, "CLAT: failed to configure IPv4, stopping: %m");
        xlat_stop(link);
}

/* Remove everything we requested, and what resulted from it */
static void clat_remove_configuration(Link *link, const struct in6_addr *clat_address) {
        RoutingPolicyRule *rule;
        Neighbor *neighbor;
        Address *address;
        Route *route;

        assert(link);
        assert(link->manager);
        assert(clat_address);

        (void) link_drop_requests(link, NETWORK_CONFIG_SOURCE_CLAT);

        SET_FOREACH(route, link->manager->routes) {
                if (route->source != NETWORK_CONFIG_SOURCE_CLAT ||
                    route->nexthop.ifindex != link->ifindex ||
                    !route_exists(route))
                        continue;

                (void) route_remove(route, link->manager);
        }

        SET_FOREACH(neighbor, link->neighbors)
                if (neighbor->source == NETWORK_CONFIG_SOURCE_CLAT && neighbor_exists(neighbor))
                        (void) neighbor_remove(neighbor, link);

        SET_FOREACH(address, link->addresses)
                if (address->source == NETWORK_CONFIG_SOURCE_CLAT && address_exists(address))
                        (void) address_remove(address, link);

        /* Rules are not bound to a link, find ours by its source address */
        SET_FOREACH(rule, link->manager->rules)
                if (rule->source == NETWORK_CONFIG_SOURCE_CLAT &&
                    rule->family == AF_INET6 &&
                    in6_addr_equal(&rule->from.address.in6, clat_address) &&
                    routing_policy_rule_exists(rule))
                        (void) routing_policy_rule_remove(rule, link->manager);
}

/* ---- Lifecycle ---- */

static bool route_is_clat(const Route *route) {
        assert(route);

        /* The second check covers the routes of a previous instance, and the removal notifications */
        return route->source == NETWORK_CONFIG_SOURCE_CLAT ||
                (route->family == AF_INET &&
                 route->priority == CLAT_ROUTE_METRIC &&
                 route->nexthop.gw.in.s_addr == htobe32(CLAT_IPV4_GATEWAY));
}

static bool route_is_ipv4_default(const Route *route) {
        assert(route);

        return route->family == AF_INET &&
                route->dst_prefixlen == 0 &&
                route->table == RT_TABLE_MAIN &&
                route->type == RTN_UNICAST;
}

/* Like link_has_default_gateway(), but also covers default routes without a gateway, e.g. on
 * point-to-point links, and ignores the route CLAT adds itself */
static bool clat_link_has_native_default_route(Link *link) {
        Route *route;

        assert(link);
        assert(link->manager);

        SET_FOREACH(route, link->manager->routes)
                if (route->nexthop.ifindex == link->ifindex &&
                    route_exists(route) &&
                    route_is_ipv4_default(route) &&
                    !route_is_clat(route))
                        return true;

        return false;
}

static bool clat_select_pref64(Link *link, struct in6_addr *ret, uint8_t *ret_len) {
        NDiscPREF64 *p, *best = NULL;

        assert(link);
        assert(link->network);
        assert(ret);
        assert(ret_len);

        /* A manually configured prefix takes precedence */
        if (link->network->clat_pref64_prefix_len > 0) {
                *ret = link->network->clat_pref64_prefix;
                *ret_len = link->network->clat_pref64_prefix_len;
                return true;
        }

        /* When multiple prefixes were discovered (e.g. from different routers), pick the numerically smallest
         * one, and for equal prefixes the shortest length, so that the choice does not depend on the order of
         * the set. Use Pref64Prefix= to select a prefix explicitly. */
        SET_FOREACH(p, link->ndisc_pref64) {
                if (best) {
                        int c = memcmp(&p->prefix, &best->prefix, sizeof(struct in6_addr));
                        if (c > 0 || (c == 0 && p->prefix_len > best->prefix_len))
                                continue;
                }

                best = p;
        }

        if (!best)
                return false;

        *ret = best->prefix;
        *ret_len = best->prefix_len;
        return true;
}

void xlat_start(Link *link) {
        _cleanup_(clat_freep) Clat *clat = NULL;
        int r;

        assert(link);
        assert(link->manager);

        if (link->clat || !link_xlat_enabled(link))
                return;

        /* Only once the link is configured, so that native IPv4 connectivity had a chance to show up */
        if (link->state != LINK_STATE_CONFIGURED ||
            link->manager->state != MANAGER_RUNNING ||
            !link_has_carrier(link))
                return;

        if (clat_link_has_native_default_route(link))
                return (void) log_link_debug(link, "CLAT: link has a native IPv4 default route, not starting.");

        r = clat_new(&clat);
        if (r < 0)
                return (void) log_oom();

        if (!clat_select_pref64(link, &clat->params.pref64, &clat->params.pref64_len))
                return;

        if (link->clat_dad_failures > CLAT_DAD_RETRIES)
                return;

        r = clat_select_address(link, &clat->params.address);
        if (r == -ENOENT)
                return (void) log_link_debug(link, "CLAT: no global IPv6 address available, deferring.");
        if (r == -EADDRNOTAVAIL)
                return (void) log_link_debug(link,
                                             "CLAT: no on-link IPv6 prefix to derive an address from, deferring.");
        if (r < 0)
                return (void) log_link_warning_errno(link, r, "CLAT: failed to derive an IPv6 address: %m");

        clat->params.mtu = CLAMP(link->mtu, CLAT_IPV6_MIN_MTU, (uint32_t) UINT16_MAX);
        clat->params.drop_udp_zero_checksum = link->network->clat_drop_udp_zero_checksum;
        clat->params.ipv4_id = (uint16_t) random_u32();

        log_link_info(link, "CLAT: starting with PREF64 %s/%u, address %s.",
                      IN6_ADDR_TO_STRING(&clat->params.pref64),
                      clat->params.pref64_len,
                      IN6_ADDR_TO_STRING(&clat->params.address));

#if ENABLE_CLAT_BPF
        /* Prefer the translation in the kernel */
        r = clat_setup_bpf(link, clat);
        if (r < 0)
                log_link_info_errno(link, r, "CLAT: BPF translation is not available, using a TUN device: %m");
#endif

        if (!clat->use_bpf) {
                r = clat_setup_tun(link, clat);
                if (r < 0)
                        return;
        }

        link->clat = TAKE_PTR(clat);

        r = clat_request_ipv6(link);
        if (r < 0) {
                log_link_warning_errno(link, r, "CLAT: failed to request the IPv6 configuration: %m");
                return xlat_stop(link);
        }

        clat_try_configure(link);
}

void xlat_stop(Link *link) {
        _cleanup_(clat_freep) Clat *clat = NULL;

        assert(link);

        /* Detach it from the link first, so that callbacks triggered below see CLAT as stopped */
        clat = TAKE_PTR(link->clat);
        if (!clat)
                return;

        /* When the interface is gone, its configuration is gone as well */
        if (link->manager && link->state != LINK_STATE_LINGER)
                clat_remove_configuration(link, &clat->params.address);

#if ENABLE_CLAT_BPF
        if (clat->obj && clat->obj->bss->clat_udp_zero_checksum_dropped > 0)
                log_link_info(link, "CLAT: dropped %" PRIu64 " UDP datagrams without checksum.",
                              (uint64_t) clat->obj->bss->clat_udp_zero_checksum_dropped);
#endif

        log_link_info(link, "CLAT: stopped.");
}

static void clat_restart(Link *link) {
        xlat_stop(link);
        xlat_start(link);
}

void xlat_address_changed(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (address->family != AF_INET6 || in6_addr_is_link_local(&address->in_addr.in6))
                return;

        if (link->clat && in6_addr_equal(&address->in_addr.in6, &link->clat->params.address)) {
                if (FLAGS_SET(address->flags, IFA_F_DADFAILED)) {
                        log_link_warning(link, "CLAT: duplicate address detection failed for %s.",
                                         IN6_ADDR_TO_STRING(&address->in_addr.in6));
                        link->clat_dad_failures++;
                        return clat_restart(link);
                }

                return clat_try_configure(link);
        }

        xlat_start(link);
}

void xlat_address_dropped(Link *link, const Address *address) {
        assert(link);
        assert(address);

        if (!link->clat || address->family != AF_INET6)
                return;

        if (in6_addr_equal(&address->in_addr.in6, &link->clat->params.address)) {
                /* While preparing, this may be the removal of a previous instance of the address, which is
                 * requested again. */
                if (link->clat->state == CLAT_PREPARING)
                        return;

                log_link_info(link, "CLAT: IPv6 address %s was removed, restarting.",
                              IN6_ADDR_TO_STRING(&address->in_addr.in6));
                return clat_restart(link);
        }

        if (!clat_address_is_still_valid(link)) {
                log_link_info(link, "CLAT: IPv6 prefix is gone, restarting.");
                return clat_restart(link);
        }
}

void xlat_route_changed(Link *link, const Route *route, bool removed) {
        assert(route);

        if (!link)
                return;

        if (route_is_ipv4_default(route) && !route_is_clat(route)) {
                if (removed)
                        return xlat_start(link);

                if (link->clat) {
                        log_link_info(link, "CLAT: native IPv4 default route appeared, stopping.");
                        return xlat_stop(link);
                }
        }

        /* An on-link prefix may be what is needed to derive the CLAT address from a /128 address */
        if (!removed && route->family == AF_INET6 && route->dst_prefixlen > 0 &&
            !in_addr_is_set(route->nexthop.family, &route->nexthop.gw))
                xlat_start(link);
}

void xlat_pref64_removed(Link *link, const struct in6_addr *prefix, uint8_t prefix_len) {
        assert(link);
        assert(prefix);

        if (!link->clat || !link->network)
                return;

        /* With a manually configured Pref64Prefix=, CLAT does not depend on the discovered entries. */
        if (link->network->clat_pref64_prefix_len > 0)
                return;

        if (prefix_len != link->clat->params.pref64_len ||
            !in6_addr_equal(prefix, &link->clat->params.pref64))
                return;

        log_link_info(link, "CLAT: PREF64 prefix %s/%u is gone.", IN6_ADDR_TO_STRING(prefix), prefix_len);
        clat_restart(link); /* with another prefix, if there is one */
}

void xlat_mtu_changed(Link *link) {
        assert(link);

        if (!link->clat)
                return;

        log_link_debug(link, "CLAT: MTU changed, restarting.");
        clat_restart(link);
}

int config_parse_clat_pref64_prefix(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Network *network = ASSERT_PTR(userdata);
        union in_addr_union a;
        uint8_t prefixlen;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                network->clat_pref64_prefix = (struct in6_addr) {};
                network->clat_pref64_prefix_len = 0;
                return 0;
        }

        r = in_addr_prefix_from_string(rvalue, AF_INET6, &a, &prefixlen);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (!IN_SET(prefixlen, 96, 64, 56, 48, 40, 32)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "NAT64 prefix length must be 32, 40, 48, 56, 64, or 96, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        (void) in6_addr_mask(&a.in6, prefixlen);
        network->clat_pref64_prefix = a.in6;
        network->clat_pref64_prefix_len = prefixlen;

        return 0;
}
