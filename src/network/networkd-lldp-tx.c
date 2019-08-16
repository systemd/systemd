/* SPDX-License-Identifier: LGPL-2.1+ */

#include <endian.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <string.h>

#include "alloc-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "missing_network.h"
#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "unaligned.h"

/* The LLDP spec calls this "txFastInit", see 9.2.5.19 */
#define LLDP_TX_FAST_INIT 4U

/* The LLDP spec calls this "msgTxHold", see 9.2.5.6 */
#define LLDP_TX_HOLD 4U

/* The jitter range to add, see 9.2.2. */
#define LLDP_JITTER_USEC (400U * USEC_PER_MSEC)

/* The LLDP spec calls this msgTxInterval, but we subtract half the jitter off it. */
#define LLDP_TX_INTERVAL_USEC (30U * USEC_PER_SEC - LLDP_JITTER_USEC / 2)

/* The LLDP spec calls this msgFastTx, but we subtract half the jitter off it. */
#define LLDP_FAST_TX_USEC (1U * USEC_PER_SEC - LLDP_JITTER_USEC / 2)

static const struct ether_addr lldp_multicast_addr[_LLDP_EMIT_MAX] = {
        [LLDP_EMIT_NEAREST_BRIDGE]  = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }},
        [LLDP_EMIT_NON_TPMR_BRIDGE] = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }},
        [LLDP_EMIT_CUSTOMER_BRIDGE] = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }},
};

bool link_lldp_emit_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        return link->network->lldp_emit != LLDP_EMIT_NO;
}

static int lldp_write_tlv_header(uint8_t **p, uint8_t id, size_t sz) {
        assert(p);

        if (id > 127)
                return -EBADMSG;
        if (sz > 511)
                return -ENOBUFS;

        (*p)[0] = (id << 1) | !!(sz & 256);
        (*p)[1] = sz & 255;

        *p = *p + 2;
        return 0;
}

static int lldp_make_packet(
                LLDPEmit mode,
                const struct ether_addr *hwaddr,
                const char *machine_id,
                const char *ifname,
                uint16_t ttl,
                const char *port_description,
                const char *hostname,
                const char *pretty_hostname,
                uint16_t system_capabilities,
                uint16_t enabled_capabilities,
                void **ret, size_t *sz) {

        size_t machine_id_length, ifname_length, port_description_length = 0, hostname_length = 0, pretty_hostname_length = 0;
        _cleanup_free_ void *packet = NULL;
        struct ether_header *h;
        uint8_t *p;
        size_t l;
        int r;

        assert(mode > LLDP_EMIT_NO);
        assert(mode < _LLDP_EMIT_MAX);
        assert(hwaddr);
        assert(machine_id);
        assert(ifname);
        assert(ret);
        assert(sz);

        machine_id_length = strlen(machine_id);
        ifname_length = strlen(ifname);

        if (port_description)
                port_description_length = strlen(port_description);

        if (hostname)
                hostname_length = strlen(hostname);

        if (pretty_hostname)
                pretty_hostname_length = strlen(pretty_hostname);

        l = sizeof(struct ether_header) +
                /* Chassis ID */
                2 + 1 + machine_id_length +
                /* Port ID */
                2 + 1 + ifname_length +
                /* TTL */
                2 + 2 +
                /* System Capabilities */
                2 + 4 +
                /* End */
                2;

        /* Port Description */
        if (port_description)
                l += 2 + port_description_length;

        /* System Name */
        if (hostname)
                l += 2 + hostname_length;

        /* System Description */
        if (pretty_hostname)
                l += 2 + pretty_hostname_length;

        packet = malloc(l);
        if (!packet)
                return -ENOMEM;

        h = (struct ether_header*) packet;
        h->ether_type = htobe16(ETHERTYPE_LLDP);
        memcpy(h->ether_dhost, lldp_multicast_addr + mode, ETH_ALEN);
        memcpy(h->ether_shost, hwaddr, ETH_ALEN);

        p = (uint8_t*) packet + sizeof(struct ether_header);

        r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_CHASSIS_ID, 1 + machine_id_length);
        if (r < 0)
                return r;
        *(p++) = SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED;
        p = mempcpy(p, machine_id, machine_id_length);

        r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_PORT_ID, 1 + ifname_length);
        if (r < 0)
                return r;
        *(p++) = SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME;
        p = mempcpy(p, ifname, ifname_length);

        r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_TTL, 2);
        if (r < 0)
                return r;
        unaligned_write_be16(p, ttl);
        p += 2;

        if (port_description) {
                r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_PORT_DESCRIPTION, port_description_length);
                if (r < 0)
                        return r;
                p = mempcpy(p, port_description, port_description_length);
        }

        if (hostname) {
                r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_SYSTEM_NAME, hostname_length);
                if (r < 0)
                        return r;
                p = mempcpy(p, hostname, hostname_length);
        }

        if (pretty_hostname) {
                r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_SYSTEM_DESCRIPTION, pretty_hostname_length);
                if (r < 0)
                        return r;
                p = mempcpy(p, pretty_hostname, pretty_hostname_length);
        }

        r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_SYSTEM_CAPABILITIES, 4);
        if (r < 0)
                return r;
        unaligned_write_be16(p, system_capabilities);
        p += 2;
        unaligned_write_be16(p, enabled_capabilities);
        p += 2;

        r = lldp_write_tlv_header(&p, SD_LLDP_TYPE_END, 0);
        if (r < 0)
                return r;

        assert(p == (uint8_t*) packet + l);

        *ret = TAKE_PTR(packet);
        *sz = l;

        return 0;
}

static int lldp_send_packet(
                int ifindex,
                const struct ether_addr *address,
                const void *packet,
                size_t packet_size) {

        union sockaddr_union sa = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETHERTYPE_LLDP),
                .ll.sll_ifindex = ifindex,
                .ll.sll_halen = ETH_ALEN,
        };

        _cleanup_close_ int fd = -1;
        ssize_t l;

        assert(ifindex > 0);
        assert(address);
        assert(packet || packet_size <= 0);

        memcpy(sa.ll.sll_addr, address, ETH_ALEN);

        fd = socket(PF_PACKET, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_RAW);
        if (fd < 0)
                return -errno;

        l = sendto(fd, packet, packet_size, MSG_NOSIGNAL, &sa.sa, sizeof(sa.ll));
        if (l < 0)
                return -errno;

        if ((size_t) l != packet_size)
                return -EIO;

        return 0;
}

static int link_send_lldp(Link *link) {
        char machine_id_string[SD_ID128_STRING_MAX];
        _cleanup_free_ char *hostname = NULL, *pretty_hostname = NULL;
        _cleanup_free_ void *packet = NULL;
        size_t packet_size = 0;
        sd_id128_t machine_id;
        uint16_t caps;
        usec_t ttl;
        int r;

        assert(link);

        if (!link->network || link->network->lldp_emit == LLDP_EMIT_NO)
                return 0;

        assert(link->network->lldp_emit < _LLDP_EMIT_MAX);

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return r;

        (void) gethostname_strict(&hostname);
        (void) parse_env_file(NULL, "/etc/machine-info", "PRETTY_HOSTNAME", &pretty_hostname);

        assert_cc(LLDP_TX_INTERVAL_USEC * LLDP_TX_HOLD + 1 <= (UINT16_MAX - 1) * USEC_PER_SEC);
        ttl = DIV_ROUND_UP(LLDP_TX_INTERVAL_USEC * LLDP_TX_HOLD + 1, USEC_PER_SEC);

        caps = (link->network && link->network->ip_forward != ADDRESS_FAMILY_NO) ?
                SD_LLDP_SYSTEM_CAPABILITIES_ROUTER :
                SD_LLDP_SYSTEM_CAPABILITIES_STATION;

        r = lldp_make_packet(link->network->lldp_emit,
                             &link->mac,
                             sd_id128_to_string(machine_id, machine_id_string),
                             link->ifname,
                             (uint16_t) ttl,
                             link->network ? link->network->description : NULL,
                             hostname,
                             pretty_hostname,
                             SD_LLDP_SYSTEM_CAPABILITIES_STATION|SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE|SD_LLDP_SYSTEM_CAPABILITIES_ROUTER,
                             caps,
                             &packet, &packet_size);
        if (r < 0)
                return r;

        return lldp_send_packet(link->ifindex, lldp_multicast_addr + link->network->lldp_emit, packet, packet_size);
}

static int on_lldp_timer(sd_event_source *s, usec_t t, void *userdata) {
        Link *link = userdata;
        usec_t current, delay, next;
        int r;

        assert(s);
        assert(userdata);

        log_link_debug(link, "Sending LLDP packet...");

        r = link_send_lldp(link);
        if (r < 0)
                log_link_debug_errno(link, r, "Failed to send LLDP packet, ignoring: %m");

        if (link->lldp_tx_fast > 0)
                link->lldp_tx_fast--;

        assert_se(sd_event_now(sd_event_source_get_event(s), clock_boottime_or_monotonic(), &current) >= 0);

        delay = link->lldp_tx_fast > 0 ? LLDP_FAST_TX_USEC : LLDP_TX_INTERVAL_USEC;
        next = usec_add(usec_add(current, delay), (usec_t) random_u64() % LLDP_JITTER_USEC);

        r = sd_event_source_set_time(s, next);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to restart LLDP timer: %m");

        r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to enable LLDP timer: %m");

        return 0;
}

int link_lldp_emit_start(Link *link) {
        usec_t next;
        int r;

        assert(link);

        if (!link->network || link->network->lldp_emit == LLDP_EMIT_NO) {
                link_lldp_emit_stop(link);
                return 0;
        }

        /* Starts the LLDP transmission in "fast" mode. If it is already started, turns "fast" mode back on again. */

        link->lldp_tx_fast = LLDP_TX_FAST_INIT;

        next = usec_add(usec_add(now(clock_boottime_or_monotonic()), LLDP_FAST_TX_USEC),
                     (usec_t) random_u64() % LLDP_JITTER_USEC);

        if (link->lldp_emit_event_source) {
                usec_t old;

                /* Lower the timeout, maybe */
                r = sd_event_source_get_time(link->lldp_emit_event_source, &old);
                if (r < 0)
                        return r;

                if (old <= next)
                        return 0;

                return sd_event_source_set_time(link->lldp_emit_event_source, next);
        } else {
                r = sd_event_add_time(
                                link->manager->event,
                                &link->lldp_emit_event_source,
                                clock_boottime_or_monotonic(),
                                next,
                                0,
                                on_lldp_timer,
                                link);
                if (r < 0)
                        return r;

                (void) sd_event_source_set_description(link->lldp_emit_event_source, "lldp-tx");
        }

        return 0;
}

void link_lldp_emit_stop(Link *link) {
        assert(link);

        link->lldp_emit_event_source = sd_event_source_unref(link->lldp_emit_event_source);
}

int config_parse_lldp_emit(
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

        LLDPEmit *emit = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                *emit = LLDP_EMIT_NO;
        else if (streq(rvalue, "nearest-bridge"))
                *emit = LLDP_EMIT_NEAREST_BRIDGE;
        else if (streq(rvalue, "non-tpmr-bridge"))
                *emit = LLDP_EMIT_NON_TPMR_BRIDGE;
        else if (streq(rvalue, "customer-bridge"))
                *emit = LLDP_EMIT_CUSTOMER_BRIDGE;
        else {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, 0, "Failed to parse LLDP emission setting, ignoring: %s", rvalue);
                        return 0;
                }

                *emit = r ? LLDP_EMIT_NEAREST_BRIDGE : LLDP_EMIT_NO;
        }

        return 0;
}
