/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-lldp-tx.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "network-common.h"
#include "random-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "unaligned.h"
#include "web-util.h"

/* The LLDP spec calls this "txFastInit", see 9.2.5.19 */
#define LLDP_FAST_TX_INIT 4U

/* The LLDP spec calls this "msgTxHold", see 9.2.5.6 */
#define LLDP_TX_HOLD 4U

/* The jitter range to add, see 9.2.2. */
#define LLDP_TX_JITTER_USEC (400U * USEC_PER_MSEC)

/* The LLDP spec calls this msgTxInterval, but we subtract half the jitter off it. */
#define LLDP_TX_INTERVAL_USEC (30U * USEC_PER_SEC - LLDP_TX_JITTER_USEC / 2)

/* The LLDP spec calls this msgFastTx, but we subtract half the jitter off it. */
#define LLDP_FAST_TX_INTERVAL_USEC (1U * USEC_PER_SEC - LLDP_TX_JITTER_USEC / 2)

#define LLDP_TX_TTL ((uint16_t) DIV_ROUND_UP(LLDP_TX_INTERVAL_USEC * LLDP_TX_HOLD + 1, USEC_PER_SEC))

static const struct ether_addr lldp_multicast_addr[_SD_LLDP_MULTICAST_MODE_MAX] = {
        [SD_LLDP_MULTICAST_MODE_NEAREST_BRIDGE]  = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e }},
        [SD_LLDP_MULTICAST_MODE_NON_TPMR_BRIDGE] = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }},
        [SD_LLDP_MULTICAST_MODE_CUSTOMER_BRIDGE] = {{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 }},
};

struct sd_lldp_tx {
        unsigned n_ref;

        int ifindex;
        char *ifname;

        sd_event *event;
        int64_t event_priority;
        sd_event_source *timer_event_source;

        unsigned fast_tx;

        sd_lldp_multicast_mode_t mode;
        struct ether_addr hwaddr;

        char *port_description;
        char *hostname;
        char *pretty_hostname;
        char *mud_url;
        uint16_t supported_capabilities;
        uint16_t enabled_capabilities;
};

#define log_lldp_tx_errno(lldp_tx, error, fmt, ...)     \
        log_interface_prefix_full_errno(                \
                "LLDP Tx: ",                            \
                sd_lldp_tx, lldp_tx,                    \
                error, fmt, ##__VA_ARGS__)
#define log_lldp_tx(lldp_tx, fmt, ...)                  \
        log_interface_prefix_full_errno_zerook(         \
                "LLDP Tx: ",                            \
                sd_lldp_tx, lldp_tx,                    \
                0, fmt, ##__VA_ARGS__)

static sd_lldp_tx *lldp_tx_free(sd_lldp_tx *lldp_tx) {
        if (!lldp_tx)
                return NULL;

        sd_lldp_tx_detach_event(lldp_tx);

        free(lldp_tx->port_description);
        free(lldp_tx->hostname);
        free(lldp_tx->pretty_hostname);
        free(lldp_tx->mud_url);

        free(lldp_tx->ifname);
        return mfree(lldp_tx);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_lldp_tx, sd_lldp_tx, lldp_tx_free);

int sd_lldp_tx_new(sd_lldp_tx **ret) {
        _cleanup_(sd_lldp_tx_unrefp) sd_lldp_tx *lldp_tx = NULL;

        assert_return(ret, -EINVAL);

        lldp_tx = new(sd_lldp_tx, 1);
        if (!lldp_tx)
                return -ENOMEM;

        *lldp_tx = (sd_lldp_tx) {
                .n_ref = 1,
                .mode = _SD_LLDP_MULTICAST_MODE_INVALID,
        };

        *ret = TAKE_PTR(lldp_tx);
        return 0;
}

int sd_lldp_tx_set_ifindex(sd_lldp_tx *lldp_tx, int ifindex) {
        assert_return(lldp_tx, -EINVAL);
        assert_return(ifindex > 0, -EINVAL);

        lldp_tx->ifindex = ifindex;
        return 0;
}

int sd_lldp_tx_set_ifname(sd_lldp_tx *lldp_tx, const char *ifname) {
        assert_return(lldp_tx, -EINVAL);
        assert_return(ifname, -EINVAL);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE))
                return -EINVAL;

        return free_and_strdup(&lldp_tx->ifname, ifname);
}

int sd_lldp_tx_get_ifname(sd_lldp_tx *lldp_tx, const char **ret) {
        int r;

        assert_return(lldp_tx, -EINVAL);

        r = get_ifname(lldp_tx->ifindex, &lldp_tx->ifname);
        if (r < 0)
                return r;

        if (ret)
                *ret = lldp_tx->ifname;

        return 0;
}

int sd_lldp_tx_set_multicast_mode(sd_lldp_tx *lldp_tx, sd_lldp_multicast_mode_t mode) {
        assert_return(lldp_tx, -EINVAL);
        assert_return(mode >= 0 && mode < _SD_LLDP_MULTICAST_MODE_MAX, -EINVAL);

        lldp_tx->mode = mode;
        return 0;
}

int sd_lldp_tx_set_hwaddr(sd_lldp_tx *lldp_tx, const struct ether_addr *hwaddr) {
        assert_return(lldp_tx, -EINVAL);
        assert_return(!ether_addr_is_null(hwaddr), -EINVAL);

        lldp_tx->hwaddr = *hwaddr;
        return 0;
}

int sd_lldp_tx_set_capabilities(sd_lldp_tx *lldp_tx, uint16_t supported, uint16_t enabled) {
        assert_return(lldp_tx, -EINVAL);
        assert_return((enabled & ~supported) == 0, -EINVAL);

        lldp_tx->supported_capabilities = supported;
        lldp_tx->enabled_capabilities = enabled;
        return 0;
}

int sd_lldp_tx_set_port_description(sd_lldp_tx *lldp_tx, const char *port_description) {
        assert_return(lldp_tx, -EINVAL);

        /* An empty string unset the previously set hostname. */
        if (strlen_ptr(port_description) >= 512)
                return -EINVAL;

        return free_and_strdup(&lldp_tx->port_description, empty_to_null(port_description));
}

int sd_lldp_tx_set_hostname(sd_lldp_tx *lldp_tx, const char *hostname) {
        assert_return(lldp_tx, -EINVAL);

        /* An empty string unset the previously set hostname. */
        if (!isempty(hostname)) {
                assert_cc(HOST_NAME_MAX < 512);

                if (!hostname_is_valid(hostname, 0))
                        return -EINVAL;
        }

        return free_and_strdup(&lldp_tx->hostname, empty_to_null(hostname));
}

int sd_lldp_tx_set_pretty_hostname(sd_lldp_tx *lldp_tx, const char *pretty_hostname) {
        assert_return(lldp_tx, -EINVAL);

        /* An empty string unset the previously set hostname. */
        if (strlen_ptr(pretty_hostname) >= 512)
                return -EINVAL;

        return free_and_strdup(&lldp_tx->pretty_hostname, empty_to_null(pretty_hostname));
}

int sd_lldp_tx_set_mud_url(sd_lldp_tx *lldp_tx, const char *mud_url) {
        assert_return(lldp_tx, -EINVAL);

        /* An empty string unset the previously set hostname. */
        if (!isempty(mud_url)) {
                /* Unless the maximum length of each value is 511, the MUD url must be smaller than 256.
                 * See RFC 8520. */
                if (strlen(mud_url) >= 256)
                        return -EINVAL;

                if (!http_url_is_valid(mud_url))
                        return -EINVAL;
        }

        return free_and_strdup(&lldp_tx->mud_url, empty_to_null(mud_url));
}

static size_t lldp_tx_calculate_maximum_packet_size(sd_lldp_tx *lldp_tx, const char *hostname, const char *pretty_hostname) {
        assert(lldp_tx);
        assert(lldp_tx->ifindex > 0);

        return sizeof(struct ether_header) +
                /* Chassis ID */
                2 + 1 + (SD_ID128_STRING_MAX - 1) +
                /* Port ID */
                2 + 1 + strlen_ptr(lldp_tx->ifname) +
                /* TTL */
                2 + 2 +
                /* Port description */
                2 + strlen_ptr(lldp_tx->port_description) +
                /* System name */
                2 + strlen_ptr(hostname) +
                /* System description */
                2 + strlen_ptr(pretty_hostname) +
                /* MUD URL */
                2 + sizeof(SD_LLDP_OUI_IANA_MUD) + strlen_ptr(lldp_tx->mud_url) +
                /* System Capabilities */
                2 + 4 +
                /* End */
                2;
}

static int packet_append_tlv_header(uint8_t *packet, size_t packet_size, size_t *offset, uint8_t type, size_t data_len) {
        assert(packet);
        assert(offset);

        /*
         * +--------+--------+--------------
         * |TLV Type|  len   |   value
         * |(7 bits)|(9 bits)|(0-511 octets)
         * +--------+--------+--------------
         * where:
         *
         * len = indicates the length of value
         */

        /* The type field is 7-bits. */
        if (type >= 128)
                return -EINVAL;

        /* The data length field is 9-bits. */
        if (data_len >= 512)
                return -EINVAL;

        if (packet_size < 2 + data_len)
                return -ENOBUFS;

        if (*offset > packet_size - 2 - data_len)
                return -ENOBUFS;

        packet[(*offset)++] = (type << 1) | !!(data_len >> 8);
        packet[(*offset)++] = data_len & (size_t) UINT8_MAX;

        return 0;
}

static int packet_append_prefixed_string(
                uint8_t *packet,
                size_t packet_size,
                size_t *offset,
                uint8_t type,
                size_t prefix_len,
                const void *prefix,
                const char *str) {

        size_t len;
        int r;

        assert(packet);
        assert(offset);
        assert(prefix_len == 0 || prefix);

        if (isempty(str))
                return 0;

        len = strlen(str);

        /* Check for overflow */
        if (len > SIZE_MAX - prefix_len)
                return -ENOBUFS;

        r = packet_append_tlv_header(packet, packet_size, offset, type, prefix_len + len);
        if (r < 0)
                return r;

        memcpy_safe(packet + *offset, prefix, prefix_len);
        *offset += prefix_len;

        memcpy(packet + *offset, str, len);
        *offset += len;

        return 0;
}

static int packet_append_string(
                uint8_t *packet,
                size_t packet_size,
                size_t *offset,
                uint8_t type,
                const char *str) {

        return packet_append_prefixed_string(packet, packet_size, offset, type, 0, NULL, str);
}

static int lldp_tx_create_packet(sd_lldp_tx *lldp_tx, size_t *ret_packet_size, uint8_t **ret_packet) {
        _cleanup_free_ char *hostname = NULL, *pretty_hostname = NULL;
        _cleanup_free_ uint8_t *packet = NULL;
        struct ether_header *header;
        size_t packet_size, offset;
        sd_id128_t machine_id;
        int r;

        assert(lldp_tx);
        assert(lldp_tx->ifindex > 0);
        assert(ret_packet_size);
        assert(ret_packet);

        /* If ifname is not set yet, set ifname from ifindex. */
        r = sd_lldp_tx_get_ifname(lldp_tx, NULL);
        if (r < 0)
                return r;

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return r;

        if (!lldp_tx->hostname)
                (void) gethostname_strict(&hostname);
        if (!lldp_tx->pretty_hostname)
                (void) get_pretty_hostname(&pretty_hostname);

        packet_size = lldp_tx_calculate_maximum_packet_size(lldp_tx,
                                                            lldp_tx->hostname ?: hostname,
                                                            lldp_tx->pretty_hostname ?: pretty_hostname);

        packet = new(uint8_t, packet_size);
        if (!packet)
                return -ENOMEM;

        header = (struct ether_header*) packet;
        header->ether_type = htobe16(ETHERTYPE_LLDP);
        memcpy(header->ether_dhost, lldp_multicast_addr + lldp_tx->mode, ETH_ALEN);
        memcpy(header->ether_shost, &lldp_tx->hwaddr, ETH_ALEN);

        offset = sizeof(struct ether_header);

        /* The three mandatory TLVs must appear first, in this specific order:
         *   1. Chassis ID
         *   2. Port ID
         *   3. Time To Live
         */

        r = packet_append_prefixed_string(packet, packet_size, &offset, SD_LLDP_TYPE_CHASSIS_ID,
                                          1, (const uint8_t[]) { SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED },
                                          SD_ID128_TO_STRING(machine_id));
        if (r < 0)
                return r;

        r = packet_append_prefixed_string(packet, packet_size, &offset, SD_LLDP_TYPE_PORT_ID,
                                          1, (const uint8_t[]) { SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME },
                                          lldp_tx->ifname);
        if (r < 0)
                return r;

        r = packet_append_tlv_header(packet, packet_size, &offset, SD_LLDP_TYPE_TTL, 2);
        if (r < 0)
                return r;

        unaligned_write_be16(packet + offset, LLDP_TX_TTL);
        offset += 2;

        /* Optional TLVs follow, in no specific order: */

        r = packet_append_string(packet, packet_size, &offset, SD_LLDP_TYPE_PORT_DESCRIPTION,
                                 lldp_tx->port_description);
        if (r < 0)
                return r;

        r = packet_append_string(packet, packet_size, &offset, SD_LLDP_TYPE_SYSTEM_NAME,
                                 lldp_tx->hostname ?: hostname);
        if (r < 0)
                return r;

        r = packet_append_string(packet, packet_size, &offset, SD_LLDP_TYPE_SYSTEM_DESCRIPTION,
                                 lldp_tx->pretty_hostname ?: pretty_hostname);
        if (r < 0)
                return r;

        /* See section 12 of RFC 8520.
         * +--------+--------+----------+---------+--------------
         * |TLV Type|  len   |   OUI    |subtype  | MUDString
         * |  =127  |        |= 00 00 5E|  = 1    |
         * |(7 bits)|(9 bits)|(3 octets)|(1 octet)|(1-255 octets)
         * +--------+--------+----------+---------+--------------
         * where:
         *
         * o  TLV Type = 127 indicates a vendor-specific TLV
         * o  len = indicates the TLV string length
         * o  OUI = 00 00 5E is the organizationally unique identifier of IANA
         * o  subtype = 1 (as assigned by IANA for the MUDstring)
         * o  MUDstring = the length MUST NOT exceed 255 octets
         */
        r = packet_append_prefixed_string(packet, packet_size, &offset, SD_LLDP_TYPE_PRIVATE,
                                          sizeof(SD_LLDP_OUI_IANA_MUD), SD_LLDP_OUI_IANA_MUD,
                                          lldp_tx->mud_url);
        if (r < 0)
                return r;

        r = packet_append_tlv_header(packet, packet_size, &offset, SD_LLDP_TYPE_SYSTEM_CAPABILITIES, 4);
        if (r < 0)
                return r;

        unaligned_write_be16(packet + offset, lldp_tx->supported_capabilities);
        offset += 2;
        unaligned_write_be16(packet + offset, lldp_tx->enabled_capabilities);
        offset += 2;

        r = packet_append_tlv_header(packet, packet_size, &offset, SD_LLDP_TYPE_END, 0);
        if (r < 0)
                return r;

        *ret_packet_size = offset;
        *ret_packet = TAKE_PTR(packet);
        return 0;
}

static int lldp_tx_send_packet(sd_lldp_tx *lldp_tx, size_t packet_size, const uint8_t *packet) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa;
        ssize_t l;

        assert(lldp_tx);
        assert(lldp_tx->ifindex > 0);
        assert(packet_size > sizeof(struct ether_header));
        assert(packet);

        sa = (union sockaddr_union) {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htobe16(ETHERTYPE_LLDP),
                .ll.sll_ifindex = lldp_tx->ifindex,
                .ll.sll_halen = ETH_ALEN,
        };
        memcpy(sa.ll.sll_addr, lldp_multicast_addr + lldp_tx->mode, ETH_ALEN);

        fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
        if (fd < 0)
                return -errno;

        l = sendto(fd, packet, packet_size, MSG_NOSIGNAL, &sa.sa, sizeof(sa.ll));
        if (l < 0)
                return -errno;

        if ((size_t) l != packet_size)
                return -EIO;

        return 0;
}

static int lldp_tx_send(sd_lldp_tx *lldp_tx) {
        _cleanup_free_ uint8_t *packet = NULL;
        size_t packet_size = 0;  /* avoid false maybe-uninitialized warning */
        int r;

        assert(lldp_tx);

        r = lldp_tx_create_packet(lldp_tx, &packet_size, &packet);
        if (r < 0)
                return r;

        return lldp_tx_send_packet(lldp_tx, packet_size, packet);
}

int sd_lldp_tx_attach_event(sd_lldp_tx *lldp_tx, sd_event *event, int64_t priority) {
        int r;

        assert_return(lldp_tx, -EINVAL);
        assert_return(!lldp_tx->event, -EBUSY);

        if (event)
                lldp_tx->event = sd_event_ref(event);
        else {
                r = sd_event_default(&lldp_tx->event);
                if (r < 0)
                        return r;
        }

        lldp_tx->event_priority = priority;

        return 0;
}

int sd_lldp_tx_detach_event(sd_lldp_tx *lldp_tx) {
        assert_return(lldp_tx, -EINVAL);

        lldp_tx->timer_event_source = sd_event_source_disable_unref(lldp_tx->timer_event_source);
        lldp_tx->event = sd_event_unref(lldp_tx->event);
        return 0;
}

static usec_t lldp_tx_get_delay(sd_lldp_tx *lldp_tx) {
        assert(lldp_tx);

        return usec_add(lldp_tx->fast_tx > 0 ? LLDP_FAST_TX_INTERVAL_USEC : LLDP_TX_INTERVAL_USEC,
                        (usec_t) random_u64() % LLDP_TX_JITTER_USEC);
}

static int lldp_tx_reset_timer(sd_lldp_tx *lldp_tx) {
        usec_t delay;
        int r;

        assert(lldp_tx);
        assert(lldp_tx->timer_event_source);

        delay = lldp_tx_get_delay(lldp_tx);

        r = sd_event_source_set_time_relative(lldp_tx->timer_event_source, delay);
        if (r < 0)
                return r;

        return sd_event_source_set_enabled(lldp_tx->timer_event_source, SD_EVENT_ONESHOT);
}

static int on_timer_event(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_lldp_tx *lldp_tx = ASSERT_PTR(userdata);
        int r;

        r = lldp_tx_send(lldp_tx);
        if (r < 0)
                log_lldp_tx_errno(lldp_tx, r, "Failed to send packet, ignoring: %m");

        if (lldp_tx->fast_tx > 0)
                lldp_tx->fast_tx--;

        r = lldp_tx_reset_timer(lldp_tx);
        if (r < 0)
                log_lldp_tx_errno(lldp_tx, r, "Failed to reset timer: %m");

        return 0;
}

int sd_lldp_tx_is_running(sd_lldp_tx *lldp_tx) {
        int enabled;

        if (!lldp_tx)
                return 0;

        if (!lldp_tx->timer_event_source)
                return 0;

        if (sd_event_source_get_enabled(lldp_tx->timer_event_source, &enabled) < 0)
                return 0;

        return enabled == SD_EVENT_ONESHOT;
}

int sd_lldp_tx_stop(sd_lldp_tx *lldp_tx) {
        if (!lldp_tx)
                return 0;

        if (!lldp_tx->timer_event_source)
                return 0;

        (void) sd_event_source_set_enabled(lldp_tx->timer_event_source, SD_EVENT_OFF);

        return 1;
}
int sd_lldp_tx_start(sd_lldp_tx *lldp_tx) {
        usec_t delay;
        int r;

        assert_return(lldp_tx, -EINVAL);
        assert_return(lldp_tx->event, -EINVAL);
        assert_return(lldp_tx->ifindex > 0, -EINVAL);
        assert_return(lldp_tx->mode >= 0 && lldp_tx->mode < _SD_LLDP_MULTICAST_MODE_MAX, -EINVAL);
        assert_return(!ether_addr_is_null(&lldp_tx->hwaddr), -EINVAL);

        if (sd_lldp_tx_is_running(lldp_tx))
                return 0;

        lldp_tx->fast_tx = LLDP_FAST_TX_INIT;

        if (lldp_tx->timer_event_source) {
                r = lldp_tx_reset_timer(lldp_tx);
                if (r < 0)
                        return log_lldp_tx_errno(lldp_tx, r, "Failed to re-enable timer: %m");

                return 0;
        }

        delay = lldp_tx_get_delay(lldp_tx);

        r = sd_event_add_time_relative(lldp_tx->event, &lldp_tx->timer_event_source,
                                       CLOCK_BOOTTIME, delay, 0,
                                       on_timer_event, lldp_tx);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(lldp_tx->timer_event_source, "lldp-tx-timer");
        (void) sd_event_source_set_priority(lldp_tx->timer_event_source, lldp_tx->event_priority);

        return 0;
}
