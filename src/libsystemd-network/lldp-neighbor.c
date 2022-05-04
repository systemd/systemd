/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "lldp-neighbor.h"
#include "memory-util.h"
#include "missing_network.h"
#include "unaligned.h"

static void lldp_neighbor_id_hash_func(const LLDPNeighborID *id, struct siphash *state) {
        assert(id);
        assert(state);

        siphash24_compress(id->chassis_id, id->chassis_id_size, state);
        siphash24_compress(&id->chassis_id_size, sizeof(id->chassis_id_size), state);
        siphash24_compress(id->port_id, id->port_id_size, state);
        siphash24_compress(&id->port_id_size, sizeof(id->port_id_size), state);
}

int lldp_neighbor_id_compare_func(const LLDPNeighborID *x, const LLDPNeighborID *y) {
        assert(x);
        assert(y);

        return memcmp_nn(x->chassis_id, x->chassis_id_size, y->chassis_id, y->chassis_id_size)
            ?: memcmp_nn(x->port_id, x->port_id_size, y->port_id, y->port_id_size);
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        lldp_neighbor_hash_ops,
        LLDPNeighborID,
        lldp_neighbor_id_hash_func,
        lldp_neighbor_id_compare_func,
        sd_lldp_neighbor,
        lldp_neighbor_unlink);

int lldp_neighbor_prioq_compare_func(const void *a, const void *b) {
        const sd_lldp_neighbor *x = a, *y = b;

        assert(x);
        assert(y);

        return CMP(x->until, y->until);
}

sd_lldp_neighbor *sd_lldp_neighbor_ref(sd_lldp_neighbor *n) {
        if (!n)
                return NULL;

        assert(n->n_ref > 0 || n->lldp_rx);
        n->n_ref++;

        return n;
}

static sd_lldp_neighbor *lldp_neighbor_free(sd_lldp_neighbor *n) {
        if (!n)
                return NULL;

        free(n->id.port_id);
        free(n->id.chassis_id);
        free(n->port_description);
        free(n->system_name);
        free(n->system_description);
        free(n->mud_url);
        free(n->chassis_id_as_string);
        free(n->port_id_as_string);
        return mfree(n);
}

sd_lldp_neighbor *sd_lldp_neighbor_unref(sd_lldp_neighbor *n) {

        /* Drops one reference from the neighbor. Note that the object is not freed unless it is already unlinked from
         * the sd_lldp object. */

        if (!n)
                return NULL;

        assert(n->n_ref > 0);
        n->n_ref--;

        if (n->n_ref <= 0 && !n->lldp_rx)
                lldp_neighbor_free(n);

        return NULL;
}

sd_lldp_neighbor *lldp_neighbor_unlink(sd_lldp_neighbor *n) {

        /* Removes the neighbor object from the LLDP object, and frees it if it also has no other reference. */

        if (!n)
                return NULL;

        if (!n->lldp_rx)
                return NULL;

        /* Only remove the neighbor object from the hash table if it's in there, don't complain if it isn't. This is
         * because we are used as destructor call for hashmap_clear() and thus sometimes are called to de-register
         * ourselves from the hashtable and sometimes are called after we already are de-registered. */

        (void) hashmap_remove_value(n->lldp_rx->neighbor_by_id, &n->id, n);

        assert_se(prioq_remove(n->lldp_rx->neighbor_by_expiry, n, &n->prioq_idx) >= 0);

        n->lldp_rx = NULL;

        if (n->n_ref <= 0)
                lldp_neighbor_free(n);

        return NULL;
}

sd_lldp_neighbor *lldp_neighbor_new(size_t raw_size) {
        sd_lldp_neighbor *n;

        if (raw_size > SIZE_MAX - ALIGN(sizeof(sd_lldp_neighbor)))
                return NULL;

        n = malloc0(ALIGN(sizeof(sd_lldp_neighbor)) + raw_size);
        if (!n)
                return NULL;

        n->raw_size = raw_size;
        n->n_ref = 1;

        return n;
}

static int parse_string(sd_lldp_rx *lldp_rx, char **s, const void *q, size_t n) {
        const char *p = q;
        char *k;

        assert(s);
        assert(p || n == 0);

        if (*s) {
                log_lldp_rx(lldp_rx, "Found duplicate string, ignoring field.");
                return 0;
        }

        /* Strip trailing NULs, just to be nice */
        while (n > 0 && p[n-1] == 0)
                n--;

        if (n <= 0) /* Ignore empty strings */
                return 0;

        /* Look for inner NULs */
        if (memchr(p, 0, n)) {
                log_lldp_rx(lldp_rx, "Found inner NUL in string, ignoring field.");
                return 0;
        }

        /* Let's escape weird chars, for security reasons */
        k = cescape_length(p, n);
        if (!k)
                return log_oom_debug();

        free(*s);
        *s = k;

        return 1;
}

int lldp_neighbor_parse(sd_lldp_neighbor *n) {
        struct ether_header h;
        const uint8_t *p;
        size_t left;
        int r;

        assert(n);

        if (n->raw_size < sizeof(struct ether_header))
                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                         "Received truncated packet, ignoring.");

        memcpy(&h, LLDP_NEIGHBOR_RAW(n), sizeof(h));

        if (h.ether_type != htobe16(ETHERTYPE_LLDP))
                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                         "Received packet with wrong type, ignoring.");

        if (h.ether_dhost[0] != 0x01 ||
            h.ether_dhost[1] != 0x80 ||
            h.ether_dhost[2] != 0xc2 ||
            h.ether_dhost[3] != 0x00 ||
            h.ether_dhost[4] != 0x00 ||
            !IN_SET(h.ether_dhost[5], 0x00, 0x03, 0x0e))
                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                         "Received packet with wrong destination address, ignoring.");

        memcpy(&n->source_address, h.ether_shost, sizeof(struct ether_addr));
        memcpy(&n->destination_address, h.ether_dhost, sizeof(struct ether_addr));

        p = (const uint8_t*) LLDP_NEIGHBOR_RAW(n) + sizeof(struct ether_header);
        left = n->raw_size - sizeof(struct ether_header);

        for (;;) {
                uint8_t type;
                uint16_t length;

                if (left < 2)
                        return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                              "TLV lacks header, ignoring.");

                type = p[0] >> 1;
                length = p[1] + (((uint16_t) (p[0] & 1)) << 8);
                p += 2, left -= 2;

                if (left < length)
                        return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                 "TLV truncated, ignoring datagram.");

                switch (type) {

                case SD_LLDP_TYPE_END:
                        if (length != 0)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "End marker TLV not zero-sized, ignoring datagram.");

                        /* Note that after processing the SD_LLDP_TYPE_END left could still be > 0
                         * as the message may contain padding (see IEEE 802.1AB-2016, sec. 8.5.12) */

                        goto end_marker;

                case SD_LLDP_TYPE_CHASSIS_ID:
                        if (length < 2 || length > 256)
                                /* includes the chassis subtype, hence one extra byte */
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Chassis ID field size out of range, ignoring datagram.");

                        if (n->id.chassis_id)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Duplicate chassis ID field, ignoring datagram.");

                        n->id.chassis_id = memdup(p, length);
                        if (!n->id.chassis_id)
                                return log_oom_debug();

                        n->id.chassis_id_size = length;
                        break;

                case SD_LLDP_TYPE_PORT_ID:
                        if (length < 2 || length > 256)
                                /* includes the port subtype, hence one extra byte */
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Port ID field size out of range, ignoring datagram.");

                        if (n->id.port_id)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Duplicate port ID field, ignoring datagram.");

                        n->id.port_id = memdup(p, length);
                        if (!n->id.port_id)
                                return log_oom_debug();

                        n->id.port_id_size = length;
                        break;

                case SD_LLDP_TYPE_TTL:
                        if (length != 2)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "TTL field has wrong size, ignoring datagram.");

                        if (n->has_ttl)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Duplicate TTL field, ignoring datagram.");

                        n->ttl = unaligned_read_be16(p);
                        n->has_ttl = true;
                        break;

                case SD_LLDP_TYPE_PORT_DESCRIPTION:
                        r = parse_string(n->lldp_rx, &n->port_description, p, length);
                        if (r < 0)
                                return r;
                        break;

                case SD_LLDP_TYPE_SYSTEM_NAME:
                        r = parse_string(n->lldp_rx, &n->system_name, p, length);
                        if (r < 0)
                                return r;
                        break;

                case SD_LLDP_TYPE_SYSTEM_DESCRIPTION:
                        r = parse_string(n->lldp_rx, &n->system_description, p, length);
                        if (r < 0)
                                return r;
                        break;

                case SD_LLDP_TYPE_SYSTEM_CAPABILITIES:
                        if (length != 4)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "System capabilities field has wrong size.");

                        n->system_capabilities = unaligned_read_be16(p);
                        n->enabled_capabilities = unaligned_read_be16(p + 2);
                        n->has_capabilities = true;
                        break;

                case SD_LLDP_TYPE_PRIVATE:
                        if (length < 4)
                                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                                         "Found private TLV that is too short, ignoring.");

                        /* RFC 8520: MUD URL */
                        if (memcmp(p, SD_LLDP_OUI_IANA_MUD, sizeof(SD_LLDP_OUI_IANA_MUD)) == 0) {
                                r = parse_string(n->lldp_rx, &n->mud_url, p + sizeof(SD_LLDP_OUI_IANA_MUD),
                                                 length - sizeof(SD_LLDP_OUI_IANA_MUD));
                                if (r < 0)
                                        return r;
                        }
                        break;
                }

                p += length, left -= length;
        }

end_marker:
        if (!n->id.chassis_id || !n->id.port_id || !n->has_ttl)
                return log_lldp_rx_errno(n->lldp_rx, SYNTHETIC_ERRNO(EBADMSG),
                                         "One or more mandatory TLV missing in datagram. Ignoring.");

        n->rindex = sizeof(struct ether_header);

        return 0;
}

void lldp_neighbor_start_ttl(sd_lldp_neighbor *n) {
        assert(n);

        if (n->ttl > 0) {
                usec_t base;

                /* Use the packet's timestamp if there is one known */
                base = triple_timestamp_by_clock(&n->timestamp, CLOCK_BOOTTIME);
                if (!timestamp_is_set(base))
                        base = now(CLOCK_BOOTTIME); /* Otherwise, take the current time */

                n->until = usec_add(base, n->ttl * USEC_PER_SEC);
        } else
                n->until = 0;

        if (n->lldp_rx)
                prioq_reshuffle(n->lldp_rx->neighbor_by_expiry, n, &n->prioq_idx);
}

bool lldp_neighbor_equal(const sd_lldp_neighbor *a, const sd_lldp_neighbor *b) {
        if (a == b)
                return true;

        if (!a || !b)
                return false;

        if (a->raw_size != b->raw_size)
                return false;

        return memcmp(LLDP_NEIGHBOR_RAW(a), LLDP_NEIGHBOR_RAW(b), a->raw_size) == 0;
}

int sd_lldp_neighbor_get_source_address(sd_lldp_neighbor *n, struct ether_addr* address) {
        assert_return(n, -EINVAL);
        assert_return(address, -EINVAL);

        *address = n->source_address;
        return 0;
}

int sd_lldp_neighbor_get_destination_address(sd_lldp_neighbor *n, struct ether_addr* address) {
        assert_return(n, -EINVAL);
        assert_return(address, -EINVAL);

        *address = n->destination_address;
        return 0;
}

int sd_lldp_neighbor_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        *ret = LLDP_NEIGHBOR_RAW(n);
        *size = n->raw_size;

        return 0;
}

int sd_lldp_neighbor_get_chassis_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size) {
        assert_return(n, -EINVAL);
        assert_return(type, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        assert(n->id.chassis_id_size > 0);

        *type = *(uint8_t*) n->id.chassis_id;
        *ret = (uint8_t*) n->id.chassis_id + 1;
        *size = n->id.chassis_id_size - 1;

        return 0;
}

static int format_mac_address(const void *data, size_t sz, char **ret) {
        struct ether_addr a;
        char *k;

        assert(data || sz <= 0);

        if (sz != 7)
                return 0;

        memcpy(&a, (uint8_t*) data + 1, sizeof(a));

        k = new(char, ETHER_ADDR_TO_STRING_MAX);
        if (!k)
                return -ENOMEM;

        *ret = ether_addr_to_string(&a, k);
        return 1;
}

static int format_network_address(const void *data, size_t sz, char **ret) {
        union in_addr_union a;
        int family, r;

        if (sz == 6 && ((uint8_t*) data)[1] == 1) {
                memcpy(&a.in, (uint8_t*) data + 2, sizeof(a.in));
                family = AF_INET;
        } else if (sz == 18 && ((uint8_t*) data)[1] == 2) {
                memcpy(&a.in6, (uint8_t*) data + 2, sizeof(a.in6));
                family = AF_INET6;
        } else
                return 0;

        r = in_addr_to_string(family, &a, ret);
        if (r < 0)
                return r;
        return 1;
}

int sd_lldp_neighbor_get_chassis_id_as_string(sd_lldp_neighbor *n, const char **ret) {
        char *k;
        int r;

        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (n->chassis_id_as_string) {
                *ret = n->chassis_id_as_string;
                return 0;
        }

        assert(n->id.chassis_id_size > 0);

        switch (*(uint8_t*) n->id.chassis_id) {

        case SD_LLDP_CHASSIS_SUBTYPE_CHASSIS_COMPONENT:
        case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_ALIAS:
        case SD_LLDP_CHASSIS_SUBTYPE_PORT_COMPONENT:
        case SD_LLDP_CHASSIS_SUBTYPE_INTERFACE_NAME:
        case SD_LLDP_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED:
                k = cescape_length((char*) n->id.chassis_id + 1, n->id.chassis_id_size - 1);
                if (!k)
                        return -ENOMEM;

                goto done;

        case SD_LLDP_CHASSIS_SUBTYPE_MAC_ADDRESS:
                r = format_mac_address(n->id.chassis_id, n->id.chassis_id_size, &k);
                if (r < 0)
                        return r;
                if (r > 0)
                        goto done;

                break;

        case SD_LLDP_CHASSIS_SUBTYPE_NETWORK_ADDRESS:
                r = format_network_address(n->id.chassis_id, n->id.chassis_id_size, &k);
                if (r < 0)
                        return r;
                if (r > 0)
                        goto done;

                break;
        }

        /* Generic fallback */
        k = hexmem(n->id.chassis_id, n->id.chassis_id_size);
        if (!k)
                return -ENOMEM;

done:
        *ret = n->chassis_id_as_string = k;
        return 0;
}

int sd_lldp_neighbor_get_port_id(sd_lldp_neighbor *n, uint8_t *type, const void **ret, size_t *size) {
        assert_return(n, -EINVAL);
        assert_return(type, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        assert(n->id.port_id_size > 0);

        *type = *(uint8_t*) n->id.port_id;
        *ret = (uint8_t*) n->id.port_id + 1;
        *size = n->id.port_id_size - 1;

        return 0;
}

int sd_lldp_neighbor_get_port_id_as_string(sd_lldp_neighbor *n, const char **ret) {
        char *k;
        int r;

        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (n->port_id_as_string) {
                *ret = n->port_id_as_string;
                return 0;
        }

        assert(n->id.port_id_size > 0);

        switch (*(uint8_t*) n->id.port_id) {

        case SD_LLDP_PORT_SUBTYPE_INTERFACE_ALIAS:
        case SD_LLDP_PORT_SUBTYPE_PORT_COMPONENT:
        case SD_LLDP_PORT_SUBTYPE_INTERFACE_NAME:
        case SD_LLDP_PORT_SUBTYPE_LOCALLY_ASSIGNED:
                k = cescape_length((char*) n->id.port_id + 1, n->id.port_id_size - 1);
                if (!k)
                        return -ENOMEM;

                goto done;

        case SD_LLDP_PORT_SUBTYPE_MAC_ADDRESS:
                r = format_mac_address(n->id.port_id, n->id.port_id_size, &k);
                if (r < 0)
                        return r;
                if (r > 0)
                        goto done;

                break;

        case SD_LLDP_PORT_SUBTYPE_NETWORK_ADDRESS:
                r = format_network_address(n->id.port_id, n->id.port_id_size, &k);
                if (r < 0)
                        return r;
                if (r > 0)
                        goto done;

                break;
        }

        /* Generic fallback */
        k = hexmem(n->id.port_id, n->id.port_id_size);
        if (!k)
                return -ENOMEM;

done:
        *ret = n->port_id_as_string = k;
        return 0;
}

int sd_lldp_neighbor_get_ttl(sd_lldp_neighbor *n, uint16_t *ret_sec) {
        assert_return(n, -EINVAL);
        assert_return(ret_sec, -EINVAL);

        *ret_sec = n->ttl;
        return 0;
}

int sd_lldp_neighbor_get_system_name(sd_lldp_neighbor *n, const char **ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->system_name)
                return -ENODATA;

        *ret = n->system_name;
        return 0;
}

int sd_lldp_neighbor_get_system_description(sd_lldp_neighbor *n, const char **ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->system_description)
                return -ENODATA;

        *ret = n->system_description;
        return 0;
}

int sd_lldp_neighbor_get_port_description(sd_lldp_neighbor *n, const char **ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->port_description)
                return -ENODATA;

        *ret = n->port_description;
        return 0;
}

int sd_lldp_neighbor_get_mud_url(sd_lldp_neighbor *n, const char **ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->mud_url)
                return -ENODATA;

        *ret = n->mud_url;
        return 0;
}

int sd_lldp_neighbor_get_system_capabilities(sd_lldp_neighbor *n, uint16_t *ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->has_capabilities)
                return -ENODATA;

        *ret = n->system_capabilities;
        return 0;
}

int sd_lldp_neighbor_get_enabled_capabilities(sd_lldp_neighbor *n, uint16_t *ret) {
        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);

        if (!n->has_capabilities)
                return -ENODATA;

        *ret = n->enabled_capabilities;
        return 0;
}

int sd_lldp_neighbor_from_raw(sd_lldp_neighbor **ret, const void *raw, size_t raw_size) {
        _cleanup_(sd_lldp_neighbor_unrefp) sd_lldp_neighbor *n = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(raw || raw_size <= 0, -EINVAL);

        n = lldp_neighbor_new(raw_size);
        if (!n)
                return -ENOMEM;

        memcpy_safe(LLDP_NEIGHBOR_RAW(n), raw, raw_size);

        r = lldp_neighbor_parse(n);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(n);

        return r;
}

int sd_lldp_neighbor_tlv_rewind(sd_lldp_neighbor *n) {
        assert_return(n, -EINVAL);

        assert(n->raw_size >= sizeof(struct ether_header));
        n->rindex = sizeof(struct ether_header);

        return n->rindex < n->raw_size;
}

int sd_lldp_neighbor_tlv_next(sd_lldp_neighbor *n) {
        size_t length;

        assert_return(n, -EINVAL);

        if (n->rindex == n->raw_size) /* EOF */
                return -ESPIPE;

        if (n->rindex + 2 > n->raw_size) /* Truncated message */
                return -EBADMSG;

        length = LLDP_NEIGHBOR_TLV_LENGTH(n);
        if (n->rindex + 2 + length > n->raw_size)
                return -EBADMSG;

        n->rindex += 2 + length;
        return n->rindex < n->raw_size;
}

int sd_lldp_neighbor_tlv_get_type(sd_lldp_neighbor *n, uint8_t *type) {
        assert_return(n, -EINVAL);
        assert_return(type, -EINVAL);

        if (n->rindex == n->raw_size) /* EOF */
                return -ESPIPE;

        if (n->rindex + 2 > n->raw_size)
                return -EBADMSG;

        *type = LLDP_NEIGHBOR_TLV_TYPE(n);
        return 0;
}

int sd_lldp_neighbor_tlv_is_type(sd_lldp_neighbor *n, uint8_t type) {
        uint8_t k;
        int r;

        assert_return(n, -EINVAL);

        r = sd_lldp_neighbor_tlv_get_type(n, &k);
        if (r < 0)
                return r;

        return type == k;
}

int sd_lldp_neighbor_tlv_get_oui(sd_lldp_neighbor *n, uint8_t oui[_SD_ARRAY_STATIC 3], uint8_t *subtype) {
        const uint8_t *d;
        size_t length;
        int r;

        assert_return(n, -EINVAL);
        assert_return(oui, -EINVAL);
        assert_return(subtype, -EINVAL);

        r = sd_lldp_neighbor_tlv_is_type(n, SD_LLDP_TYPE_PRIVATE);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENXIO;

        length = LLDP_NEIGHBOR_TLV_LENGTH(n);
        if (length < 4)
                return -EBADMSG;

        if (n->rindex + 2 + length > n->raw_size)
                return -EBADMSG;

        d = LLDP_NEIGHBOR_TLV_DATA(n);
        memcpy(oui, d, 3);
        *subtype = d[3];

        return 0;
}

int sd_lldp_neighbor_tlv_is_oui(sd_lldp_neighbor *n, const uint8_t oui[_SD_ARRAY_STATIC 3], uint8_t subtype) {
        uint8_t k[3], st;
        int r;

        r = sd_lldp_neighbor_tlv_get_oui(n, k, &st);
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return r;

        return memcmp(k, oui, 3) == 0 && st == subtype;
}

int sd_lldp_neighbor_tlv_get_raw(sd_lldp_neighbor *n, const void **ret, size_t *size) {
        size_t length;

        assert_return(n, -EINVAL);
        assert_return(ret, -EINVAL);
        assert_return(size, -EINVAL);

        /* Note that this returns the full TLV, including the TLV header */

        if (n->rindex + 2 > n->raw_size)
                return -EBADMSG;

        length = LLDP_NEIGHBOR_TLV_LENGTH(n);
        if (n->rindex + 2 + length > n->raw_size)
                return -EBADMSG;

        *ret = (uint8_t*) LLDP_NEIGHBOR_RAW(n) + n->rindex;
        *size = length + 2;

        return 0;
}

int sd_lldp_neighbor_get_timestamp(sd_lldp_neighbor *n, clockid_t clock, uint64_t *ret) {
        assert_return(n, -EINVAL);
        assert_return(TRIPLE_TIMESTAMP_HAS_CLOCK(clock), -EOPNOTSUPP);
        assert_return(clock_supported(clock), -EOPNOTSUPP);
        assert_return(ret, -EINVAL);

        if (!triple_timestamp_is_set(&n->timestamp))
                return -ENODATA;

        *ret = triple_timestamp_by_clock(&n->timestamp, clock);
        return 0;
}
