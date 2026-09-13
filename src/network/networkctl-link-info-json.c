/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-client-id.h"
#include "sd-json.h"

#include "iovec-util.h"
#include "json-util.h"
#include "networkctl-link-info.h"
#include "networkctl-link-info-json.h"
#include "networkctl-util.h"
#include "time-util.h"

static int acquire_link_bitrates(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "BitRates"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "TxBitRate", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, tx_bitrate), SD_JSON_MANDATORY },
                { "RxBitRate", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, rx_bitrate), SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table,
                             SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS,
                             link);
        if (r < 0)
                return r;

        link->has_bitrates = true;
        return 0;
}

static int acquire_link_dhcp_client(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv4Client", "ClientIdentifier"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        _cleanup_(iovec_done) struct iovec iov = {};
        r = json_dispatch_byte_array_iovec("ClientIdentifier", v, /* flags= */ 0, &iov);
        if (r < 0)
                return r;

        return sd_dhcp_client_id_set_raw(&link->dhcp_client_id, iov.iov_base, iov.iov_len);
}

static int acquire_link_dhcp_states(LinkInfo *link) {
        int r;

        assert(link);

        static const sd_json_dispatch_field dhcp4_dispatch_table[] = {
                { "State", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(LinkInfo, dhcp4_client_state), 0 },
                {}
        }, dhcp6_dispatch_table[] = {
                { "State", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(LinkInfo, dhcp6_client_state), 0 },
                {}
        };

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv4Client"), &v);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r >= 0)
                (void) sd_json_dispatch(v, dhcp4_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv6Client"), &v);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r >= 0)
                (void) sd_json_dispatch(v, dhcp6_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        return 0;
}

static int acquire_link_dhcp_lease_timestamps(LinkInfo *link) {
        int r;

        assert(link);

        static const sd_json_dispatch_field dhcp4_dispatch_table[] = {
                { "LeaseTimestampUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, dhcp4_lease_timestamp), 0 },
                {}
        }, dhcp6_dispatch_table[] = {
                { "LeaseTimestampUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, dhcp6_lease_timestamp), 0 },
                {}
        };

        link->dhcp4_lease_timestamp = USEC_INFINITY;
        link->dhcp6_lease_timestamp = USEC_INFINITY;

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv4Client", "Lease"), &v);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r >= 0)
                (void) sd_json_dispatch(v, dhcp4_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv6Client", "Lease"), &v);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r >= 0)
                (void) sd_json_dispatch(v, dhcp6_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        /* The timestamps in the JSON data are based on CLOCK_BOOTTIME, but the table display needs
         * wallclock time. */
        if (link->dhcp4_lease_timestamp != USEC_INFINITY)
                link->dhcp4_lease_timestamp = map_clock_usec(link->dhcp4_lease_timestamp, CLOCK_BOOTTIME, CLOCK_REALTIME);

        if (link->dhcp6_lease_timestamp != USEC_INFINITY)
                link->dhcp6_lease_timestamp = map_clock_usec(link->dhcp6_lease_timestamp, CLOCK_BOOTTIME, CLOCK_REALTIME);

        return 0;
}

static int acquire_link_dhcp_message(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv4Client", "Lease", "Message"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return dhcp_message_parse_json(v, &link->dhcp_message);
}

int link_info_parse_description(LinkInfo *link, sd_varlink *vl) {
        int r;

        assert(link);

        if (!vl)
                return 0;

        r = acquire_link_description(vl, link->ifindex, &link->description);
        if (r < 0)
                return r;

        (void) acquire_link_bitrates(link);
        (void) acquire_link_dhcp_client(link);
        (void) acquire_link_dhcp_message(link);
        (void) acquire_link_dhcp_states(link);
        (void) acquire_link_dhcp_lease_timestamps(link);

        return 0;
}
