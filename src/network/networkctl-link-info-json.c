/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-client-id.h"
#include "sd-json.h"

#include "iovec-util.h"
#include "json-util.h"
#include "networkctl-link-info.h"
#include "networkctl-link-info-json.h"
#include "networkctl-util.h"
#include "networkd-link.h"
#include "strv.h"
#include "time-util.h"

static JSON_DISPATCH_ENUM_DEFINE(dispatch_dhcp_state, DHCPState, dhcp_state_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_dhcp6_state, DHCP6State, dhcp6_state_from_string);

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

static int acquire_link_dhcp4_client_info(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv4Client"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        static const sd_json_dispatch_field state_dispatch_table[] = {
                { "State", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_dhcp_state, offsetof(LinkInfo, dhcp4_client_state), 0 },
                {}
        };
        (void) sd_json_dispatch(v, state_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        sd_json_variant *lease;
        r = json_variant_find_object(v, STRV_MAKE("Lease"), &lease);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        static const sd_json_dispatch_field lease_dispatch_table[] = {
                { "LeaseTimestampUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, dhcp4_lease_timestamp), 0 },
                {}
        };
        (void) sd_json_dispatch(lease, lease_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        /* The timestamp in the JSON data is based on CLOCK_BOOTTIME, but the table display needs
         * wallclock time. */
        if (link->dhcp4_lease_timestamp != USEC_INFINITY)
                link->dhcp4_lease_timestamp = map_clock_usec(link->dhcp4_lease_timestamp, CLOCK_BOOTTIME, CLOCK_REALTIME);

        return 0;
}

static int acquire_link_dhcp6_client_info(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "DHCPv6Client"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        static const sd_json_dispatch_field state_dispatch_table[] = {
                { "State", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_dhcp6_state, offsetof(LinkInfo, dhcp6_client_state), 0 },
                {}
        };
        (void) sd_json_dispatch(v, state_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        sd_json_variant *lease;
        r = json_variant_find_object(v, STRV_MAKE("Lease"), &lease);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        static const sd_json_dispatch_field lease_dispatch_table[] = {
                { "LeaseTimestampUSec", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(LinkInfo, dhcp6_lease_timestamp), 0 },
                {}
        };
        (void) sd_json_dispatch(lease, lease_dispatch_table, SD_JSON_LOG | SD_JSON_WARNING | SD_JSON_ALLOW_EXTENSIONS, link);

        /* The timestamp in the JSON data is based on CLOCK_BOOTTIME, but the table display needs
         * wallclock time. */
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

static int acquire_link_configuring_reasons(LinkInfo *link) {
        _cleanup_strv_free_ char **ids = NULL, **reasons = NULL;
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "ConfiguringReasons"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        r = sd_json_dispatch_strv("ConfiguringReasons", v, /* flags= */ 0, &ids);
        if (r < 0)
                return r;

        STRV_FOREACH(id, ids) {
                /* The IDs are underscorified in the JSON output. */
                LinkConfiguringReason reason = link_configuring_reason_from_string(json_dashify(*id));

                /* Show the ID as is, if the reason is unknown to this version. */
                r = strv_extend(&reasons, reason >= 0 ? link_configuring_reason_message_to_string(reason) : *id);
                if (r < 0)
                        return r;
        }

        return strv_free_and_replace(link->configuring_reasons, reasons);
}

int link_info_parse_description(LinkInfo *link, sd_varlink *vl) {
        int r;

        assert(link);

        link->dhcp4_client_state = _DHCP_STATE_INVALID;
        link->dhcp6_client_state = _DHCP6_STATE_INVALID;
        link->dhcp4_lease_timestamp = USEC_INFINITY;
        link->dhcp6_lease_timestamp = USEC_INFINITY;

        if (!vl)
                return 0;

        r = acquire_link_description(vl, link->ifindex, &link->description);
        if (r < 0)
                return r;

        (void) acquire_link_bitrates(link);
        (void) acquire_link_dhcp_client(link);
        (void) acquire_link_dhcp4_client_info(link);
        (void) acquire_link_dhcp_message(link);
        (void) acquire_link_dhcp6_client_info(link);
        (void) acquire_link_configuring_reasons(link);

        return 0;
}
