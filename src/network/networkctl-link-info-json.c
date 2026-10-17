/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-dhcp-client-id.h"
#include "sd-json.h"

#include "iovec-util.h"
#include "json-util.h"
#include "networkctl-link-info.h"
#include "networkctl-link-info-json.h"
#include "networkctl-util.h"

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

static JSON_DISPATCH_ENUM_DEFINE(dispatch_link_configuring_reason, LinkConfiguringReason, link_configuring_reason_from_string);

static int acquire_link_configuring_reason(LinkInfo *link) {
        int r;

        assert(link);

        sd_json_variant *v;
        r = json_variant_find_object(link->description, STRV_MAKE("Interface", "ConfiguringReason"), &v);
        if (r == -ENODATA)
                return 0;
        if (r < 0)
                return r;

        return dispatch_link_configuring_reason("ConfiguringReason", v, /* flags= */ 0,
                                                &link->configuring_reason);
}

int link_info_parse_description(LinkInfo *link, sd_varlink *vl) {
        int r;

        assert(link);

        link->configuring_reason = _LINK_CONFIGURING_REASON_INVALID;

        if (!vl)
                return 0;

        r = acquire_link_description(vl, link->ifindex, &link->description);
        if (r < 0)
                return r;

        (void) acquire_link_bitrates(link);
        (void) acquire_link_dhcp_client(link);
        (void) acquire_link_dhcp_message(link);
        (void) acquire_link_configuring_reason(link);

        return 0;
}
