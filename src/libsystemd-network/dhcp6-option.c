/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <netinet/in.h>

#include "sd-dhcp6-client.h"

#include "alloc-util.h"
#include "dhcp6-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "dns-domain.h"
#include "escape.h"
#include "memory-util.h"
#include "network-common.h"
#include "strv.h"
#include "unaligned.h"

#define DHCP6_OPTION_IA_NA_LEN (sizeof(struct ia_na))
#define DHCP6_OPTION_IA_PD_LEN (sizeof(struct ia_pd))
#define DHCP6_OPTION_IA_TA_LEN (sizeof(struct ia_ta))

bool dhcp6_option_can_request(uint16_t option) {
        /* See Client ORO field in
         * https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-2 */

        switch (option) {
        case SD_DHCP6_OPTION_CLIENTID:
        case SD_DHCP6_OPTION_SERVERID:
        case SD_DHCP6_OPTION_IA_NA:
        case SD_DHCP6_OPTION_IA_TA:
        case SD_DHCP6_OPTION_IAADDR:
        case SD_DHCP6_OPTION_ORO:
        case SD_DHCP6_OPTION_PREFERENCE:
        case SD_DHCP6_OPTION_ELAPSED_TIME:
        case SD_DHCP6_OPTION_RELAY_MSG:
        case SD_DHCP6_OPTION_AUTH:
        case SD_DHCP6_OPTION_UNICAST:
        case SD_DHCP6_OPTION_STATUS_CODE:
        case SD_DHCP6_OPTION_RAPID_COMMIT:
        case SD_DHCP6_OPTION_USER_CLASS:
        case SD_DHCP6_OPTION_VENDOR_CLASS:
                return false;
        case SD_DHCP6_OPTION_VENDOR_OPTS:
                return true;
        case SD_DHCP6_OPTION_INTERFACE_ID:
        case SD_DHCP6_OPTION_RECONF_MSG:
        case SD_DHCP6_OPTION_RECONF_ACCEPT:
                return false;
        case SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME:
        case SD_DHCP6_OPTION_SIP_SERVER_ADDRESS:
        case SD_DHCP6_OPTION_DNS_SERVER:
        case SD_DHCP6_OPTION_DOMAIN:
                return true;
        case SD_DHCP6_OPTION_IA_PD:
        case SD_DHCP6_OPTION_IA_PD_PREFIX:
                return false;
        case SD_DHCP6_OPTION_NIS_SERVER:
        case SD_DHCP6_OPTION_NISP_SERVER:
        case SD_DHCP6_OPTION_NIS_DOMAIN_NAME:
        case SD_DHCP6_OPTION_NISP_DOMAIN_NAME:
        case SD_DHCP6_OPTION_SNTP_SERVER:
                return true;
        case SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME:
                return false; /* This is automatically set when sending INFORMATION_REQUEST message. */
        case SD_DHCP6_OPTION_BCMCS_SERVER_D:
        case SD_DHCP6_OPTION_BCMCS_SERVER_A:
        case SD_DHCP6_OPTION_GEOCONF_CIVIC:
                return true;
        case SD_DHCP6_OPTION_REMOTE_ID:
        case SD_DHCP6_OPTION_SUBSCRIBER_ID:
                return false;
        case SD_DHCP6_OPTION_CLIENT_FQDN:
        case SD_DHCP6_OPTION_PANA_AGENT:
        case SD_DHCP6_OPTION_POSIX_TIMEZONE:
        case SD_DHCP6_OPTION_TZDB_TIMEZONE:
                return true;
        case SD_DHCP6_OPTION_ERO:
        case SD_DHCP6_OPTION_LQ_QUERY:
        case SD_DHCP6_OPTION_CLIENT_DATA:
        case SD_DHCP6_OPTION_CLT_TIME:
        case SD_DHCP6_OPTION_LQ_RELAY_DATA:
        case SD_DHCP6_OPTION_LQ_CLIENT_LINK:
                return false;
        case SD_DHCP6_OPTION_MIP6_HNIDF:
        case SD_DHCP6_OPTION_MIP6_VDINF:
        case SD_DHCP6_OPTION_V6_LOST:
        case SD_DHCP6_OPTION_CAPWAP_AC_V6:
                return true;
        case SD_DHCP6_OPTION_RELAY_ID:
                return false;
        case SD_DHCP6_OPTION_IPV6_ADDRESS_MOS:
        case SD_DHCP6_OPTION_IPV6_FQDN_MOS:
        case SD_DHCP6_OPTION_NTP_SERVER:
        case SD_DHCP6_OPTION_V6_ACCESS_DOMAIN:
        case SD_DHCP6_OPTION_SIP_UA_CS_LIST:
        case SD_DHCP6_OPTION_BOOTFILE_URL:
        case SD_DHCP6_OPTION_BOOTFILE_PARAM:
                return true;
        case SD_DHCP6_OPTION_CLIENT_ARCH_TYPE:
                return false;
        case SD_DHCP6_OPTION_NII:
        case SD_DHCP6_OPTION_GEOLOCATION:
        case SD_DHCP6_OPTION_AFTR_NAME:
        case SD_DHCP6_OPTION_ERP_LOCAL_DOMAIN_NAME:
                return true;
        case SD_DHCP6_OPTION_RSOO:
                return false;
        case SD_DHCP6_OPTION_PD_EXCLUDE:
                return true;
        case SD_DHCP6_OPTION_VSS:
                return false;
        case SD_DHCP6_OPTION_MIP6_IDINF:
        case SD_DHCP6_OPTION_MIP6_UDINF:
        case SD_DHCP6_OPTION_MIP6_HNP:
        case SD_DHCP6_OPTION_MIP6_HAA:
        case SD_DHCP6_OPTION_MIP6_HAF:
        case SD_DHCP6_OPTION_RDNSS_SELECTION:
        case SD_DHCP6_OPTION_KRB_PRINCIPAL_NAME:
        case SD_DHCP6_OPTION_KRB_REALM_NAME:
        case SD_DHCP6_OPTION_KRB_DEFAULT_REALM_NAME:
        case SD_DHCP6_OPTION_KRB_KDC:
                return true;
        case SD_DHCP6_OPTION_CLIENT_LINKLAYER_ADDR:
        case SD_DHCP6_OPTION_LINK_ADDRESS:
        case SD_DHCP6_OPTION_RADIUS:
        case SD_DHCP6_OPTION_SOL_MAX_RT: /* Automatically set when sending SOLICIT message. */
        case SD_DHCP6_OPTION_INF_MAX_RT: /* Automatically set when sending INFORMATION_REQUEST message. */
                return false;
        case SD_DHCP6_OPTION_ADDRSEL:
        case SD_DHCP6_OPTION_ADDRSEL_TABLE:
        case SD_DHCP6_OPTION_V6_PCP_SERVER:
                return true;
        case SD_DHCP6_OPTION_DHCPV4_MSG:
                return false;
        case SD_DHCP6_OPTION_DHCP4_O_DHCP6_SERVER:
                return true;
        case SD_DHCP6_OPTION_S46_RULE:
                return false;
        case SD_DHCP6_OPTION_S46_BR:
                return true;
        case SD_DHCP6_OPTION_S46_DMR:
        case SD_DHCP6_OPTION_S46_V4V6BIND:
        case SD_DHCP6_OPTION_S46_PORTPARAMS:
                return false;
        case SD_DHCP6_OPTION_S46_CONT_MAPE:
        case SD_DHCP6_OPTION_S46_CONT_MAPT:
        case SD_DHCP6_OPTION_S46_CONT_LW:
        case SD_DHCP6_OPTION_4RD:
        case SD_DHCP6_OPTION_4RD_MAP_RULE:
        case SD_DHCP6_OPTION_4RD_NON_MAP_RULE:
                return true;
        case SD_DHCP6_OPTION_LQ_BASE_TIME:
        case SD_DHCP6_OPTION_LQ_START_TIME:
        case SD_DHCP6_OPTION_LQ_END_TIME:
                return false;
        case SD_DHCP6_OPTION_CAPTIVE_PORTAL:
        case SD_DHCP6_OPTION_MPL_PARAMETERS:
                return true;
        case SD_DHCP6_OPTION_ANI_ATT:
        case SD_DHCP6_OPTION_ANI_NETWORK_NAME:
        case SD_DHCP6_OPTION_ANI_AP_NAME:
        case SD_DHCP6_OPTION_ANI_AP_BSSID:
        case SD_DHCP6_OPTION_ANI_OPERATOR_ID:
        case SD_DHCP6_OPTION_ANI_OPERATOR_REALM:
                return false;
        case SD_DHCP6_OPTION_S46_PRIORITY:
                return true;
        case SD_DHCP6_OPTION_MUD_URL_V6:
                return false;
        case SD_DHCP6_OPTION_V6_PREFIX64:
                return true;
        case SD_DHCP6_OPTION_F_BINDING_STATUS:
        case SD_DHCP6_OPTION_F_CONNECT_FLAGS:
        case SD_DHCP6_OPTION_F_DNS_REMOVAL_INFO:
        case SD_DHCP6_OPTION_F_DNS_HOST_NAME:
        case SD_DHCP6_OPTION_F_DNS_ZONE_NAME:
        case SD_DHCP6_OPTION_F_DNS_FLAGS:
        case SD_DHCP6_OPTION_F_EXPIRATION_TIME:
        case SD_DHCP6_OPTION_F_MAX_UNACKED_BNDUPD:
        case SD_DHCP6_OPTION_F_MCLT:
        case SD_DHCP6_OPTION_F_PARTNER_LIFETIME:
        case SD_DHCP6_OPTION_F_PARTNER_LIFETIME_SENT:
        case SD_DHCP6_OPTION_F_PARTNER_DOWN_TIME:
        case SD_DHCP6_OPTION_F_PARTNER_RAW_CLT_TIME:
        case SD_DHCP6_OPTION_F_PROTOCOL_VERSION:
        case SD_DHCP6_OPTION_F_KEEPALIVE_TIME:
        case SD_DHCP6_OPTION_F_RECONFIGURE_DATA:
        case SD_DHCP6_OPTION_F_RELATIONSHIP_NAME:
        case SD_DHCP6_OPTION_F_SERVER_FLAGS:
        case SD_DHCP6_OPTION_F_SERVER_STATE:
        case SD_DHCP6_OPTION_F_START_TIME_OF_STATE:
        case SD_DHCP6_OPTION_F_STATE_EXPIRATION_TIME:
        case SD_DHCP6_OPTION_RELAY_PORT:
                return false;
        case SD_DHCP6_OPTION_V6_SZTP_REDIRECT:
        case SD_DHCP6_OPTION_S46_BIND_IPV6_PREFIX:
                return true;
        case SD_DHCP6_OPTION_IA_LL:
        case SD_DHCP6_OPTION_LLADDR:
        case SD_DHCP6_OPTION_SLAP_QUAD:
                return false;
        case SD_DHCP6_OPTION_V6_DOTS_RI:
        case SD_DHCP6_OPTION_V6_DOTS_ADDRESS:
        case SD_DHCP6_OPTION_IPV6_ADDRESS_ANDSF:
        case SD_DHCP6_OPTION_V6_DNR:
                return true;
        default:
                return false;
        }
}

static int option_append_hdr(uint8_t **buf, size_t *offset, uint16_t optcode, size_t optlen) {
        assert(buf);
        assert(*buf);
        assert(offset);

        if (optlen > 0xffff)
                return -ENOBUFS;

        if (optlen + offsetof(DHCP6Option, data) > SIZE_MAX - *offset)
                return -ENOBUFS;

        if (!GREEDY_REALLOC(*buf, *offset + optlen + offsetof(DHCP6Option, data)))
                return -ENOMEM;

        unaligned_write_be16(*buf + *offset + offsetof(DHCP6Option, code), optcode);
        unaligned_write_be16(*buf + *offset + offsetof(DHCP6Option, len), optlen);

        *offset += offsetof(DHCP6Option, data);
        return 0;
}

int dhcp6_option_append(
                uint8_t **buf,
                size_t *offset,
                uint16_t code,
                size_t optlen,
                const void *optval) {

        int r;

        assert(optval || optlen == 0);

        r = option_append_hdr(buf, offset, code, optlen);
        if (r < 0)
                return r;

        memcpy_safe(*buf + *offset, optval, optlen);
        *offset += optlen;

        return 0;
}

int dhcp6_option_append_vendor_option(uint8_t **buf, size_t *offset, OrderedSet *vendor_options) {
        sd_dhcp6_option *options;
        int r;

        assert(buf);
        assert(*buf);
        assert(offset);

        ORDERED_SET_FOREACH(options, vendor_options) {
                _cleanup_free_ uint8_t *p = NULL;
                size_t total;

                total = 4 + 2 + 2 + options->length;

                p = malloc(total);
                if (!p)
                        return -ENOMEM;

                unaligned_write_be32(p, options->enterprise_identifier);
                unaligned_write_be16(p + 4, options->option);
                unaligned_write_be16(p + 6, options->length);
                memcpy(p + 8, options->data, options->length);

                r = dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_VENDOR_OPTS, total, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int option_append_ia_address(uint8_t **buf, size_t *offset, const struct iaaddr *address) {
        assert(buf);
        assert(*buf);
        assert(offset);
        assert(address);

        /* Do not append T1 and T2. */
        const struct iaaddr a = {
                .address = address->address,
        };

        return dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_IAADDR, sizeof(struct iaaddr), &a);
}

static int option_append_pd_prefix(uint8_t **buf, size_t *offset, const struct iapdprefix *prefix) {
        assert(buf);
        assert(*buf);
        assert(offset);
        assert(prefix);

        if (prefix->prefixlen == 0)
                return -EINVAL;

        /* Do not append T1 and T2. */
        const struct iapdprefix p = {
                .prefixlen = prefix->prefixlen,
                .address = prefix->address,
        };

        return dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_IA_PD_PREFIX, sizeof(struct iapdprefix), &p);
}

int dhcp6_option_append_ia(uint8_t **buf, size_t *offset, const DHCP6IA *ia) {
        _cleanup_free_ uint8_t *data = NULL;
        struct ia_header header;
        size_t len;
        int r;

        assert(buf);
        assert(*buf);
        assert(offset);
        assert(ia);

        /* client should not send set T1 and T2. See, RFC 8415, and issue #18090. */

        switch (ia->type) {
        case SD_DHCP6_OPTION_IA_NA:
        case SD_DHCP6_OPTION_IA_PD:
                len = sizeof(struct ia_header);
                header = (struct ia_header) {
                        .id = ia->header.id,
                };
                break;

        case SD_DHCP6_OPTION_IA_TA:
                len = sizeof(header.id); /* IA_TA does not have lifetime. */
                header = (struct ia_header) {
                        .id = ia->header.id,
                };
                break;

        default:
                assert_not_reached();
        }

        if (!GREEDY_REALLOC(data, len))
                return -ENOMEM;

        memcpy(data, &header, len);

        LIST_FOREACH(addresses, addr, ia->addresses) {
                if (ia->type == SD_DHCP6_OPTION_IA_PD)
                        r = option_append_pd_prefix(&data, &len, &addr->iapdprefix);
                else
                        r = option_append_ia_address(&data, &len, &addr->iaaddr);
                if (r < 0)
                        return r;
        }

        return dhcp6_option_append(buf, offset, ia->type, len, data);
}

int dhcp6_option_append_fqdn(uint8_t **buf, size_t *offset, const char *fqdn) {
        uint8_t buffer[1 + DNS_WIRE_FORMAT_HOSTNAME_MAX];
        int r;

        assert(buf);
        assert(*buf);
        assert(offset);

        if (isempty(fqdn))
                return 0;

        buffer[0] = DHCP6_FQDN_FLAG_S; /* Request server to perform AAAA RR DNS updates */

        /* Store domain name after flags field */
        r = dns_name_to_wire_format(fqdn, buffer + 1, sizeof(buffer) - 1, false);
        if (r <= 0)
                return r;

        /*
         * According to RFC 4704, chapter 4.2 only add terminating zero-length
         * label in case a FQDN is provided. Since dns_name_to_wire_format
         * always adds terminating zero-length label remove if only a hostname
         * is provided.
         */
        if (dns_name_is_single_label(fqdn))
                r--;

        return dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_CLIENT_FQDN, 1 + r, buffer);
}

int dhcp6_option_append_user_class(uint8_t **buf, size_t *offset, char * const *user_class) {
        _cleanup_free_ uint8_t *p = NULL;
        size_t n = 0;

        assert(buf);
        assert(*buf);
        assert(offset);

        if (strv_isempty(user_class))
                return 0;

        STRV_FOREACH(s, user_class) {
                size_t len = strlen(*s);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;

                if (!GREEDY_REALLOC(p, n + len + 2))
                        return -ENOMEM;

                unaligned_write_be16(p + n, len);
                memcpy(p + n + 2, *s, len);
                n += len + 2;
        }

        return dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_USER_CLASS, n, p);
}

int dhcp6_option_append_vendor_class(uint8_t **buf, size_t *offset, char * const *vendor_class) {
        _cleanup_free_ uint8_t *p = NULL;
        size_t n = 0;

        assert(buf);
        assert(*buf);
        assert(offset);

        if (strv_isempty(vendor_class))
                return 0;

        if (!GREEDY_REALLOC(p, sizeof(be32_t)))
                return -ENOMEM;

        /* Enterprise Identifier */
        unaligned_write_be32(p, SYSTEMD_PEN);
        n += sizeof(be32_t);

        STRV_FOREACH(s, vendor_class) {
                size_t len = strlen(*s);

                if (len > UINT16_MAX || len == 0)
                        return -EINVAL;

                if (!GREEDY_REALLOC(p, n + len + 2))
                        return -ENOMEM;

                unaligned_write_be16(p + n, len);
                memcpy(p + n + 2, *s, len);
                n += len + 2;
        }

        return dhcp6_option_append(buf, offset, SD_DHCP6_OPTION_VENDOR_CLASS, n, p);
}

int dhcp6_option_parse(
                const uint8_t *buf,
                size_t buflen,
                size_t *offset,
                uint16_t *ret_option_code,
                size_t *ret_option_data_len,
                const uint8_t **ret_option_data) {

        size_t len;

        assert(buf);
        assert(offset);
        assert(ret_option_code);
        assert(ret_option_data_len);
        assert(ret_option_data);

        if (buflen < offsetof(DHCP6Option, data))
                return -EBADMSG;

        if (*offset > buflen - offsetof(DHCP6Option, data))
                return -EBADMSG;

        len = unaligned_read_be16(buf + *offset + offsetof(DHCP6Option, len));

        if (len > buflen - offsetof(DHCP6Option, data) - *offset)
                return -EBADMSG;

        *ret_option_code = unaligned_read_be16(buf + *offset + offsetof(DHCP6Option, code));
        *ret_option_data_len = len;
        *ret_option_data = len == 0 ? NULL : buf + *offset + offsetof(DHCP6Option, data);
        *offset += offsetof(DHCP6Option, data) + len;

        return 0;
}

int dhcp6_option_parse_status(const uint8_t *data, size_t data_len, char **ret_status_message) {
        DHCP6Status status;

        assert(data || data_len == 0);

        if (data_len < sizeof(uint16_t))
                return -EBADMSG;

        status = unaligned_read_be16(data);

        if (ret_status_message) {
                _cleanup_free_ char *msg = NULL;
                const char *s;

                /* The status message MUST NOT be null-terminated. See section 21.13 of RFC8415.
                 * Let's escape unsafe characters for safety. */
                msg = cescape_length((const char*) (data + sizeof(uint16_t)), data_len - sizeof(uint16_t));
                if (!msg)
                        return -ENOMEM;

                s = dhcp6_message_status_to_string(status);
                if (s && !strextend_with_separator(&msg, ": ", s))
                        return -ENOMEM;

                *ret_status_message = TAKE_PTR(msg);
        }

        return status;
}

/* parse a string from dhcp option field. *ret must be initialized */
int dhcp6_option_parse_string(const uint8_t *data, size_t data_len, char **ret) {
        _cleanup_free_ char *string = NULL;
        int r;

        assert(data || data_len == 0);
        assert(ret);

        if (data_len <= 0) {
                *ret = mfree(*ret);
                return 0;
        }

        r = make_cstring((const char *) data, data_len, MAKE_CSTRING_REFUSE_TRAILING_NUL, &string);
        if (r < 0)
                return r;

        return free_and_replace(*ret, string);
}

static int dhcp6_option_parse_ia_options(sd_dhcp6_client *client, const uint8_t *buf, size_t buflen) {
        int r;

        assert(buf || buflen == 0);

        for (size_t offset = 0; offset < buflen;) {
                const uint8_t *data;
                size_t data_len;
                uint16_t code;

                r = dhcp6_option_parse(buf, buflen, &offset, &code, &data_len, &data);
                if (r < 0)
                        return r;

                switch (code) {
                case SD_DHCP6_OPTION_STATUS_CODE: {
                        _cleanup_free_ char *msg = NULL;

                        r = dhcp6_option_parse_status(data, data_len, &msg);
                        if (r == -ENOMEM)
                                return r;
                        if (r > 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                              "Received an IA address or PD prefix option with non-zero status%s%s",
                                                              isempty(msg) ? "." : ": ", strempty(msg));
                        if (r < 0)
                                /* Let's log but ignore the invalid status option. */
                                log_dhcp6_client_errno(client, r,
                                                       "Received an IA address or PD prefix option with an invalid status sub option, ignoring: %m");
                        break;
                }
                default:
                        log_dhcp6_client(client, "Received an unknown sub option %u in IA address or PD prefix, ignoring.", code);
                }
        }

        return 0;
}

static int dhcp6_option_parse_ia_address(sd_dhcp6_client *client, DHCP6IA *ia, const uint8_t *data, size_t len) {
        _cleanup_free_ DHCP6Address *a = NULL;
        usec_t lt_valid, lt_pref;
        int r;

        assert(ia);
        assert(data || len == 0);

        if (!IN_SET(ia->type, SD_DHCP6_OPTION_IA_NA, SD_DHCP6_OPTION_IA_TA))
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an IA address sub-option in an invalid option, ignoring.");

        if (len < sizeof(struct iaaddr))
                return -EBADMSG;

        a = new(DHCP6Address, 1);
        if (!a)
                return -ENOMEM;

        memcpy(&a->iaaddr, data, sizeof(struct iaaddr));

        lt_valid = be32_sec_to_usec(a->iaaddr.lifetime_valid, /* max_as_infinity = */ true);
        lt_pref = be32_sec_to_usec(a->iaaddr.lifetime_preferred, /* max_as_infinity = */ true);

        if (lt_valid == 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an IA address with zero valid lifetime, ignoring.");
        if (lt_pref > lt_valid)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an IA address with preferred lifetime %s "
                                              "larger than valid lifetime %s, ignoring.",
                                              FORMAT_TIMESPAN(lt_pref, USEC_PER_SEC),
                                              FORMAT_TIMESPAN(lt_valid, USEC_PER_SEC));

        if (len > sizeof(struct iaaddr)) {
                r = dhcp6_option_parse_ia_options(client, data + sizeof(struct iaaddr), len - sizeof(struct iaaddr));
                if (r < 0)
                        return r;
        }

        LIST_PREPEND(addresses, ia->addresses, TAKE_PTR(a));
        return 0;
}

static int dhcp6_option_parse_ia_pdprefix(sd_dhcp6_client *client, DHCP6IA *ia, const uint8_t *data, size_t len) {
        _cleanup_free_ DHCP6Address *a = NULL;
        usec_t lt_valid, lt_pref;
        int r;

        assert(ia);
        assert(data || len == 0);

        if (ia->type != SD_DHCP6_OPTION_IA_PD)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an PD prefix sub-option in an invalid option, ignoring");

        if (len < sizeof(struct iapdprefix))
                return -EBADMSG;

        a = new(DHCP6Address, 1);
        if (!a)
                return -ENOMEM;

        memcpy(&a->iapdprefix, data, sizeof(struct iapdprefix));

        lt_valid = be32_sec_to_usec(a->iapdprefix.lifetime_valid, /* max_as_infinity = */ true);
        lt_pref = be32_sec_to_usec(a->iapdprefix.lifetime_preferred, /* max_as_infinity = */ true);

        if (lt_valid == 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received a PD prefix with zero valid lifetime, ignoring.");
        if (lt_pref > lt_valid)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received a PD prefix with preferred lifetime %s "
                                              "larger than valid lifetime %s, ignoring.",
                                              FORMAT_TIMESPAN(lt_pref, USEC_PER_SEC),
                                              FORMAT_TIMESPAN(lt_valid, USEC_PER_SEC));

        if (len > sizeof(struct iapdprefix)) {
                r = dhcp6_option_parse_ia_options(client, data + sizeof(struct iapdprefix), len - sizeof(struct iapdprefix));
                if (r < 0)
                        return r;
        }

        LIST_PREPEND(addresses, ia->addresses, TAKE_PTR(a));
        return 0;
}

int dhcp6_option_parse_ia(
                sd_dhcp6_client *client,
                be32_t iaid,
                uint16_t option_code,
                size_t option_data_len,
                const uint8_t *option_data,
                DHCP6IA **ret) {

        _cleanup_(dhcp6_ia_freep) DHCP6IA *ia = NULL;
        usec_t lt_t1, lt_t2;
        size_t header_len;
        int r;

        assert(IN_SET(option_code, SD_DHCP6_OPTION_IA_NA, SD_DHCP6_OPTION_IA_TA, SD_DHCP6_OPTION_IA_PD));
        assert(option_data || option_data_len == 0);
        assert(ret);

        /* This will return the following:
         * -ENOMEM: memory allocation error,
         * -ENOANO: unmatching IAID,
         * -EINVAL: non-zero status code, or invalid lifetime,
         * -EBADMSG: invalid message format,
         * -ENODATA: no valid address or PD prefix,
         * 0: success. */

        switch (option_code) {
        case SD_DHCP6_OPTION_IA_NA:
        case SD_DHCP6_OPTION_IA_PD:
                header_len = sizeof(struct ia_header);
                break;

        case SD_DHCP6_OPTION_IA_TA:
                header_len = sizeof(be32_t); /* IA_TA does not have lifetime. */
                break;

        default:
                assert_not_reached();
        }

        if (option_data_len < header_len)
                return -EBADMSG;

        ia = new(DHCP6IA, 1);
        if (!ia)
                return -ENOMEM;

        *ia = (DHCP6IA) {
                .type = option_code,
        };
        memcpy(&ia->header, option_data, header_len);

        /* According to RFC8415, IAs which do not match the client's IAID should be ignored,
         * but not necessary to ignore or refuse the whole message. */
        if (ia->header.id != iaid)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(ENOANO),
                                              "Received an IA option with a different IAID "
                                              "from the one chosen by the client, ignoring.");

        /* It is not necessary to check if the lifetime_t2 is zero here, as in that case it will be updated later. */
        lt_t1 = be32_sec_to_usec(ia->header.lifetime_t1, /* max_as_infinity = */ true);
        lt_t2 = be32_sec_to_usec(ia->header.lifetime_t2, /* max_as_infinity = */ true);

        if (lt_t1 > lt_t2)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an IA option with T1 %s > T2 %s, ignoring.",
                                              FORMAT_TIMESPAN(lt_t1, USEC_PER_SEC),
                                              FORMAT_TIMESPAN(lt_t2, USEC_PER_SEC));
        if (lt_t1 == 0 && lt_t2 > 0)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                              "Received an IA option with zero T1 and non-zero T2 (%s), ignoring.",
                                              FORMAT_TIMESPAN(lt_t2, USEC_PER_SEC));

        for (size_t offset = header_len; offset < option_data_len;) {
                const uint8_t *subdata;
                size_t subdata_len;
                uint16_t subopt;

                r = dhcp6_option_parse(option_data, option_data_len, &offset, &subopt, &subdata_len, &subdata);
                if (r < 0)
                        return r;

                switch (subopt) {
                case SD_DHCP6_OPTION_IAADDR: {
                        r = dhcp6_option_parse_ia_address(client, ia, subdata, subdata_len);
                        if (r == -ENOMEM)
                                return r;

                        /* Ignore non-critical errors in the sub-option. */
                        break;
                }
                case SD_DHCP6_OPTION_IA_PD_PREFIX: {
                        r = dhcp6_option_parse_ia_pdprefix(client, ia, subdata, subdata_len);
                        if (r == -ENOMEM)
                                return r;

                        /* Ignore non-critical errors in the sub-option. */
                        break;
                }
                case SD_DHCP6_OPTION_STATUS_CODE: {
                        _cleanup_free_ char *msg = NULL;

                        r = dhcp6_option_parse_status(subdata, subdata_len, &msg);
                        if (r == -ENOMEM)
                                return r;
                        if (r > 0)
                                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(EINVAL),
                                                              "Received an IA option with non-zero status%s%s",
                                                              isempty(msg) ? "." : ": ", strempty(msg));
                        if (r < 0)
                                log_dhcp6_client_errno(client, r,
                                                       "Received an IA option with an invalid status sub option, ignoring: %m");
                        break;
                }
                default:
                        log_dhcp6_client(client, "Received an IA option with an unknown sub-option %u, ignoring", subopt);
                }
        }

        if (!ia->addresses)
                return log_dhcp6_client_errno(client, SYNTHETIC_ERRNO(ENODATA),
                                              "Received an IA option without valid IA addresses or PD prefixes, ignoring.");

        *ret = TAKE_PTR(ia);
        return 0;
}

int dhcp6_option_parse_addresses(
                const uint8_t *optval,
                size_t optlen,
                struct in6_addr **addrs,
                size_t *count) {

        assert(optval || optlen == 0);
        assert(addrs);
        assert(count);

        if (optlen == 0 || optlen % sizeof(struct in6_addr) != 0)
                return -EBADMSG;

        if (!GREEDY_REALLOC(*addrs, *count + optlen / sizeof(struct in6_addr)))
                return -ENOMEM;

        memcpy(*addrs + *count, optval, optlen);
        *count += optlen / sizeof(struct in6_addr);

        return 0;
}

int dhcp6_option_parse_domainname(const uint8_t *optval, size_t optlen, char **ret) {
        _cleanup_free_ char *domain = NULL;
        int r;

        assert(optval || optlen == 0);
        assert(ret);

        r = dns_name_from_wire_format(&optval, &optlen, &domain);
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;
        if (optlen != 0)
                return -EINVAL;

        *ret = TAKE_PTR(domain);
        return 0;
}

int dhcp6_option_parse_domainname_list(const uint8_t *optval, size_t optlen, char ***ret) {
        _cleanup_strv_free_ char **names = NULL;
        int r;

        assert(optval || optlen == 0);
        assert(ret);

        if (optlen <= 1)
                return -ENODATA;
        if (optval[optlen - 1] != '\0')
                return -EINVAL;

        while (optlen > 0) {
                _cleanup_free_ char *name = NULL;

                r = dns_name_from_wire_format(&optval, &optlen, &name);
                if (r < 0)
                        return r;
                if (dns_name_is_root(name)) /* root domain */
                        return -EBADMSG;

                r = strv_consume(&names, TAKE_PTR(name));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(names);
        return 0;
}

static sd_dhcp6_option* dhcp6_option_free(sd_dhcp6_option *i) {
        if (!i)
                return NULL;

        free(i->data);
        return mfree(i);
}

int sd_dhcp6_option_new(uint16_t option, const void *data, size_t length, uint32_t enterprise_identifier, sd_dhcp6_option **ret) {
        assert_return(ret, -EINVAL);
        assert_return(length == 0 || data, -EINVAL);

        _cleanup_free_ void *q = memdup(data, length);
        if (!q)
                return -ENOMEM;

        sd_dhcp6_option *p = new(sd_dhcp6_option, 1);
        if (!p)
                return -ENOMEM;

        *p = (sd_dhcp6_option) {
                .n_ref = 1,
                .option = option,
                .enterprise_identifier = enterprise_identifier,
                .length = length,
                .data = TAKE_PTR(q),
        };

        *ret = p;
        return 0;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(sd_dhcp6_option, sd_dhcp6_option, dhcp6_option_free);
DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dhcp6_option_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                sd_dhcp6_option,
                sd_dhcp6_option_unref);
