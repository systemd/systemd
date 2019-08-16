/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "conf-parser.h"
#include "extract-word.h"
#include "geneve.h"
#include "netlink-util.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "missing.h"
#include "networkd-manager.h"

#define GENEVE_FLOW_LABEL_MAX_MASK 0xFFFFFU
#define DEFAULT_GENEVE_DESTINATION_PORT 6081

static const char* const geneve_df_table[_NETDEV_GENEVE_DF_MAX] = {
        [NETDEV_GENEVE_DF_NO] = "no",
        [NETDEV_GENEVE_DF_YES] = "yes",
        [NETDEV_GENEVE_DF_INHERIT] = "inherit",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(geneve_df, GeneveDF, NETDEV_GENEVE_DF_YES);
DEFINE_CONFIG_PARSE_ENUM(config_parse_geneve_df, geneve_df, GeneveDF, "Failed to parse Geneve IPDoNotFragment= setting");

/* callback for geneve netdev's created without a backing Link */
static int geneve_netdev_create_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "Geneve netdev exists, using existing without changing its parameters");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "Geneve netdev could not be created: %m");
                netdev_drop(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "Geneve created");

        return 1;
}

static int netdev_geneve_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        Geneve *v;
        int r;

        assert(netdev);

        v = GENEVE(netdev);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate RTM_NEWLINK message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IFNAME, attribute: %m");

        if (netdev->mac) {
                r = sd_netlink_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_ADDRESS attribute: %m");
        }

        if (netdev->mtu != 0) {
                r = sd_netlink_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_MTU attribute: %m");
        }

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        if (v->id <= GENEVE_VID_MAX) {
                r = sd_netlink_message_append_u32(m, IFLA_GENEVE_ID, v->id);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_ID attribute: %m");
        }

        if (in_addr_is_null(v->remote_family, &v->remote) == 0) {
                if (v->remote_family == AF_INET)
                        r = sd_netlink_message_append_in_addr(m, IFLA_GENEVE_REMOTE, &v->remote.in);
                else
                        r = sd_netlink_message_append_in6_addr(m, IFLA_GENEVE_REMOTE6, &v->remote.in6);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_REMOTE/IFLA_GENEVE_REMOTE6 attribute: %m");
        }

        if (v->inherit) {
                r = sd_netlink_message_append_u8(m, IFLA_GENEVE_TTL_INHERIT, 1);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_TTL_INHERIT attribute: %m");
        } else {
                r = sd_netlink_message_append_u8(m, IFLA_GENEVE_TTL, v->ttl);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_TTL attribute: %m");
        }

        r = sd_netlink_message_append_u8(m, IFLA_GENEVE_TOS, v->tos);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_TOS attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GENEVE_UDP_CSUM, v->udpcsum);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_UDP_CSUM attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GENEVE_UDP_ZERO_CSUM6_TX, v->udp6zerocsumtx);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_UDP_ZERO_CSUM6_TX attribute: %m");

        r = sd_netlink_message_append_u8(m, IFLA_GENEVE_UDP_ZERO_CSUM6_RX, v->udp6zerocsumrx);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_UDP_ZERO_CSUM6_RX attribute: %m");

        if (v->dest_port != DEFAULT_GENEVE_DESTINATION_PORT) {
                r = sd_netlink_message_append_u16(m, IFLA_GENEVE_PORT, htobe16(v->dest_port));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_PORT attribute: %m");
        }

        if (v->flow_label > 0) {
                r = sd_netlink_message_append_u32(m, IFLA_GENEVE_LABEL, htobe32(v->flow_label));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_LABEL attribute: %m");
        }

        if (v->geneve_df != _NETDEV_GENEVE_DF_INVALID) {
                r = sd_netlink_message_append_u8(m, IFLA_GENEVE_DF, v->geneve_df);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_GENEVE_DF attribute: %m");
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = netlink_call_async(netdev->manager->rtnl, NULL, m, geneve_netdev_create_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

        netdev_ref(netdev);
        netdev->state = NETDEV_STATE_CREATING;

        log_netdev_debug(netdev, "Creating");

        return r;
}

int config_parse_geneve_vni(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {
        Geneve *v = userdata;
        uint32_t f;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &f);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse Geneve VNI '%s'.", rvalue);
                return 0;
        }

        if (f > GENEVE_VID_MAX){
                log_syntax(unit, LOG_ERR, filename, line, r, "Geneve VNI out is of range '%s'.", rvalue);
                return 0;
        }

        v->id = f;

        return 0;
}

int config_parse_geneve_address(const char *unit,
                                const char *filename,
                                unsigned line,
                                const char *section,
                                unsigned section_line,
                                const char *lvalue,
                                int ltype,
                                const char *rvalue,
                                void *data,
                                void *userdata) {
        Geneve *v = userdata;
        union in_addr_union *addr = data, buffer;
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "geneve '%s' address is invalid, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        r = in_addr_is_multicast(f, &buffer);
        if (r > 0) {
                log_syntax(unit, LOG_ERR, filename, line, 0, "geneve invalid multicast '%s' address, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        v->remote_family = f;
        *addr = buffer;

        return 0;
}

int config_parse_geneve_flow_label(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata) {
        Geneve *v = userdata;
        uint32_t f;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou32(rvalue, &f);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Failed to parse Geneve flow label '%s'.", rvalue);
                return 0;
        }

        if (f & ~GENEVE_FLOW_LABEL_MAX_MASK) {
                log_syntax(unit, LOG_ERR, filename, line, r,
                           "Geneve flow label '%s' not valid. Flow label range should be [0-1048575].", rvalue);
                return 0;
        }

        v->flow_label = f;

        return 0;
}

int config_parse_geneve_ttl(const char *unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {
        Geneve *v = userdata;
        unsigned f;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "inherit"))
                v->inherit = true;
        else {
                r = safe_atou(rvalue, &f);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, r,
                                   "Failed to parse Geneve TTL '%s', ignoring assignment: %m", rvalue);
                        return 0;
                }

                if (f > 255) {
                        log_syntax(unit, LOG_ERR, filename, line, 0,
                                   "Invalid Geneve TTL '%s'. TTL must be <= 255. Ignoring assignment.", rvalue);
                        return 0;
                }

                v->ttl = f;
        }

        return 0;
}

static int netdev_geneve_verify(NetDev *netdev, const char *filename) {
        Geneve *v = GENEVE(netdev);

        assert(netdev);
        assert(v);
        assert(filename);

        if (v->id > GENEVE_VID_MAX)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: Geneve without valid VNI (or Virtual Network Identifier) configured. Ignoring.",
                                                filename);

        return 0;
}

static void geneve_init(NetDev *netdev) {
        Geneve *v;

        assert(netdev);

        v = GENEVE(netdev);

        assert(v);

        v->id = GENEVE_VID_MAX + 1;
        v->geneve_df = _NETDEV_GENEVE_DF_INVALID;
        v->dest_port = DEFAULT_GENEVE_DESTINATION_PORT;
        v->udpcsum = false;
        v->udp6zerocsumtx = false;
        v->udp6zerocsumrx = false;
}

const NetDevVTable geneve_vtable = {
        .object_size = sizeof(Geneve),
        .init = geneve_init,
        .sections = "Match\0NetDev\0GENEVE\0",
        .create = netdev_geneve_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = netdev_geneve_verify,
        .generate_mac = true,
};
