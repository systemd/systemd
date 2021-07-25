/* SPDX-License-Identifier: LGPL-2.1+ */

#include <linux/mptcp.h>

#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-mptcp.h"
#include "parse-util.h"
#include "set.h"

#include <linux/if_arp.h>

static int mp_tcp_new(MPTCP **ret) {
        MPTCP *mp_tcp;

        mp_tcp = new(MPTCP, 1);
        if (!mp_tcp)
                return -ENOMEM;

        *mp_tcp = (MPTCP) {
                  .family = AF_UNSPEC,
                  .id_is_set = false,
        };

        *ret = TAKE_PTR(mp_tcp);

        return 0;
}

static int mp_tcp_new_static(Network *network, const char *filename, unsigned section_line, MPTCP **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(mp_tcp_freep) MPTCP *mp_tcp = NULL;
        MPTCP *existing;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = ordered_hashmap_get(network->mp_tcp_by_section, n);
        if (existing) {
                *ret = existing;
                return 0;
        }

        r = mp_tcp_new(&mp_tcp);
        if (r < 0)
                return r;

        mp_tcp->network = network;
        mp_tcp->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->mp_tcp_by_section, &network_config_hash_ops, mp_tcp->section, mp_tcp);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(mp_tcp);
        return 0;
}

MPTCP *mp_tcp_free(MPTCP *mp_tcp) {
        if (!mp_tcp)
                return NULL;

        if (mp_tcp->network && mp_tcp->section)
                ordered_hashmap_remove(mp_tcp->network->mp_tcp_by_section, mp_tcp->section);

        network_config_section_free(mp_tcp->section);

        return mfree(mp_tcp);
}

static int mp_tcp_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->mp_tcp_messages > 0);

        link->mp_tcp_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_link_message_error_errno(link, m, r, "Could not set up MPTCP");
                link_enter_failed(link);
                return 1;
        }

        if (link->mp_tcp_messages == 0) {
                log_link_debug(link, "MPTCP configured");
                link->mp_tcp_configured = true;
                link_check_ready(link);
        }

        return 1;
}

int mp_tcp_configure_address(Link *link, MPTCP *mp_tcp) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        log_link_debug(link, "Configuring MPTCP");

        r = sd_genl_message_new(link->manager->genl, SD_GENL_MPTCP, MPTCP_PM_CMD_ADD_ADDR, &req);
        if (r < 0)
                return log_link_error_errno(link, r, "Failed to allocate generic netlink message: %m");

        r = sd_netlink_message_open_container(req, MPTCP_PM_ATTR_ADDR);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open MPTCP_PM_ATTR_ADDR container: %m");

        if (mp_tcp->id_is_set) {
                r = sd_netlink_message_append_u8(req, MPTCP_PM_ADDR_ATTR_ID, mp_tcp->id);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append MPTCP_PM_ADDR_ATTR_ID attribute: %m");
        }

        r = sd_netlink_message_append_s32(req, MPTCP_PM_ADDR_ATTR_IF_IDX, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not append MPTCP_PM_ADDR_ATTR_IF_IDX attribute: %m");

        if (in_addr_is_null(mp_tcp->family, &mp_tcp->address) == 0) {
                r = sd_netlink_message_append_u16(req, MPTCP_PM_ADDR_ATTR_FAMILY, mp_tcp->family);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append MPTCP_PM_ADDR_ATTR_FAMILY attribute: %m");

                if (mp_tcp->family == AF_INET)
                        r = sd_netlink_message_append_in_addr(req, MPTCP_PM_ADDR_ATTR_ADDR4, &mp_tcp->address.in);
                else
                        r = sd_netlink_message_append_in6_addr(req, MPTCP_PM_ADDR_ATTR_ADDR6, &mp_tcp->address.in6);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append MPTCP_PM_ADDR_ATTR_ADDR4 / MPTCP_PM_ADDR_ATTR_ADDR6 attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close MPTCP_PM_ATTR_ADDR container: %m");

        r = netlink_call_async(link->manager->genl, NULL, req, mp_tcp_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->mp_tcp_messages++;

        return 0;
}

static int mp_tcp_limit_handler(sd_netlink *rtnl, sd_netlink_message *n, Manager *m) {
        int r;

        assert(n);
        assert(m);

        r = sd_netlink_message_get_errno(n);
        if (r < 0) {
                log_message_warning_errno(n, r, "Could not set up MPTCP limits: %m");
                return 1;
        }

        log_debug("MPTCP limit configured");

        return 1;
}

int mp_tcp_configure_limit(Manager *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(m);
        assert(m->rtnl);

        if (m->mp_tcp_subflows == UINT32_MAX && m->mp_tcp_add_addr_accepted == UINT32_MAX)
                return 0;

        r = sd_genl_message_new(m->genl, SD_GENL_MPTCP, MPTCP_PM_CMD_SET_LIMITS, &req);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate generic netlink message: %m");

        if (m->mp_tcp_add_addr_accepted != UINT32_MAX) {
                r = sd_netlink_message_append_u32(req, MPTCP_PM_ATTR_RCV_ADD_ADDRS, m->mp_tcp_add_addr_accepted);
                if (r < 0)
                        return log_error_errno(r, "Could not append MPTCP_PM_ATTR_RCV_ADD_ADDRS attribute: %m");
        }

        if (m->mp_tcp_subflows != UINT32_MAX) {
                r = sd_netlink_message_append_u32(req, MPTCP_PM_ATTR_SUBFLOWS, m->mp_tcp_subflows);
                if (r < 0)
                        return log_error_errno(r, "Could not append MPTCP_PM_ATTR_SUBFLOWS attribute: %m");
        }

        r = netlink_call_async(m->genl, NULL, req, mp_tcp_limit_handler, NULL, m);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        return 0;
}

int link_configure_mp_tcp(Link *link) {
        MPTCP *mp_tcp;
        int r;

        assert(link);
        assert(link->network);

        if (link->iftype == ARPHRD_CAN) {
                link->mp_tcp_configured = true;
                return 0;
        }

        link->mp_tcp_configured = false;
        link->mp_tcp_messages = 0;

        ORDERED_HASHMAP_FOREACH(mp_tcp, link->network->mp_tcp_by_section) {
                r = mp_tcp_configure_address(link, mp_tcp);
                if (r < 0)
                        return r;
        }

        if (link->mp_tcp_messages == 0)
                link->mp_tcp_configured = true;
        else
                log_link_debug(link, "Configuring MPTCP");

        return 0;
}

static int mp_tcp_section_verify(MPTCP *mp_tcp) {
        if (section_is_invalid(mp_tcp->section))
                return -EINVAL;

        if (mp_tcp->family == AF_UNSPEC)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "%s: [MPTCP] section without Address= field configured. "
                                         "Ignoring [MPTCP] section from line %u.",
                                         mp_tcp->section->filename, mp_tcp->section->line);

        return 0;
}

int network_drop_invalid_mp_tcp(Network *network) {
        MPTCP *mp_tcp;

        assert(network);

        ORDERED_HASHMAP_FOREACH(mp_tcp, network->mp_tcp_by_section)
                if (mp_tcp_section_verify(mp_tcp) < 0)
                        mp_tcp_free(mp_tcp);

        return 0;
}

int config_parse_mp_tcp_id(
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

        _cleanup_(mp_tcp_free_or_set_invalidp) MPTCP *mp_tcp = NULL;
        Network *network = data;
        uint8_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = mp_tcp_new_static(network, filename, section_line, &mp_tcp);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                mp_tcp->id_is_set = false;

                TAKE_PTR(mp_tcp);
                return 0;
        }

        r = safe_atou8(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MPTCP '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid MPTCP value '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        mp_tcp->id = k;
        mp_tcp->id_is_set = true;

        TAKE_PTR(mp_tcp);
        return 0;
}

int config_parse_mp_tcp_address(
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

        _cleanup_(mp_tcp_free_or_set_invalidp) MPTCP *mp_tcp = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = mp_tcp_new_static(network, filename, section_line, &mp_tcp);
        if (r < 0)
                return log_oom();

        if (isempty(rvalue)) {
                mp_tcp->address = IN_ADDR_NULL;
                mp_tcp->family = AF_UNSPEC;

                TAKE_PTR(mp_tcp);
                return 0;
        }

        r = in_addr_from_string_auto(rvalue, &mp_tcp->family, &mp_tcp->address);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MPTCP '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(mp_tcp);
        return 0;
}

int config_parse_mp_tcp_uint32(
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

        _cleanup_(mp_tcp_free_or_set_invalidp) MPTCP *mp_tcp = NULL;
        uint32_t *v = data;
        uint32_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *v = UINT32_MAX;

                TAKE_PTR(mp_tcp);
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse MPTCP '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }
        if (k > 8  || k == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid MPTCP value '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        *v = k;
        return 0;
}
