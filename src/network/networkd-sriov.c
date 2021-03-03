/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-sriov.h"
#include "parse-util.h"
#include "set.h"
#include "string-util.h"

static int sr_iov_new(SRIOV **ret) {
        SRIOV *sr_iov;

        sr_iov = new(SRIOV, 1);
        if (!sr_iov)
                return -ENOMEM;

        *sr_iov = (SRIOV) {
                  .vf = UINT32_MAX,
                  .vlan_proto = ETH_P_8021Q,
                  .vf_spoof_check_setting = -1,
                  .trust = -1,
                  .query_rss = -1,
                  .link_state = _SR_IOV_LINK_STATE_INVALID,
        };

        *ret = TAKE_PTR(sr_iov);

        return 0;
}

static int sr_iov_new_static(Network *network, const char *filename, unsigned section_line, SRIOV **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(sr_iov_freep) SRIOV *sr_iov = NULL;
        SRIOV *existing = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(filename);
        assert(section_line > 0);

        r = network_config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = ordered_hashmap_get(network->sr_iov_by_section, n);
        if (existing) {
                *ret = existing;
                return 0;
        }

        r = sr_iov_new(&sr_iov);
        if (r < 0)
                return r;

        sr_iov->network = network;
        sr_iov->section = TAKE_PTR(n);

        r = ordered_hashmap_ensure_put(&network->sr_iov_by_section, &network_config_hash_ops, sr_iov->section, sr_iov);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(sr_iov);
        return 0;
}

SRIOV *sr_iov_free(SRIOV *sr_iov) {
        if (!sr_iov)
                return NULL;

        if (sr_iov->network && sr_iov->section)
                ordered_hashmap_remove(sr_iov->network->sr_iov_by_section, sr_iov->section);

        network_config_section_free(sr_iov->section);

        return mfree(sr_iov);
}

static int sr_iov_handler(sd_netlink *rtnl, sd_netlink_message *m, Link *link) {
        int r;

        assert(link);
        assert(link->sr_iov_messages > 0);
        link->sr_iov_messages--;

        if (IN_SET(link->state, LINK_STATE_FAILED, LINK_STATE_LINGER))
                return 1;

        r = sd_netlink_message_get_errno(m);
        if (r < 0 && r != -EEXIST) {
                log_link_message_error_errno(link, m, r, "Could not set up SR-IOV");
                link_enter_failed(link);
                return 1;
        }

        if (link->sr_iov_messages == 0) {
                log_link_debug(link, "SR-IOV configured");
                link->sr_iov_configured = true;
                link_check_ready(link);
        }

        return 1;
}

static int sr_iov_configure(Link *link, SRIOV *sr_iov) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(link);
        assert(link->manager);
        assert(link->manager->rtnl);
        assert(link->ifindex > 0);

        log_link_debug(link, "Setting SR-IOV virtual function %"PRIu32, sr_iov->vf);

        r = sd_rtnl_message_new_link(link->manager->rtnl, &req, RTM_SETLINK, link->ifindex);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_open_container(req, IFLA_VFINFO_LIST);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open IFLA_VFINFO_LIST container: %m");

        r = sd_netlink_message_open_container(req, IFLA_VF_INFO);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not open IFLA_VF_INFO container: %m");

        if (!ether_addr_is_null(&sr_iov->mac)) {
                struct ifla_vf_mac ivm = {
                        .vf = sr_iov->vf,
                };

                memcpy(ivm.mac, &sr_iov->mac, ETH_ALEN);
                r = sd_netlink_message_append_data(req, IFLA_VF_MAC, &ivm, sizeof(struct ifla_vf_mac));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_MAC: %m");
        }

        if (sr_iov->vf_spoof_check_setting >= 0) {
                struct ifla_vf_spoofchk ivs = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->vf_spoof_check_setting,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_SPOOFCHK, &ivs, sizeof(struct ifla_vf_spoofchk));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_SPOOFCHK: %m");
        }

        if (sr_iov->query_rss >= 0) {
                struct ifla_vf_rss_query_en ivs = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->query_rss,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_RSS_QUERY_EN, &ivs, sizeof(struct ifla_vf_rss_query_en));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_RSS_QUERY_EN: %m");
        }

        if (sr_iov->trust >= 0) {
                struct ifla_vf_trust ivt = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->trust,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_TRUST, &ivt, sizeof(struct ifla_vf_trust));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_TRUST: %m");
        }

        if (sr_iov->link_state >= 0) {
                struct ifla_vf_link_state ivl = {
                        .vf = sr_iov->vf,
                        .link_state = sr_iov->link_state,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_LINK_STATE, &ivl, sizeof(struct ifla_vf_link_state));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_LINK_STATE: %m");
        }

        if (sr_iov->vlan > 0) {
                /* Because of padding, first the buffer must be initialized with 0. */
                struct ifla_vf_vlan_info ivvi = {};
                ivvi.vf = sr_iov->vf;
                ivvi.vlan = sr_iov->vlan;
                ivvi.qos = sr_iov->qos;
                ivvi.vlan_proto = htobe16(sr_iov->vlan_proto);

                r = sd_netlink_message_open_container(req, IFLA_VF_VLAN_LIST);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not open IFLA_VF_VLAN_LIST container: %m");

                r = sd_netlink_message_append_data(req, IFLA_VF_VLAN_INFO, &ivvi, sizeof(struct ifla_vf_vlan_info));
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not append IFLA_VF_VLAN_INFO: %m");

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return log_link_error_errno(link, r, "Could not close IFLA_VF_VLAN_LIST container: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close IFLA_VF_INFO container: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not close IFLA_VFINFO_LIST container: %m");

        r = netlink_call_async(link->manager->rtnl, NULL, req, sr_iov_handler,
                               link_netlink_destroy_callback, link);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not send rtnetlink message: %m");

        link_ref(link);
        link->sr_iov_messages++;

        return 0;
}

int link_configure_sr_iov(Link *link) {
        SRIOV *sr_iov;
        int r;

        assert(link);
        assert(link->network);

        if (link->sr_iov_messages != 0) {
                log_link_debug(link, "SR-IOV is configuring.");
                return 0;
        }

        link->sr_iov_configured = false;

        ORDERED_HASHMAP_FOREACH(sr_iov, link->network->sr_iov_by_section) {
                r = sr_iov_configure(link, sr_iov);
                if (r < 0)
                        return r;
        }

        if (link->sr_iov_messages == 0)
                link->sr_iov_configured = true;
        else
                log_link_debug(link, "Configuring SR-IOV");

        return 0;
}

static int sr_iov_section_verify(SRIOV *sr_iov) {
        assert(sr_iov);

        if (section_is_invalid(sr_iov->section))
                return -EINVAL;

        if (sr_iov->vf == UINT32_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [SRIOV] section without VirtualFunction= field configured. "
                                         "Ignoring [SRIOV] section from line %u.",
                                         sr_iov->section->filename, sr_iov->section->line);

        return 0;
}

void network_drop_invalid_sr_iov(Network *network) {
        SRIOV *sr_iov;

        assert(network);

        ORDERED_HASHMAP_FOREACH(sr_iov, network->sr_iov_by_section)
                if (sr_iov_section_verify(sr_iov) < 0)
                        sr_iov_free(sr_iov);
}

int config_parse_sr_iov_uint32(
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

        _cleanup_(sr_iov_free_or_set_invalidp) SRIOV *sr_iov = NULL;
        Network *network = data;
        uint32_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = sr_iov_new_static(network, filename, section_line, &sr_iov);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                if (streq(lvalue, "VirtualFunction"))
                        sr_iov->vf = UINT32_MAX;
                else if (streq(lvalue, "VLANId"))
                        sr_iov->vlan = 0;
                else if (streq(lvalue, "QualityOfService"))
                        sr_iov->qos = 0;
                else
                        assert_not_reached("Invalid lvalue");

                TAKE_PTR(sr_iov);
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SR-IOV '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "VLANId")) {
                if (k == 0 || k > 4095) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid SR-IOV VLANId: %d", k);
                        return 0;
                }
                sr_iov->vlan = k;
        } else if (streq(lvalue, "VirtualFunction")) {
                if (k >= INT_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid SR-IOV virtual function: %d", k);
                        return 0;
                }
                sr_iov->vf = k;
        } else if (streq(lvalue, "QualityOfService"))
                sr_iov->qos = k;
        else
                assert_not_reached("Invalid lvalue");

        TAKE_PTR(sr_iov);
        return 0;
}

int config_parse_sr_iov_vlan_proto(
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

        _cleanup_(sr_iov_free_or_set_invalidp) SRIOV *sr_iov = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = sr_iov_new_static(network, filename, section_line, &sr_iov);
        if (r < 0)
                return r;

        if (isempty(rvalue) || streq(rvalue, "802.1Q"))
                sr_iov->vlan_proto = ETH_P_8021Q;
        else if (streq(rvalue, "802.1ad"))
                sr_iov->vlan_proto = ETH_P_8021AD;
        else {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid SR-IOV '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(sr_iov);
        return 0;
}

int config_parse_sr_iov_link_state(
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

        _cleanup_(sr_iov_free_or_set_invalidp) SRIOV *sr_iov = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = sr_iov_new_static(network, filename, section_line, &sr_iov);
        if (r < 0)
                return r;

        /* Unfortunately, SR_IOV_LINK_STATE_DISABLE is 2, not 0. So, we cannot use
         * DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN() macro. */

        if (isempty(rvalue)) {
                sr_iov->link_state = _SR_IOV_LINK_STATE_INVALID;
                TAKE_PTR(sr_iov);
                return 0;
        }

        if (streq(rvalue, "auto")) {
                sr_iov->link_state = SR_IOV_LINK_STATE_AUTO;
                TAKE_PTR(sr_iov);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SR-IOV '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        sr_iov->link_state = r ? SR_IOV_LINK_STATE_ENABLE : SR_IOV_LINK_STATE_DISABLE;
        TAKE_PTR(sr_iov);
        return 0;
}

int config_parse_sr_iov_boolean(
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

        _cleanup_(sr_iov_free_or_set_invalidp) SRIOV *sr_iov = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = sr_iov_new_static(network, filename, section_line, &sr_iov);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                if (streq(lvalue, "MACSpoofCheck"))
                        sr_iov->vf_spoof_check_setting = -1;
                else if (streq(lvalue, "QueryReceiveSideScaling"))
                        sr_iov->query_rss = -1;
                else if (streq(lvalue, "Trust"))
                        sr_iov->trust = -1;
                else
                        assert_not_reached("Invalid lvalue");

                TAKE_PTR(sr_iov);
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse '%s=', ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (streq(lvalue, "MACSpoofCheck"))
                sr_iov->vf_spoof_check_setting = r;
        else if (streq(lvalue, "QueryReceiveSideScaling"))
                sr_iov->query_rss = r;
        else if (streq(lvalue, "Trust"))
                sr_iov->trust = r;
        else
                assert_not_reached("Invalid lvalue");

        TAKE_PTR(sr_iov);
        return 0;
}

int config_parse_sr_iov_mac(
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

        _cleanup_(sr_iov_free_or_set_invalidp) SRIOV *sr_iov = NULL;
        Network *network = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = sr_iov_new_static(network, filename, section_line, &sr_iov);
        if (r < 0)
                return r;

        if (isempty(rvalue)) {
                sr_iov->mac = ETHER_ADDR_NULL;
                TAKE_PTR(sr_iov);
                return 0;
        }

        r = ether_addr_from_string(rvalue, &sr_iov->mac);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SR-IOV '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(sr_iov);
        return 0;
}
