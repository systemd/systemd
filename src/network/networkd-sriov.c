/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "alloc-util.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "networkd-sriov.h"
#include "parse-util.h"
#include "set.h"
#include "stdio-util.h"
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

static int sr_iov_set_num_vfs(Link *link) {
        char val[DECIMAL_STR_MAX(uint32_t)];
        bool request_exact = false;
        uint32_t num_vfs;
        const char *str;
        int r;

        assert(link);
        assert(link->network);

        if (!link->sd_device)
                return 0;

        if (link->network->sr_iov_num_vfs != UINT32_MAX) {
                /* If the number of virtual function is explicitly specified, then use it. */

                num_vfs = link->network->sr_iov_num_vfs;
                request_exact = true;
        } else {
                SRIOV *sr_iov;

                /* If it is not specified, then determine it from the VirtualFunction= setting in the
                 * [SR-IOV] sections. */

                num_vfs = 0;
                ORDERED_HASHMAP_FOREACH(sr_iov, link->network->sr_iov_by_section)
                        num_vfs = MAX(num_vfs, sr_iov->vf + 1);
        }

        /* No VF is requested. */
        if (num_vfs == 0) {
                if (!request_exact)
                        return 0;

                r = sd_device_set_sysattr_value(link->sd_device, "device/sriov_numvfs", "0");
                if (r < 0)
                        /* Gracefully handle the error in setting SR-IOV=0 when the interface does not support SR-IOV. */
                        log_link_full_errno(link, r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                            "Failed to write device/sriov_numvfs sysfs attribute, ignoring: %m");

                return r == -ENOENT ? 0 : r;
        }

        if (!request_exact) {
                uint32_t current_num_vfs;

                r = sd_device_get_sysattr_value(link->sd_device, "device/sriov_numvfs", &str);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to read device/sriov_numvfs sysfs attribute: %m");

                r = safe_atou32(str, &current_num_vfs);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to parse device/sriov_numvfs sysfs attribute '%s': %m", str);

                /* Enough VFs already exist. */
                if (num_vfs <= current_num_vfs)
                        return 0;
        }

        /* So, the interface does not have enough VFs. Before increasing the number of VFs, check the
         * maximum allowed number of VFs from the sriov_totalvfs sysattr. Note that the sysattr
         * currently exists for PCI drivers (netdevsim provides the information about the maximum
         * number of VFs in debugfs, which cannot read it by networkd). Hence, ignore -ENOENT. */
        r = sd_device_get_sysattr_value(link->sd_device, "device/sriov_totalvfs", &str);
        if (r >= 0) {
                uint32_t max_num_vfs;

                r = safe_atou32(str, &max_num_vfs);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to parse device/sriov_totalvfs sysfs attribute '%s': %m", str);

                if (num_vfs > max_num_vfs)
                        return log_link_warning_errno(link, SYNTHETIC_ERRNO(ERANGE), "Specified virtual function is out of range.");

        } else if (r != -ENOENT)
                return log_link_warning_errno(link, r, "Failed to read device/sriov_totalvfs sysfs attribute: %m");

        xsprintf(val, "%"PRIu32, num_vfs);
        r = sd_device_set_sysattr_value(link->sd_device, "device/sriov_numvfs", val);
        if (r == -EBUSY) {
                /* Some devices e.g. netdevsim refuse to set sriov_numvfs if it has non-zero value. */
                r = sd_device_set_sysattr_value(link->sd_device, "device/sriov_numvfs", "0");
                if (r >= 0)
                        r = sd_device_set_sysattr_value(link->sd_device, "device/sriov_numvfs", val);
        }
        if (r < 0)
                return log_link_warning_errno(link, r, "Failed to write device/sriov_numvfs sysfs attribute: %m");

        log_link_debug(link, "device/sriov_numvfs sysfs attribute set to '%s'.", val);
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

        r = sr_iov_set_num_vfs(link);
        if (r < 0)
                return r;

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
        assert(sr_iov->network);

        if (section_is_invalid(sr_iov->section))
                return -EINVAL;

        if (sr_iov->vf == UINT32_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [SR-IOV] section without VirtualFunction= field configured. "
                                         "Ignoring [SR-IOV] section from line %u.",
                                         sr_iov->section->filename, sr_iov->section->line);

        if (sr_iov->vf >= sr_iov->network->sr_iov_num_vfs)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: The VirtualFunction= setting must be smaller than "
                                         "the value specified in the SR-IOV= setting. "
                                         "Ignoring [SR-IOV] section from line %u.",
                                         sr_iov->section->filename, sr_iov->section->line);

        return 0;
}

int network_drop_invalid_sr_iov(Network *network) {
        _cleanup_hashmap_free_ Hashmap *hashmap = NULL;
        SRIOV *sr_iov;
        int r;

        assert(network);

        ORDERED_HASHMAP_FOREACH(sr_iov, network->sr_iov_by_section) {
                SRIOV *dup;

                if (sr_iov_section_verify(sr_iov) < 0) {
                        sr_iov_free(sr_iov);
                        continue;
                }

                assert(sr_iov->vf < INT_MAX);

                dup = hashmap_remove(hashmap, UINT32_TO_PTR(sr_iov->vf + 1));
                if (dup) {
                        log_warning("%s: Conflicting [SR-IOV] section is specified at line %u and %u, "
                                    "dropping the [SR-IOV] section specified at line %u.",
                                    dup->section->filename, sr_iov->section->line,
                                    dup->section->line, dup->section->line);
                        sr_iov_free(dup);
                }

                r = hashmap_ensure_put(&hashmap, NULL, UINT32_TO_PTR(sr_iov->vf + 1), sr_iov);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

        return 0;
}

int config_parse_sr_iov_num_vfs(
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

        uint32_t n, *num_vfs = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *num_vfs = UINT32_MAX;
                return 0;
        }

        r = safe_atou32(rvalue, &n);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse the number of SR-IOV virtual functions, ignoring assignment: %s",
                           rvalue);
                return 0;
        }
        if (n == UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "The number of SR-IOV virtual functions is out of range, ignoring assignment: %s",
                           rvalue);
                return 0;
        }

        *num_vfs = n;
        return 0;
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
                        assert_not_reached();

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
                assert_not_reached();

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
                        assert_not_reached();

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
                assert_not_reached();

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

        r = parse_ether_addr(rvalue, &sr_iov->mac);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse SR-IOV '%s=', ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        TAKE_PTR(sr_iov);
        return 0;
}
