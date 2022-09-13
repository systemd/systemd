/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "device-util.h"
#include "netlink-util.h"
#include "netif-sriov.h"
#include "parse-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"

static int sr_iov_new(SRIOV **ret) {
        SRIOV *sr_iov;

        assert(ret);

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

static int sr_iov_new_static(OrderedHashmap **sr_iov_by_section, const char *filename, unsigned section_line, SRIOV **ret) {
        _cleanup_(config_section_freep) ConfigSection *n = NULL;
        _cleanup_(sr_iov_freep) SRIOV *sr_iov = NULL;
        SRIOV *existing = NULL;
        int r;

        assert(sr_iov_by_section);
        assert(filename);
        assert(section_line > 0);
        assert(ret);

        r = config_section_new(filename, section_line, &n);
        if (r < 0)
                return r;

        existing = ordered_hashmap_get(*sr_iov_by_section, n);
        if (existing) {
                *ret = existing;
                return 0;
        }

        r = sr_iov_new(&sr_iov);
        if (r < 0)
                return r;

        r = ordered_hashmap_ensure_put(sr_iov_by_section, &config_section_hash_ops, n, sr_iov);
        if (r < 0)
                return r;

        sr_iov->section = TAKE_PTR(n);
        sr_iov->sr_iov_by_section = *sr_iov_by_section;

        *ret = TAKE_PTR(sr_iov);
        return 0;
}

SRIOV *sr_iov_free(SRIOV *sr_iov) {
        if (!sr_iov)
                return NULL;

        if (sr_iov->sr_iov_by_section && sr_iov->section)
                ordered_hashmap_remove(sr_iov->sr_iov_by_section, sr_iov->section);

        config_section_free(sr_iov->section);

        return mfree(sr_iov);
}

void sr_iov_hash_func(const SRIOV *sr_iov, struct siphash *state) {
        assert(sr_iov);
        assert(state);

        siphash24_compress(&sr_iov->vf, sizeof(sr_iov->vf), state);
}

int sr_iov_compare_func(const SRIOV *s1, const SRIOV *s2) {
        assert(s1);
        assert(s2);

        return CMP(s1->vf, s2->vf);
}

DEFINE_PRIVATE_HASH_OPS(
        sr_iov_hash_ops,
        SRIOV,
        sr_iov_hash_func,
        sr_iov_compare_func);

int sr_iov_set_netlink_message(SRIOV *sr_iov, sd_netlink_message *req) {
        int r;

        assert(sr_iov);
        assert(req);

        r = sd_netlink_message_open_container(req, IFLA_VFINFO_LIST);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(req, IFLA_VF_INFO);
        if (r < 0)
                return r;

        if (!ether_addr_is_null(&sr_iov->mac)) {
                struct ifla_vf_mac ivm = {
                        .vf = sr_iov->vf,
                };

                memcpy(ivm.mac, &sr_iov->mac, ETH_ALEN);
                r = sd_netlink_message_append_data(req, IFLA_VF_MAC, &ivm, sizeof(struct ifla_vf_mac));
                if (r < 0)
                        return r;
        }

        if (sr_iov->vf_spoof_check_setting >= 0) {
                struct ifla_vf_spoofchk ivs = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->vf_spoof_check_setting,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_SPOOFCHK, &ivs, sizeof(struct ifla_vf_spoofchk));
                if (r < 0)
                        return r;
        }

        if (sr_iov->query_rss >= 0) {
                struct ifla_vf_rss_query_en ivs = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->query_rss,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_RSS_QUERY_EN, &ivs, sizeof(struct ifla_vf_rss_query_en));
                if (r < 0)
                        return r;
        }

        if (sr_iov->trust >= 0) {
                struct ifla_vf_trust ivt = {
                        .vf = sr_iov->vf,
                        .setting = sr_iov->trust,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_TRUST, &ivt, sizeof(struct ifla_vf_trust));
                if (r < 0)
                        return r;
        }

        if (sr_iov->link_state >= 0) {
                struct ifla_vf_link_state ivl = {
                        .vf = sr_iov->vf,
                        .link_state = sr_iov->link_state,
                };

                r = sd_netlink_message_append_data(req, IFLA_VF_LINK_STATE, &ivl, sizeof(struct ifla_vf_link_state));
                if (r < 0)
                        return r;
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
                        return r;

                r = sd_netlink_message_append_data(req, IFLA_VF_VLAN_INFO, &ivvi, sizeof(struct ifla_vf_vlan_info));
                if (r < 0)
                        return r;

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

int sr_iov_get_num_vfs(sd_device *device, uint32_t *ret) {
        const char *str;
        uint32_t n;
        int r;

        assert(device);
        assert(ret);

        r = sd_device_get_sysattr_value(device, "device/sriov_numvfs", &str);
        if (r < 0)
                return r;

        r = safe_atou32(str, &n);
        if (r < 0)
                return r;

        *ret = n;
        return 0;
}

int sr_iov_set_num_vfs(sd_device *device, uint32_t num_vfs, OrderedHashmap *sr_iov_by_section) {
        char val[DECIMAL_STR_MAX(uint32_t)];
        const char *str;
        int r;

        assert(device);

        if (num_vfs == UINT32_MAX) {
                uint32_t current_num_vfs;
                SRIOV *sr_iov;

                /* If the number of virtual functions is not specified, then use the maximum number of VF + 1. */

                num_vfs = 0;
                ORDERED_HASHMAP_FOREACH(sr_iov, sr_iov_by_section)
                        num_vfs = MAX(num_vfs, sr_iov->vf + 1);

                if (num_vfs == 0) /* No VF is configured. */
                        return 0;

                r = sr_iov_get_num_vfs(device, &current_num_vfs);
                if (r < 0)
                        return log_device_debug_errno(device, r, "Failed to get the current number of SR-IOV virtual functions: %m");

                /* Enough VFs already exist. */
                if (num_vfs <= current_num_vfs)
                        return 0;

        } else if (num_vfs == 0) {
                r = sd_device_set_sysattr_value(device, "device/sriov_numvfs", "0");
                if (r < 0)
                        log_device_debug_errno(device, r, "Failed to write device/sriov_numvfs sysfs attribute, ignoring: %m");

                /* Gracefully handle the error in disabling VFs when the interface does not support SR-IOV. */
                return r == -ENOENT ? 0 : r;
        }

        /* So, the interface does not have enough VFs. Before increasing the number of VFs, check the
         * maximum allowed number of VFs from the sriov_totalvfs sysattr. Note that the sysattr
         * currently exists only for PCI drivers. Hence, ignore -ENOENT.
         * TODO: netdevsim provides the information in debugfs. */
        r = sd_device_get_sysattr_value(device, "device/sriov_totalvfs", &str);
        if (r >= 0) {
                uint32_t max_num_vfs;

                r = safe_atou32(str, &max_num_vfs);
                if (r < 0)
                        return log_device_debug_errno(device, r, "Failed to parse device/sriov_totalvfs sysfs attribute '%s': %m", str);

                if (num_vfs > max_num_vfs)
                        return log_device_debug_errno(device, SYNTHETIC_ERRNO(ERANGE),
                                                      "Specified number of virtual functions is out of range. "
                                                      "The maximum allowed value is %"PRIu32".",
                                                      max_num_vfs);

        } else if (r != -ENOENT) /* Currently, only PCI driver has the attribute. */
                return log_device_debug_errno(device, r, "Failed to read device/sriov_totalvfs sysfs attribute: %m");

        xsprintf(val, "%"PRIu32, num_vfs);
        r = sd_device_set_sysattr_value(device, "device/sriov_numvfs", val);
        if (r == -EBUSY) {
                /* Some devices e.g. netdevsim refuse to set sriov_numvfs if it has non-zero value. */
                r = sd_device_set_sysattr_value(device, "device/sriov_numvfs", "0");
                if (r >= 0)
                        r = sd_device_set_sysattr_value(device, "device/sriov_numvfs", val);
        }
        if (r < 0)
                return log_device_debug_errno(device, r, "Failed to write device/sriov_numvfs sysfs attribute: %m");

        log_device_debug(device, "device/sriov_numvfs sysfs attribute set to '%s'.", val);
        return 0;
}

static int sr_iov_section_verify(uint32_t num_vfs, SRIOV *sr_iov) {
        assert(sr_iov);

        if (section_is_invalid(sr_iov->section))
                return -EINVAL;

        if (sr_iov->vf == UINT32_MAX)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [SR-IOV] section without VirtualFunction= field configured. "
                                         "Ignoring [SR-IOV] section from line %u.",
                                         sr_iov->section->filename, sr_iov->section->line);

        if (sr_iov->vf >= num_vfs)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: VirtualFunction= must be smaller than the value specified in SR-IOVVirtualFunctions=. "
                                         "Ignoring [SR-IOV] section from line %u.",
                                         sr_iov->section->filename, sr_iov->section->line);

        return 0;
}

int sr_iov_drop_invalid_sections(uint32_t num_vfs, OrderedHashmap *sr_iov_by_section) {
        _cleanup_set_free_ Set *set = NULL;
        SRIOV *sr_iov;
        int r;

        ORDERED_HASHMAP_FOREACH(sr_iov, sr_iov_by_section) {
                SRIOV *dup;

                if (sr_iov_section_verify(num_vfs, sr_iov) < 0) {
                        sr_iov_free(sr_iov);
                        continue;
                }

                dup = set_remove(set, sr_iov);
                if (dup) {
                        log_warning("%s: Conflicting [SR-IOV] section is specified at line %u and %u, "
                                    "dropping the [SR-IOV] section specified at line %u.",
                                    dup->section->filename, sr_iov->section->line,
                                    dup->section->line, dup->section->line);
                        sr_iov_free(dup);
                }

                r = set_ensure_put(&set, &sr_iov_hash_ops, sr_iov);
                if (r < 0)
                        return log_oom();
                assert(r > 0);
        }

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
        OrderedHashmap **sr_iov_by_section = ASSERT_PTR(data);
        uint32_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sr_iov_new_static(sr_iov_by_section, filename, section_line, &sr_iov);
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
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid SR-IOV VLANId: %u", k);
                        return 0;
                }
                sr_iov->vlan = k;
        } else if (streq(lvalue, "VirtualFunction")) {
                if (k >= INT_MAX) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid SR-IOV virtual function: %u", k);
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
        OrderedHashmap **sr_iov_by_section = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sr_iov_new_static(sr_iov_by_section, filename, section_line, &sr_iov);
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
        OrderedHashmap **sr_iov_by_section = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sr_iov_new_static(sr_iov_by_section, filename, section_line, &sr_iov);
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
        OrderedHashmap **sr_iov_by_section = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sr_iov_new_static(sr_iov_by_section, filename, section_line, &sr_iov);
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
        OrderedHashmap **sr_iov_by_section = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = sr_iov_new_static(sr_iov_by_section, filename, section_line, &sr_iov);
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

        uint32_t n, *num_vfs = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *num_vfs = UINT32_MAX;
                return 0;
        }

        r = safe_atou32(rvalue, &n);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        if (n > INT_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "The number of SR-IOV virtual functions is too large. It must be equal to "
                           "or smaller than 2147483647. Ignoring assignment: %"PRIu32, n);
                return 0;
        }

        *num_vfs = n;
        return 0;
}
