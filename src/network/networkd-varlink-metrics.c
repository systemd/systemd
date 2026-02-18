/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "argv-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "metrics.h"
#include "network-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-varlink-metrics.h"

#define METRIC_IO_SYSTEMD_NETWORK_PREFIX "io.systemd.Network."

typedef const char* (*link_metric_extractor_t)(const Link *link);

static int link_metric_build_json(
                MetricFamilyContext *context,
                link_metric_extractor_t extractor,
                void *userdata) {

        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        int r;

        assert(context);
        assert(extractor);

        HASHMAP_FOREACH(link, manager->links_by_index) {
                r = metric_build_send_string(context, link->ifname, extractor(link), /* fields= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const char* link_get_address_state(const Link *l) {
        return link_address_state_to_string(ASSERT_PTR(l)->address_state);
}

static const char* link_get_admin_state(const Link *l) {
        return link_state_to_string(ASSERT_PTR(l)->state);
}

static const char* link_get_carrier_state(const Link *l) {
        return link_carrier_state_to_string(ASSERT_PTR(l)->carrier_state);
}

static const char* link_get_ipv4_address_state(const Link *l) {
        return link_address_state_to_string(ASSERT_PTR(l)->ipv4_address_state);
}

static const char* link_get_ipv6_address_state(const Link *l) {
        return link_address_state_to_string(ASSERT_PTR(l)->ipv6_address_state);
}

static const char* link_get_oper_state(const Link *l) {
        return link_operstate_to_string(ASSERT_PTR(l)->operstate);
}

static int link_address_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_address_state, userdata);
}

static int link_admin_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_admin_state, userdata);
}

static int link_carrier_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_carrier_state, userdata);
}

static int link_ipv4_address_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_ipv4_address_state, userdata);
}

static int link_ipv6_address_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_ipv6_address_state, userdata);
}

static int link_oper_state_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_oper_state, userdata);
}

static int managed_interfaces_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        uint64_t count = 0;

        assert(context);

        HASHMAP_FOREACH(link, manager->links_by_index)
                if (link->network)
                        count++;

        return metric_build_send_unsigned(context, /* object= */ NULL, count, /* fields= */ NULL);
}

/* Keep metrics ordered alphabetically */
static const MetricFamily network_metric_family_table[] = {
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "AddressState",
                .description = "Per interface metric: address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "AdministrativeState",
                .description = "Per interface metric: administrative state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_admin_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "CarrierState",
                .description = "Per interface metric: carrier state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_carrier_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "IPv4AddressState",
                .description = "Per interface metric: IPv4 address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_ipv4_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "IPv6AddressState",
                .description = "Per interface metric: IPv6 address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_ipv6_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "ManagedInterfaces",
                .description = "Number of network interfaces managed by systemd-networkd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = managed_interfaces_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "OperationalState",
                .description = "Per interface metric: operational state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_oper_state_build_json,
        },
        {}
};

static int vl_method_metrics_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(network_metric_family_table, link, parameters, flags, userdata);
}

static int vl_method_metrics_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(network_metric_family_table, link, parameters, flags, userdata);
}

int manager_varlink_metrics_init(Manager *m, int fd) {
        _unused_ _cleanup_close_ int fd_close = fd; /* take possession */
        int r;

        assert(m);

        if (m->varlink_metrics_server)
                return 0;

        if (fd < 0 && invoked_by_systemd()) {
                log_debug("systemd-networkd-varlink-metrics.socket seems to be disabled, not installing metrics varlink server.");
                return 0;
        }

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        r = metrics_setup_varlink_server(
                        &s,
                        SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m->event,
                        SD_EVENT_PRIORITY_NORMAL,
                        vl_method_metrics_list,
                        vl_method_metrics_describe,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to set up metrics varlink server: %m");

        if (fd < 0) {
                r = sd_varlink_server_listen_address(
                                s,
                                "/run/systemd/report/io.systemd.Network",
                                0666 | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_warning_errno(r, "Failed to bind to metrics varlink socket, ignoring: %m");
                        return 0;
                }
        } else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to metrics varlink socket: %m");

        TAKE_FD(fd_close);
        m->varlink_metrics_server = TAKE_PTR(s);
        return 0;
}
