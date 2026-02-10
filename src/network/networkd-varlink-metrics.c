/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "metrics.h"
#include "network-util.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-varlink-metrics.h"
#include "string-util.h"

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
                r = metric_build_send_string(context, link->ifname, extractor(link), NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const char* link_get_address_state(const Link *l) {
        assert(l);

        return link_address_state_to_string(l->address_state);
}

static const char* link_get_admin_state(const Link *l) {
        assert(l);

        return link_state_to_string(l->state);
}

static const char* link_get_carrier_state(const Link *l) {
        assert(l);

        return link_carrier_state_to_string(l->carrier_state);
}

static const char* link_get_ipv4_address_state(const Link *l) {
        assert(l);

        return link_address_state_to_string(l->ipv4_address_state);
}

static const char* link_get_ipv6_address_state(const Link *l) {
        assert(l);

        return link_address_state_to_string(l->ipv6_address_state);
}

static const char* link_get_oper_state(const Link *l) {
        assert(l);

        return link_operstate_to_string(l->operstate);
}

static const char* link_get_required_for_online(const Link *l) {
        assert(l);

        return yes_no(l->network && l->network->required_for_online > 0);
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

static int link_required_for_online_build_json(MetricFamilyContext *ctx, void *userdata) {
        return link_metric_build_json(ctx, link_get_required_for_online, userdata);
}

static int managed_interfaces_build_json(MetricFamilyContext *context, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        Link *link;
        uint64_t count = 0;

        assert(context);

        HASHMAP_FOREACH(link, manager->links_by_index) {
                if (link->network)
                        count++;
        }

        return metric_build_send_unsigned(context, /* object= */ NULL, count, /* fields= */ NULL);
}

/* Keep metrics ordered alphabetically */
static const MetricFamily network_metric_family_table[] = {
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "addressState",
                .description = "Per interface metric: address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "adminState",
                .description = "Per interface metric: admin state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_admin_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "carrierState",
                .description = "Per interface metric: carrier state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_carrier_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "ipv4AddressState",
                .description = "Per interface metric: IPv4 address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_ipv4_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "ipv6AddressState",
                .description = "Per interface metric: IPv6 address state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_ipv6_address_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "managedInterfaces",
                .description = "Number of network interfaces managed by systemd-networkd",
                .type = METRIC_FAMILY_TYPE_GAUGE,
                .generate = managed_interfaces_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "operState",
                .description = "Per interface metric: operational state",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_oper_state_build_json,
        },
        {
                .name = METRIC_IO_SYSTEMD_NETWORK_PREFIX "requiredForOnline",
                .description = "Per interface metric: required for online",
                .type = METRIC_FAMILY_TYPE_STRING,
                .generate = link_required_for_online_build_json,
        },
        {}
};

int vl_method_metrics_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(network_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_metrics_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(network_metric_family_table, link, parameters, flags, userdata);
}
