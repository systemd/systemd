/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "qdisc.h"
#include "tc.h"
#include "tclass.h"

void traffic_control_free(TrafficControl *tc) {
        if (!tc)
                return;

        switch (tc->kind) {
        case TC_KIND_QDISC:
                qdisc_free(TC_TO_QDISC(tc));
                break;
        case TC_KIND_TCLASS:
                tclass_free(TC_TO_TCLASS(tc));
                break;
        default:
                assert_not_reached("Invalid traffic control type");
        }
}

static int traffic_control_configure(Link *link, TrafficControl *tc) {
        assert(link);
        assert(tc);

        switch(tc->kind) {
        case TC_KIND_QDISC:
                return qdisc_configure(link, TC_TO_QDISC(tc));
        case TC_KIND_TCLASS:
                return tclass_configure(link, TC_TO_TCLASS(tc));
        default:
                assert_not_reached("Invalid traffic control type");
        }
}

int link_configure_traffic_control(Link *link) {
        TrafficControl *tc;
        int r;

        assert(link);
        assert(link->network);

        if (link->tc_messages != 0) {
                log_link_debug(link, "Traffic control is configuring.");
                return 0;
        }

        link->tc_configured = false;

        ORDERED_HASHMAP_FOREACH(tc, link->network->tc_by_section) {
                r = traffic_control_configure(link, tc);
                if (r < 0)
                        return r;
        }

        if (link->tc_messages == 0)
                link->tc_configured = true;
        else
                log_link_debug(link, "Configuring traffic control");

        return 0;
}

static int traffic_control_section_verify(TrafficControl *tc, bool *qdisc_has_root, bool *qdisc_has_clsact) {
        assert(tc);

        switch(tc->kind) {
        case TC_KIND_QDISC:
                return qdisc_section_verify(TC_TO_QDISC(tc), qdisc_has_root, qdisc_has_clsact);
        case TC_KIND_TCLASS:
                return tclass_section_verify(TC_TO_TCLASS(tc));
        default:
                assert_not_reached("Invalid traffic control type");
        }
}

void network_drop_invalid_traffic_control(Network *network) {
        bool has_root = false, has_clsact = false;
        TrafficControl *tc;

        assert(network);

        ORDERED_HASHMAP_FOREACH(tc, network->tc_by_section)
                if (traffic_control_section_verify(tc, &has_root, &has_clsact) < 0)
                        traffic_control_free(tc);
}
