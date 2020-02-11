/* SPDX-License-Identifier: LGPL-2.1+ */

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

int traffic_control_configure(Link *link, TrafficControl *tc) {
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

int traffic_control_section_verify(TrafficControl *tc, bool *qdisc_has_root, bool *qdisc_has_clsact) {
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
