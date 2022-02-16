/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "networkd-queue.h"
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
                assert_not_reached();
        }
}

void traffic_control_hash_func(const TrafficControl *tc, struct siphash *state) {
        assert(tc);
        assert(state);

        siphash24_compress(&tc->kind, sizeof(tc->kind), state);

        switch (tc->kind) {
        case TC_KIND_QDISC:
                qdisc_hash_func(TC_TO_QDISC_CONST(tc), state);
                break;
        case TC_KIND_TCLASS:
                tclass_hash_func(TC_TO_TCLASS_CONST(tc), state);
                break;
        default:
                assert_not_reached();
        }
}

int traffic_control_compare_func(const TrafficControl *a, const TrafficControl *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->kind, b->kind);
        if (r != 0)
                return r;

        switch (a->kind) {
        case TC_KIND_QDISC:
                return qdisc_compare_func(TC_TO_QDISC_CONST(a), TC_TO_QDISC_CONST(b));
        case TC_KIND_TCLASS:
                return tclass_compare_func(TC_TO_TCLASS_CONST(a), TC_TO_TCLASS_CONST(b));
        default:
                assert_not_reached();
        }
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        traffic_control_hash_ops,
        TrafficControl,
        traffic_control_hash_func,
        traffic_control_compare_func,
        traffic_control_free);

int traffic_control_get(Link *link, const TrafficControl *in, TrafficControl **ret) {
        TrafficControl *existing;

        assert(link);
        assert(in);

        existing = set_get(link->traffic_control, in);
        if (!existing)
                return -ENOENT;

        if (ret)
                *ret = existing;
        return 0;
}

int traffic_control_add(Link *link, TrafficControl *tc) {
        int r;

        assert(link);
        assert(tc);

        /* This must be called only from qdisc_add() or tclass_add(). */

        r = set_ensure_put(&link->traffic_control, &traffic_control_hash_ops, tc);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        return 0;
}

static int traffic_control_configure(Link *link, TrafficControl *tc) {
        assert(link);
        assert(tc);

        switch (tc->kind) {
        case TC_KIND_QDISC:
                return qdisc_configure(link, TC_TO_QDISC(tc));
        case TC_KIND_TCLASS:
                return tclass_configure(link, TC_TO_TCLASS(tc));
        default:
                assert_not_reached();
        }
}

static int link_request_traffic_control_one(Link *link, TrafficControl *tc) {
        assert(link);
        assert(tc);

        switch (tc->kind) {
        case TC_KIND_QDISC:
                return link_request_qdisc(link, TC_TO_QDISC(tc));
        case TC_KIND_TCLASS:
                return link_request_tclass(link, TC_TO_TCLASS(tc));
        default:
                assert_not_reached();
        }
}

int link_request_traffic_control(Link *link) {
        TrafficControl *tc;
        int r;

        assert(link);
        assert(link->network);

        link->tc_configured = false;

        HASHMAP_FOREACH(tc, link->network->tc_by_section) {
                r = link_request_traffic_control_one(link, tc);
                if (r < 0)
                        return r;
        }

        if (link->tc_messages == 0) {
                link->tc_configured = true;
                link_check_ready(link);
        } else {
                log_link_debug(link, "Setting traffic control");
                link_set_state(link, LINK_STATE_CONFIGURING);
        }

        return 0;
}

static int traffic_control_is_ready_to_configure(Link *link, TrafficControl *tc) {
        assert(link);
        assert(tc);

        if (!IN_SET(link->state, LINK_STATE_CONFIGURING, LINK_STATE_CONFIGURED))
                return false;

        switch(tc->kind) {
        case TC_KIND_QDISC:
                return qdisc_is_ready_to_configure(link, TC_TO_QDISC(tc));
        case TC_KIND_TCLASS:
                return tclass_is_ready_to_configure(link, TC_TO_TCLASS(tc));
        default:
                assert_not_reached();
        }
}

int request_process_traffic_control(Request *req) {
        TrafficControl *tc;
        Link *link;
        int r;

        assert(req);
        assert(req->traffic_control);
        assert(req->type == REQUEST_TYPE_TRAFFIC_CONTROL);

        link = ASSERT_PTR(req->link);
        tc = ASSERT_PTR(req->traffic_control);

        r = traffic_control_is_ready_to_configure(link, tc);
        if (r <= 0)
                return r;

        r = traffic_control_configure(link, tc);
        if (r < 0)
                return r;

        return 1;
}

static int traffic_control_section_verify(TrafficControl *tc, bool *qdisc_has_root, bool *qdisc_has_clsact) {
        assert(tc);

        switch (tc->kind) {
        case TC_KIND_QDISC:
                return qdisc_section_verify(TC_TO_QDISC(tc), qdisc_has_root, qdisc_has_clsact);
        case TC_KIND_TCLASS:
                return tclass_section_verify(TC_TO_TCLASS(tc));
        default:
                assert_not_reached();
        }
}

void network_drop_invalid_traffic_control(Network *network) {
        bool has_root = false, has_clsact = false;
        TrafficControl *tc;

        assert(network);

        HASHMAP_FOREACH(tc, network->tc_by_section)
                if (traffic_control_section_verify(tc, &has_root, &has_clsact) < 0)
                        traffic_control_free(tc);
}
