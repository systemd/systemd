/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "multiq.h"

static int multi_queueing_fill_message(Link *link, QDisc *qdisc, sd_netlink_message *req) {
        struct tc_multiq_qopt opt = {};

        assert(req);

        /* It looks weird, but the multiq qdisc initialization wants to receive a tc_multiq_qopt attr even
         * though it doesn't do anything with it. */
        return sd_netlink_message_append_data(req, TCA_OPTIONS, &opt, sizeof(opt));
}

const QDiscVTable multiq_vtable = {
        .object_size = sizeof(BandMultiQueueing),
        .tca_kind = "multiq",
        .fill_message = multi_queueing_fill_message,
};
