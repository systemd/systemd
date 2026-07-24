/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>

#include "sd-netlink.h"

#include "fw.h"
#include "log.h"
#include "networkd-link.h"

static int fw_fill_message(Link *link, TFilter *tfilter, sd_netlink_message *m) {
        int r;

        assert(link);
        assert(tfilter);
        assert(m);

        r = sd_netlink_message_open_container_union(m, TCA_OPTIONS, "fw");
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, TCA_FW_CLASSID, tfilter->classid);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        return 0;
}

static int fw_verify(TFilter *tfilter) {
        assert(tfilter);

        if (tfilter->parent == TC_H_ROOT)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [FirewallFilter] requires a non-root Parent= (e.g. a qdisc handle). "
                                         "Ignoring [FirewallFilter] section from line %u.",
                                         tfilter->section->filename, tfilter->section->line);

        if (tfilter->protocol == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [FirewallFilter] section without Protocol= setting. "
                                         "Ignoring [FirewallFilter] section from line %u.",
                                         tfilter->section->filename, tfilter->section->line);

        if (tfilter->handle == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [FirewallFilter] section without Handle= setting. "
                                         "Handle= encodes the fwmark to match. "
                                         "Ignoring [FirewallFilter] section from line %u.",
                                         tfilter->section->filename, tfilter->section->line);

        if (tfilter->classid == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL),
                                         "%s: [FirewallFilter] section without FlowId= setting. "
                                         "Ignoring [FirewallFilter] section from line %u.",
                                         tfilter->section->filename, tfilter->section->line);

        return 0;
}

const TFilterVTable fw_tfilter_vtable = {
        .object_size = sizeof(FirewallFilter),
        .tca_kind = "fw",
        .fill_message = fw_fill_message,
        .verify = fw_verify,
};
