/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "fq-codel.h"
#include "netem.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "sfq.h"
#include "tbf.h"

typedef struct QDisc {
        NetworkConfigSection *section;
        Network *network;

        int family;

        uint32_t handle;
        uint32_t parent;

        char *tca_kind;
        bool has_network_emulator:1;
        bool has_token_buffer_filter:1;
        bool has_stochastic_fairness_queueing:1;
        bool has_fair_queuing_controlled_delay:1;

        NetworkEmulator ne;
        TokenBufferFilter tbf;
        StochasticFairnessQueueing sfq;
        FairQueuingControlledDelay fq_codel;
} QDisc;

void qdisc_free(QDisc *qdisc);
int qdisc_new_static(Network *network, const char *filename, unsigned section_line, QDisc **ret);

int qdisc_configure(Link *link, QDisc *qdisc);

int qdisc_section_verify(QDisc *qdisc, bool *has_root, bool *has_clsact);

DEFINE_NETWORK_SECTION_FUNCTIONS(QDisc, qdisc_free);

CONFIG_PARSER_PROTOTYPE(config_parse_tc_qdiscs_parent);
