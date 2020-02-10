/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"

typedef enum QDiscKind {
        QDISC_KIND_CODEL,
        QDISC_KIND_FQ,
        QDISC_KIND_FQ_CODEL,
        QDISC_KIND_NETEM,
        QDISC_KIND_SFQ,
        QDISC_KIND_TBF,
        QDISC_KIND_TEQL,
        _QDISC_KIND_MAX,
        _QDISC_KIND_INVALID = -1,
} QDiscKind;

typedef struct QDisc {
        NetworkConfigSection *section;
        Network *network;

        int family;
        uint32_t handle;
        uint32_t parent;

        char *tca_kind;
        QDiscKind kind;
} QDisc;

typedef struct QDiscVTable {
        size_t object_size;
        const char *tca_kind;
        /* called in qdisc_new() */
        int (*init)(QDisc *qdisc);
        int (*fill_tca_kind)(Link *link, QDisc *qdisc, sd_netlink_message *m);
        int (*fill_message)(Link *link, QDisc *qdisc, sd_netlink_message *m);
        int (*verify)(QDisc *qdisc);
} QDiscVTable;

extern const QDiscVTable * const qdisc_vtable[_QDISC_KIND_MAX];

#define QDISC_VTABLE(q) ((q)->kind != _QDISC_KIND_INVALID ? qdisc_vtable[(q)->kind] : NULL)

/* For casting a qdisc into the various qdisc kinds */
#define DEFINE_QDISC_CAST(UPPERCASE, MixedCase)                           \
        static inline MixedCase* UPPERCASE(QDisc *q) {                    \
                if (_unlikely_(!q || q->kind != QDISC_KIND_##UPPERCASE))  \
                        return NULL;                                      \
                                                                          \
                return (MixedCase*) q;                                    \
        }

/* For casting the various qdisc kinds into a qdisc */
#define QDISC(q) (&(q)->meta)

void qdisc_free(QDisc *qdisc);
int qdisc_new_static(QDiscKind kind, Network *network, const char *filename, unsigned section_line, QDisc **ret);

int qdisc_configure(Link *link, QDisc *qdisc);
int qdisc_section_verify(QDisc *qdisc, bool *has_root, bool *has_clsact);

DEFINE_NETWORK_SECTION_FUNCTIONS(QDisc, qdisc_free);

CONFIG_PARSER_PROTOTYPE(config_parse_qdisc_parent);
CONFIG_PARSER_PROTOTYPE(config_parse_qdisc_handle);

#include "codel.h"
#include "fq-codel.h"
#include "fq.h"
#include "netem.h"
#include "sfq.h"
#include "tbf.h"
#include "teql.h"
