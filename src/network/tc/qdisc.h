/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "networkd-util.h"

typedef struct Link Link;
typedef struct Manager Manager;
typedef struct Network Network;

typedef enum QDiscKind {
        QDISC_KIND_BFIFO,
        QDISC_KIND_CAKE,
        QDISC_KIND_CODEL,
        QDISC_KIND_DRR,
        QDISC_KIND_ETS,
        QDISC_KIND_FQ,
        QDISC_KIND_FQ_CODEL,
        QDISC_KIND_FQ_PIE,
        QDISC_KIND_GRED,
        QDISC_KIND_HHF,
        QDISC_KIND_HTB,
        QDISC_KIND_NETEM,
        QDISC_KIND_PFIFO,
        QDISC_KIND_PFIFO_FAST,
        QDISC_KIND_PFIFO_HEAD_DROP,
        QDISC_KIND_PIE,
        QDISC_KIND_QFQ,
        QDISC_KIND_SFB,
        QDISC_KIND_SFQ,
        QDISC_KIND_TBF,
        QDISC_KIND_TEQL,
        _QDISC_KIND_MAX,
        _QDISC_KIND_INVALID = -EINVAL,
} QDiscKind;

typedef struct QDisc {
        Link *link;
        Network *network;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

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
        int (*fill_message)(Link *link, QDisc *qdisc, sd_netlink_message *m);
        int (*verify)(QDisc *qdisc);
        int (*is_ready)(QDisc *qdisc, Link *link);
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

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(QDisc, qdisc);

QDisc* qdisc_free(QDisc *qdisc);
int qdisc_new_static(QDiscKind kind, Network *network, const char *filename, unsigned section_line, QDisc **ret);

int link_find_qdisc(Link *link, uint32_t handle, uint32_t parent, const char *kind, QDisc **qdisc);

int link_request_qdisc(Link *link, QDisc *qdisc);

void network_drop_invalid_qdisc(Network *network);

int manager_rtnl_process_qdisc(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);

DEFINE_SECTION_CLEANUP_FUNCTIONS(QDisc, qdisc_free);

CONFIG_PARSER_PROTOTYPE(config_parse_qdisc_parent);
CONFIG_PARSER_PROTOTYPE(config_parse_qdisc_handle);

#include "cake.h"
#include "codel.h"
#include "ets.h"
#include "fifo.h"
#include "fq-codel.h"
#include "fq-pie.h"
#include "fq.h"
#include "gred.h"
#include "hhf.h"
#include "htb.h"
#include "pie.h"
#include "qfq.h"
#include "netem.h"
#include "drr.h"
#include "sfb.h"
#include "sfq.h"
#include "tbf.h"
#include "teql.h"
