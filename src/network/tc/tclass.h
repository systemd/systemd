/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2019 VMware, Inc. */
#pragma once

#include "conf-parser.h"
#include "networkd-link.h"
#include "networkd-network.h"
#include "networkd-util.h"
#include "tc.h"

typedef enum TClassKind {
        TCLASS_KIND_DRR,
        TCLASS_KIND_HTB,
        TCLASS_KIND_QFQ,
        _TCLASS_KIND_MAX,
        _TCLASS_KIND_INVALID = -EINVAL,
} TClassKind;

typedef struct TClass {
        TrafficControl meta;

        NetworkConfigSection *section;
        Network *network;

        uint32_t classid;
        uint32_t parent;

        TClassKind kind;
} TClass;

typedef struct TClassVTable {
        size_t object_size;
        const char *tca_kind;
        /* called in tclass_new() */
        int (*init)(TClass *tclass);
        int (*fill_message)(Link *link, TClass *tclass, sd_netlink_message *m);
        int (*verify)(TClass *tclass);
} TClassVTable;

extern const TClassVTable * const tclass_vtable[_TCLASS_KIND_MAX];

#define TCLASS_VTABLE(t) ((t)->kind != _TCLASS_KIND_INVALID ? tclass_vtable[(t)->kind] : NULL)

/* For casting a tclass into the various tclass kinds */
#define DEFINE_TCLASS_CAST(UPPERCASE, MixedCase)                          \
        static inline MixedCase* TCLASS_TO_##UPPERCASE(TClass *t) {       \
                if (_unlikely_(!t || t->kind != TCLASS_KIND_##UPPERCASE)) \
                        return NULL;                                      \
                                                                          \
                return (MixedCase*) t;                                    \
        }

/* For casting the various tclass kinds into a tclass */
#define TCLASS(t) (&(t)->meta)

TClass* tclass_free(TClass *tclass);
int tclass_new_static(TClassKind kind, Network *network, const char *filename, unsigned section_line, TClass **ret);

int tclass_configure(Link *link, TClass *tclass);
int tclass_section_verify(TClass *tclass);

DEFINE_NETWORK_SECTION_FUNCTIONS(TClass, tclass_free);

DEFINE_TC_CAST(TCLASS, TClass);

CONFIG_PARSER_PROTOTYPE(config_parse_tclass_parent);
CONFIG_PARSER_PROTOTYPE(config_parse_tclass_classid);

#include "drr.h"
#include "htb.h"
#include "qfq.h"
