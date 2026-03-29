/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"
#include "networkd-util.h"

typedef enum TFilterKind {
        TFILTER_KIND_FW,
        _TFILTER_KIND_MAX,
        _TFILTER_KIND_INVALID = -EINVAL,
} TFilterKind;

typedef struct TFilter {
        Link *link;
        Network *network;
        ConfigSection *section;
        NetworkConfigSource source;
        NetworkConfigState state;

        unsigned n_ref;

        uint32_t handle;
        uint32_t parent;
        uint32_t classid;
        uint16_t protocol;
        uint16_t priority;

        TFilterKind kind;
        char *tca_kind;
} TFilter;

typedef struct TFilterVTable {
        size_t object_size;
        const char *tca_kind;
        /* called in tfilter_new() */
        int (*init)(TFilter *tfilter);
        int (*fill_message)(Link *link, TFilter *tfilter, sd_netlink_message *m);
        int (*verify)(TFilter *tfilter);
} TFilterVTable;

extern const TFilterVTable * const tfilter_vtable[_TFILTER_KIND_MAX];

#define TFILTER_VTABLE(t) ((t)->kind != _TFILTER_KIND_INVALID ? tfilter_vtable[(t)->kind] : NULL)

/* For casting a tfilter into the various tfilter kinds */
#define DEFINE_TFILTER_CAST(UPPERCASE, MixedCase)                        \
        static inline MixedCase* TFILTER_TO_##UPPERCASE(TFilter *t) {    \
                if (_unlikely_(!t || t->kind != TFILTER_KIND_##UPPERCASE)) \
                        return NULL;                                      \
                                                                          \
                return (MixedCase*) t;                                    \
        }

DEFINE_NETWORK_CONFIG_STATE_FUNCTIONS(TFilter, tfilter);

DECLARE_TRIVIAL_REF_UNREF_FUNC(TFilter, tfilter);
int tfilter_new_static(TFilterKind kind, Network *network, const char *filename, unsigned section_line, TFilter **ret);

void link_tfilter_drop_marked(Link *link);

int link_request_tfilter(Link *link, const TFilter *tfilter);

void network_drop_invalid_tfilter(Network *network);

int manager_rtnl_process_tfilter(sd_netlink *rtnl, sd_netlink_message *message, Manager *m);
int link_enumerate_tfilter(Link *link, uint32_t parent);

DEFINE_SECTION_CLEANUP_FUNCTIONS(TFilter, tfilter_unref);

CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_parent);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_handle);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_protocol);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_priority);
CONFIG_PARSER_PROTOTYPE(config_parse_tfilter_classid);
