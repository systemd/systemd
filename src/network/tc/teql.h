/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "conf-parser.h"
#include "qdisc.h"

typedef struct TrivialLinkEqualizer {
        QDisc meta;

        unsigned id;
} TrivialLinkEqualizer;

DEFINE_QDISC_CAST(TEQL, TrivialLinkEqualizer);
extern const QDiscVTable teql_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_trivial_link_equalizer_id);
