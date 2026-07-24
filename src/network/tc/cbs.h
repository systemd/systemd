/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "qdisc.h"

typedef struct CreditBasedShaper {
        QDisc meta;

        int32_t hicredit;
        int32_t locredit;
        int32_t idleslope;  /* in kbps */
        int32_t sendslope;  /* in kbps */
        int offload;         /* tristate: -1 unset, 0 no, 1 yes */
} CreditBasedShaper;

DEFINE_QDISC_CAST(CBS, CreditBasedShaper);
extern const QDiscVTable cbs_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_cbs_slope);
CONFIG_PARSER_PROTOTYPE(config_parse_cbs_s32);
CONFIG_PARSER_PROTOTYPE(config_parse_cbs_tristate);
