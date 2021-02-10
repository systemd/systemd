/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-link.h"

typedef enum TrafficControlKind {
        TC_KIND_QDISC,
        TC_KIND_TCLASS,
        TC_KIND_FILTER,
        _TC_KIND_MAX,
        _TC_KIND_INVALID = -EINVAL,
} TrafficControlKind;

typedef struct TrafficControl {
        TrafficControlKind kind;
} TrafficControl;

/* For casting a tc into the various tc kinds */
#define DEFINE_TC_CAST(UPPERCASE, MixedCase)                           \
        static inline MixedCase* TC_TO_##UPPERCASE(TrafficControl *tc) {                    \
                if (_unlikely_(!tc || tc->kind != TC_KIND_##UPPERCASE))  \
                        return NULL;                                      \
                                                                          \
                return (MixedCase*) tc;                                    \
        }

/* For casting the various tc kinds into a tc */
#define TC(tc) (&(tc)->meta)

void traffic_control_free(TrafficControl *tc);
int link_configure_traffic_control(Link *link);
void network_drop_invalid_traffic_control(Network *network);
