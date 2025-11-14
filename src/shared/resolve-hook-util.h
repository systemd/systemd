/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "shared-forward.h"

typedef struct ResolveRecordParameters {
        DnsQuestion *question;
} ResolveRecordParameters;

void resolve_record_parameters_done(ResolveRecordParameters *p);

extern const sd_json_dispatch_field resolve_record_parameters_dispatch_table[];
