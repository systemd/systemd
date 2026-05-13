/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolve-hook-util.h"
#include "dns-question.h"

void resolve_record_parameters_done(ResolveRecordParameters *p) {
        assert(p);

        dns_question_unref(p->question);
}

const sd_json_dispatch_field resolve_record_parameters_dispatch_table[] = {
        { "question", SD_JSON_VARIANT_ARRAY, dns_json_dispatch_question, offsetof(ResolveRecordParameters, question), SD_JSON_MANDATORY },
        {}
};
