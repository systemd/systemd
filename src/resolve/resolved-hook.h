/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-future.h"

#include "resolved-forward.h"

int manager_hook_query(Manager *m, DnsQuestion *question_idna, DnsQuestion *question_utf8, HookQuery **ret);

HookQuery* hook_query_free(HookQuery *hq);
DEFINE_TRIVIAL_CLEANUP_FUNC(HookQuery*, hook_query_free);
void hook_query_abort(HookQuery *hq);
int hook_query_get_completion_future(HookQuery *hq, sd_future **ret);
int hook_query_await(HookQuery *hq);
int hook_query_get_result(HookQuery *hq, int *ret_rcode, DnsAnswer **ret_answer);
