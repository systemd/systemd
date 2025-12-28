/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

typedef void (HookCompleteCallback)(HookQuery *q, int rcode, DnsAnswer *answer, void *userdata);

int manager_hook_query(Manager *m, DnsQuestion *question_idna, DnsQuestion *question_utf8, HookCompleteCallback complete_cb, void *userdata, HookQuery **ret);

HookQuery* hook_query_free(HookQuery *hq);
