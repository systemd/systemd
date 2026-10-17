/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "timestampd.h"

int timestamp_authority_validate(const char *authority);

int timestamp_request_start(
                Manager *m,
                sd_varlink *link,
                const char *authority,
                void *request_der,
                size_t request_der_size);

void manager_cancel_all_requests(Manager *m);
