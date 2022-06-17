/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

const char *nfproto_to_string(int n) _const_;
int nfproto_from_string(const char *s) _pure_;

bool nfproto_is_valid(int n);

int af_to_nfproto(int af);
int nfproto_to_af(int n);
