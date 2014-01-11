#pragma once

#include "util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(asyncns_t*, asyncns_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(unsigned char *, asyncns_freeanswer);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct addrinfo*, asyncns_freeaddrinfo);
#define _cleanup_asyncns_free_ _cleanup_(asyncns_freep)
#define _cleanup_asyncns_answer_free_ _cleanup_(asyncns_freeanswerp)
#define _cleanup_asyncns_addrinfo_free_ _cleanup_(asyncns_freeaddrinfop)
