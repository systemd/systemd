/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chid-match-util.h"
#include "efi.h"

#include "./chid.c"

void chid_match_reset_cache(void) {
        smbios_info_populate_internal(NULL, true);
}

static RawSmbiosInfo current_info = {};

void chid_match_set_raw(RawSmbiosInfo info) {
        current_info = info;
}

/* This is a dummy implementation for testing purposes */
void smbios_raw_info_populate(RawSmbiosInfo *ret_info) {
        assert(ret_info);
        *ret_info = current_info;
}
