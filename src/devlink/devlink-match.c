/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "netlink-util.h"
#include "siphash24.h"

#include "devlink-match.h"
#include "devlinkd-manager.h"

/* Has to be in-sync with DevlinkMatchBit */
const DevlinkMatchVTable * const devlink_match_vtable[] = {
        &devlink_match_dev_vtable,
        &devlink_match_port_index_vtable,
        &devlink_match_port_split_vtable,
        &devlink_match_port_ifname_vtable,
        &devlink_match_param_vtable,
        &devlink_match_health_reporter_vtable,
};

#define DEVLINK_MATCH_VTABLE_SIZE ELEMENTSOF(devlink_match_vtable)

void devlink_match_fini(DevlinkMatch *match) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (devlink_match_vtable[i]->free)
                        devlink_match_vtable[i]->free(match);
        }
}

#define devlink_matchset_bit_check(matchset, bitnum) (matchset & (1 << i))

bool devlink_match_check(const DevlinkMatch *match, DevlinkMatchSet matchset) {
        bool r;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;
                r = devlink_match_vtable[i]->check(match);
                if (!r)
                        return r;
        }
        return true;
}

void devlink_match_log_prefix(char **pos, int *len, const DevlinkMatch *match, DevlinkMatchSet matchset) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;

                BUFFER_APPEND(*pos, *len, " ");
                devlink_match_vtable[i]->log_prefix(pos, len, match);
        }
}

void devlink_match_hash(
                const DevlinkMatch *match,
                DevlinkMatchSet matchset,
                struct siphash *state) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;
                devlink_match_vtable[i]->hash_func(match, state);
        }
}

int devlink_match_compare(
                const DevlinkMatch *x,
                const DevlinkMatch *y,
                DevlinkMatchSet matchset) {
        int d;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;
                d = devlink_match_vtable[i]->compare_func(x, y);
                if (d)
                        return d;
        }
        return 0;
}

int devlink_match_copy(
                DevlinkMatch *dst,
                const DevlinkMatch *src,
                DevlinkMatchSet matchset) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;
                assert(devlink_match_vtable[i]->copy_func);
                devlink_match_vtable[i]->copy_func(dst, src);
        }
        return 0;
}

int devlink_match_duplicate(
                DevlinkMatch *dst,
                const DevlinkMatch *src,
                DevlinkMatchSet matchset) {
        int r;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i))
                        continue;
                assert(devlink_match_vtable[i]->duplicate_func);
                r = devlink_match_vtable[i]->duplicate_func(dst, src);
                if (r)
                        return r;
        }
        return 0;
}

void devlink_match_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match,
                DevlinkMatchSet *matchset) {
        int r;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                r = devlink_match_vtable[i]->genl_read(message, m, match);
                if (r < 0)
                        continue;
                *matchset |= 1 << i;
        }
}

int devlink_match_genl_append(
                sd_netlink_message *message,
                const DevlinkMatch *match,
                DevlinkMatchSet matchset) {
        int r;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, i) ||
                    !devlink_match_vtable[i]->genl_append)
                        continue;
                r = devlink_match_vtable[i]->genl_append(message, match);
                if (r < 0)
                        return r;
        }
        return 0;
}

/* Common config parse helpers. */

int config_parse_devlink_index(CONFIG_PARSER_ARGUMENTS) {
        DevlinkMatchCommon *common = data;
        int r;

        r = config_parse_uint32(unit, filename, line, section, section_line, lvalue, ltype,
                                rvalue, &common->index, userdata);
        if (r < 0)
                return r;
        common->index_valid = true;
        return 0;
}

/* Common match callbacks. */

bool devlink_match_common_index_check(const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;

        if (!common->index_valid) {
                log_debug("Match index not configured.");
                return false;
        }
        return true;
}

void devlink_match_common_index_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;

        BUFFER_APPEND(*buf, *len, "common_index %u", common->index);
}

void devlink_match_common_index_hash_func(const DevlinkMatch *match, struct siphash *state) {
        const DevlinkMatchCommon *common = &match->common;

        siphash24_compress_typesafe(common->index, state);
}

int devlink_match_common_index_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        const DevlinkMatchCommon *xcommon = &x->common;
        const DevlinkMatchCommon *ycommon = &y->common;

        assert(xcommon->index_valid);
        assert(ycommon->index_valid);

        return CMP(xcommon->index, ycommon->index);
}

void devlink_match_common_index_copy_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        DevlinkMatchCommon *dstcommon = &dst->common;
        const DevlinkMatchCommon *srccommon = &src->common;

        assert(srccommon->index_valid);

        dstcommon->index = srccommon->index;
        dstcommon->index_valid = srccommon->index_valid;
}

int devlink_match_common_index_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        devlink_match_common_index_copy_func(dst, src);
        return 0;
}

void devlink_match_common_name_free(DevlinkMatch *match) {
        DevlinkMatchCommon *common = &match->common;

        common->name = mfree(common->name);
}

bool devlink_match_common_name_check(const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;

        if (!common->name) {
                log_debug("Match name not configured.");
                return false;
        }
        return true;
}

void devlink_match_common_name_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;

        BUFFER_APPEND(*buf, *len, "name %s", common->name);
}

void devlink_match_common_name_hash_func(const DevlinkMatch *match, struct siphash *state) {
        const DevlinkMatchCommon *common = &match->common;

        assert(common->name);

        string_hash_func(common->name, state);
}

int devlink_match_common_name_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        const DevlinkMatchCommon *xcommon = &x->common;
        const DevlinkMatchCommon *ycommon = &y->common;

        return strcmp(xcommon->name, ycommon->name);
}

void devlink_match_common_name_copy_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        DevlinkMatchCommon *dstcommon = &dst->common;
        const DevlinkMatchCommon *srccommon = &src->common;

        dstcommon->name = srccommon->name;
}
