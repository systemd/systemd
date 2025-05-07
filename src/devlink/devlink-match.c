/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "macro.h"
#include "siphash24.h"
#include "string-table.h"

#include "devlink-match.h"
#include "devlinkd-manager.h"

static const char* const devlink_match_bit_position_table[_DEVLINK_MATCH_BIT_POSITION_MAX] = {
        [DEVLINK_MATCH_BIT_POSITION_DEV] = "Handle",
        [DEVLINK_MATCH_BIT_POSITION_COMMON_INDEX] = "Index",
        [DEVLINK_MATCH_BIT_POSITION_PORT_SPLIT] = "Split",
        [DEVLINK_MATCH_BIT_POSITION_PORT_IFNAME] = "NetdevName",
        [DEVLINK_MATCH_BIT_POSITION_COMMON_NAME] = "Name",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(devlink_match_bit_position, DevlinkMatchBitPosition);

const char* devlink_match_bit_to_string(DevlinkMatchBit bit) {
        return devlink_match_bit_position_to_string(__builtin_ctz(bit));
}

const DevlinkMatchVTable * const devlink_match_vtable[] = {
        &devlink_match_dev_vtable,
        &devlink_match_port_index_vtable,
        &devlink_match_port_split_vtable,
        &devlink_match_port_ifname_vtable,
};

#define DEVLINK_MATCH_VTABLE_SIZE ELEMENTSOF(devlink_match_vtable)

void devlink_match_fini(DevlinkMatch *match) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (devlink_match_vtable[i]->free)
                        devlink_match_vtable[i]->free(match);
        }
}

#define devlink_matchset_bit_check(matchset, bit) ((matchset) & (bit))

DevlinkMatchCheckResult devlink_match_check(
        const DevlinkMatch *match,
        DevlinkMatchSet matchset,
        DevlinkMatchBit *first_extra_bit) {
        DevlinkMatchSet checkset = 0, explicit_checkset = 0;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (devlink_match_vtable[i]->check(match, false))
                        checkset |= devlink_match_vtable[i]->bit;
                if (devlink_match_vtable[i]->check(match, true))
                        explicit_checkset |= devlink_match_vtable[i]->bit;
        }

        if (explicit_checkset == matchset)
                return DEVLINK_MATCH_CHECK_RESULT_MATCH;
        else if (checkset == matchset)
                return DEVLINK_MATCH_CHECK_RESULT_MATCH;
        else if ((explicit_checkset & matchset) != matchset)
                return DEVLINK_MATCH_CHECK_RESULT_INSUFFICIENT_MATCH;

        DevlinkMatchSet extras = explicit_checkset & ~matchset;
        for (unsigned i = 0; i < sizeof(DevlinkMatchSet) * CHAR_BIT; i++) {
                if (devlink_matchset_bit_check(extras, 1U << i)) {
                        *first_extra_bit = 1U << i;
                        break;
                }
        }
        return DEVLINK_MATCH_CHECK_RESULT_EXTRA_MATCH;
}

void devlink_match_log_prefix(
        char **pos,
        int *len,
        const DevlinkMatch *match,
        DevlinkMatchSet matchset) {
        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit))
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
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit))
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
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit))
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
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit))
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
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit))
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
                *matchset |= devlink_match_vtable[i]->bit;
        }
}

int devlink_match_genl_append(
                sd_netlink_message *message,
                const DevlinkMatch *match,
                DevlinkMatchSet matchset) {
        int r;

        for (unsigned i = 0; i < DEVLINK_MATCH_VTABLE_SIZE; i++) {
                if (!devlink_matchset_bit_check(matchset, devlink_match_vtable[i]->bit) ||
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

bool devlink_match_common_index_check(const DevlinkMatch *match, bool explicit) {
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

bool devlink_match_common_name_check(const DevlinkMatch *match, bool explicit) {
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
