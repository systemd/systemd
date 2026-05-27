/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "blockdev-list.h"
#include "json-util.h"
#include "repart-list-candidate-devices.h"

int vl_method_list_candidate_devices(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        struct {
                bool ignore_root;
                bool ignore_empty;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "ignoreRoot",  SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_root),  0 },
                { "ignoreEmpty", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, voffsetof(p, ignore_empty), 0 },
                {}
        };

        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        BlockDevice *l = NULL;
        size_t n = 0;
        CLEANUP_ARRAY(l, n, block_device_array_free);

        r = blockdev_list(
                        BLOCKDEV_LIST_SHOW_SYMLINKS|
                        BLOCKDEV_LIST_REQUIRE_PARTITION_SCANNING|
                        BLOCKDEV_LIST_IGNORE_ZRAM|
                        BLOCKDEV_LIST_METADATA|
                        BLOCKDEV_LIST_IGNORE_READ_ONLY|
                        (p.ignore_empty ? BLOCKDEV_LIST_IGNORE_EMPTY : 0)|
                        (p.ignore_root ? BLOCKDEV_LIST_IGNORE_ROOT : 0),
                        &l,
                        &n);
        if (r < 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Repart.NoCandidateDevices");
        if (r < 0)
                return r;

        FOREACH_ARRAY(d, l, n) {
                r = sd_varlink_replybo(link,
                                SD_JSON_BUILD_PAIR_STRING("node", d->node),
                                JSON_BUILD_PAIR_STRV_NON_EMPTY("symlinks", d->symlinks),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("diskseq", d->diskseq, UINT64_MAX),
                                JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("sizeBytes", d->size, UINT64_MAX),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("model", d->model),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("vendor", d->vendor),
                                JSON_BUILD_PAIR_STRING_NON_EMPTY("subsystem", d->subsystem));
                if (r < 0)
                        return r;
        }

        return 0;
}
