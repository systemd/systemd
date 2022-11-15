/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-match.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *out = NULL; /* out should be freed after g */
        size_t out_size;
        _cleanup_fclose_ FILE *g = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        int r;

        if (outside_size_range(size, 0, 65536))
                return 0;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        r = sd_bus_new(&bus);
        assert_se(r >= 0);

        struct bus_match_node root = {
                .type = BUS_MATCH_ROOT,
        };

        /* Note that we use the pointer to match_callback substructure, but the code
         * uses container_of() to access outside of the passed-in type. */
        sd_bus_slot slot = {
                .type = BUS_MATCH_CALLBACK,
                .match_callback = {},
        };

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                assert_se(g = open_memstream_unlocked(&out, &out_size));

        for (size_t offset = 0; offset < size; ) {
                _cleanup_free_ char *line = NULL;
                char *end;

                end = memchr((char*) data + offset, '\n', size - offset);

                line = memdup_suffix0((char*) data + offset,
                                      end ? end - (char*) data - offset : size - offset);
                if (!line)
                        return log_oom_debug();

                offset = end ? (size_t) (end - (char*) data + 1) : size;

                struct bus_match_component *components;
                unsigned n_components;
                r = bus_match_parse(line, &components, &n_components);
                if (IN_SET(r, -EINVAL, -ENOMEM)) {
                        log_debug_errno(r, "Failed to parse line: %m");
                        continue;
                }
                assert_se(r >= 0); /* We only expect EINVAL and ENOMEM errors, or success. */

                log_debug("Parsed %u components.", n_components);

                _cleanup_free_ char *again = bus_match_to_string(components, n_components);
                if (!again) {
                        bus_match_parse_free(components, n_components);
                        log_oom();
                        break;
                }

                if (g)
                        fprintf(g, "%s\n", again);

                r = bus_match_add(&root, components, n_components, &slot.match_callback);
                bus_match_parse_free(components, n_components);
                if (r < 0) {
                        log_error_errno(r, "Failed to add match: %m");
                        break;
                }
        }

        bus_match_dump(g ?: stdout, &root, 0); /* We do this even on failure, to check consistency after error. */
        bus_match_free(&root);

        return 0;
}
