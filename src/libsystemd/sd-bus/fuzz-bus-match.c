/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-match.h"
#include "env-util.h"
#include "fuzz.h"
#include "memstream-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        FILE *g = NULL;
        int r;

        if (outside_size_range(size, 0, 65536))
                return 0;

        fuzz_setup_logging();

        r = sd_bus_new(&bus);
        assert_se(r >= 0);

        _cleanup_(bus_match_free) BusMatchNode root = {
                .type = BUS_MATCH_ROOT,
        };

        /* Note that we use the pointer to match_callback substructure, but the code
         * uses container_of() to access outside of the passed-in type. */
        sd_bus_slot slot = {
                .type = BUS_MATCH_CALLBACK,
                .match_callback = {},
        };

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                assert_se(g = memstream_init(&m));

        for (size_t offset = 0; offset < size; ) {
                _cleanup_free_ char *line = NULL;
                char *end;

                end = memchr((char*) data + offset, '\n', size - offset);

                line = memdup_suffix0((char*) data + offset,
                                      end ? end - (char*) data - offset : size - offset);
                if (!line)
                        return log_oom_debug();

                offset = end ? (size_t) (end - (char*) data + 1) : size;

                BusMatchComponent *components;
                size_t n_components;
                r = bus_match_parse(line, &components, &n_components);
                if (IN_SET(r, -EINVAL, -ENOMEM)) {
                        log_debug_errno(r, "Failed to parse line: %m");
                        continue;
                }
                assert_se(r >= 0); /* We only expect EINVAL and ENOMEM errors, or success. */

                CLEANUP_ARRAY(components, n_components, bus_match_parse_free);

                log_debug("Parsed %zu components.", n_components);

                _cleanup_free_ char *again = bus_match_to_string(components, n_components);
                if (!again) {
                        log_oom();
                        break;
                }

                if (g)
                        fprintf(g, "%s\n", again);

                r = bus_match_add(&root, components, n_components, &slot.match_callback);
                if (r < 0) {
                        log_error_errno(r, "Failed to add match: %m");
                        break;
                }
        }

        bus_match_dump(g ?: stdout, &root, 0); /* We do this even on failure, to check consistency after error. */
        bus_match_free(&root);

        return 0;
}
