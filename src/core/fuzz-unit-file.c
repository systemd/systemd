/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fd-util.h"
#include "fuzz.h"
#include "load-fragment.h"
#include "manager.h"
#include "manager-dump.h"
#include "memstream-util.h"
#include "string-util.h"
#include "unit-serialize.h"
#include "utf8.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        UnitType t;
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        const char *name;
        long offset;

        if (outside_size_range(size, 0, 65536))
                return 0;

        f = data_to_file(data, size);

        assert_se(f);

        if (read_line(f, LINE_MAX, &p) < 0)
                return 0;

        t = unit_type_from_string(p);
        if (t < 0)
                return 0;

        if (!unit_vtable[t]->load)
                return 0;

        offset = ftell(f);
        assert_se(offset >= 0);

        for (;;) {
                _cleanup_free_ char *l = NULL;
                const char *ll;

                if (read_line(f, LONG_LINE_MAX, &l) <= 0)
                        break;

                ll = startswith(l, UTF8_BYTE_ORDER_MARK) ?: l;
                ll = ll + strspn(ll, WHITESPACE);

                if (HAS_FEATURE_MEMORY_SANITIZER && startswith(ll, "ListenNetlink")) {
                        /* ListenNetlink causes a false positive in msan,
                         * let's skip this for now. */
                        log_notice("Skipping test because ListenNetlink= is present");
                        return 0;
                }
        }

        assert_se(fseek(f, offset, SEEK_SET) == 0);

        fuzz_setup_logging();

        assert_se(manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m) >= 0);

        name = strjoina("a.", unit_type_to_string(t));
        assert_se(unit_new_for_name(m, unit_vtable[t]->object_size, name, &u) >= 0);

        (void) config_parse(
                        name, name, f,
                        UNIT_VTABLE(u)->sections,
                        config_item_perf_lookup, load_fragment_gperf_lookup,
                        0,
                        u,
                        NULL);

        _cleanup_(memstream_done) MemStream ms = {};
        FILE *g;

        assert_se(g = memstream_init(&ms));
        unit_dump(u, g, "");
        manager_dump(m, g, /* patterns= */ NULL, ">>>");

        return 0;
}
