/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fd-util.h"
#include "fuzz.h"
#include "load-fragment.h"
#include "manager.h"
#include "manager-dump.h"
#include "memstream-util.h"
#include "string-util.h"
#include "tests.h"
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

        if (outside_size_range(size, /* lower= */ 0, 65536))
                return 0;

        f = ASSERT_NOT_NULL(data_to_file(data, size));

        if (read_line(f, LINE_MAX, &p) < 0)
                return 0;

        t = unit_type_from_string(p);
        if (t < 0)
                return 0;

        if (!unit_vtable[t]->load)
                return 0;

        offset = ftell(f);
        ASSERT_OK(offset);

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

        ASSERT_EQ(fseek(f, offset, SEEK_SET), 0);

        fuzz_setup_logging();

        ASSERT_OK(manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_MINIMAL|MANAGER_TEST_DONT_OPEN_EXECUTOR, &m));

        name = strjoina("a.", unit_type_to_string(t));
        ASSERT_OK(unit_new_for_name(m, unit_vtable[t]->object_size, name, &u));

        (void) config_parse(
                        name, name, f,
                        UNIT_VTABLE(u)->sections,
                        config_item_perf_lookup, load_fragment_gperf_lookup,
                        /* flags= */ 0,
                        u,
                        /* ret_stat= */ NULL);

        _cleanup_(memstream_done) MemStream ms = {};
        FILE *g;

        g = ASSERT_NOT_NULL(memstream_init(&ms));
        unit_dump(u, g, "");
        manager_dump(m, g, /* patterns= */ NULL, ">>>");

        return 0;
}
