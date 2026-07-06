/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "link-config.h"
#include "test-tables.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_link_config_load_reload(void) {
        /* Loading link configuration into an already-populated context (as link_config_load() itself
         * does via its initial clear) must not leave ctx->configs pointing at freed entries. If the clear
         * leaves the list head dangling, the reload below and the context teardown afterwards touch freed
         * memory. */

        _cleanup_(link_config_ctx_freep) LinkConfigContext *ctx = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/test-link-config.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;

        ASSERT_OK(link_config_ctx_new(&ctx));

        ASSERT_OK(fmkostemp_safe(filename, "r+", &f));
        ASSERT_OK(fputs("[Match]\nOriginalName=*\n\n[Link]\nMTUBytes=1500\n", f));
        ASSERT_OK(fflush(f));

        /* Populate the context with one configuration. */
        ASSERT_OK(link_load_one(ctx, filename));

        /* Reload into the same, already-populated context. */
        ASSERT_OK(link_config_load(ctx));
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(MACAddressPolicy, mac_address_policy, MAC_ADDRESS_POLICY);
        test_table(IRQAffinityPolicy, irq_affinity_policy, IRQ_AFFINITY_POLICY);

        test_link_config_load_reload();

        return EXIT_SUCCESS;
}
