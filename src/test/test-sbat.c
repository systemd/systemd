/* SPDX-License-Identifier: LGPL-2.1-or-later */

#undef PROJECT_VERSION
#include "efi_config.h"

#include "build.h"
#include "sbat.h"
#include "tests.h"

TEST(sbat_section_text) {
        log_info("---SBAT-----------&<----------------------------------------\n"
                 "%s"
                 "------------------>&-----------------------------------------",
#ifdef SBAT_DISTRO
                 SBAT_SECTION_TEXT
#else
                 "(not defined)"
#endif
        );
}

DEFINE_TEST_MAIN(LOG_INFO);
