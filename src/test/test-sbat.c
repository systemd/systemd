/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* We include efi_config.h after undefining PROJECT_VERSION which is also defined in config.h. */
#undef PROJECT_VERSION
#include "efi_config.h"

#include "build.h"
#include "sbat.h"
#include "tests.h"

TEST(BOOT_SBAT) {
        log_info("---SBAT-----------&<-----------------------------------------\n"
                 "%s"
                 "------------------>&-----------------------------------------",
#ifdef SBAT_DISTRO
                 SBAT_BOOT_SECTION_TEXT
#else
                 "(not defined)"
#endif
        );
}

TEST(STUB_SBAT) {
        log_info("---SBAT-----------&<-----------------------------------------\n"
                 "%s"
                 "------------------>&-----------------------------------------",
#ifdef SBAT_DISTRO
                 SBAT_STUB_SECTION_TEXT
#else
                 "(not defined)"
#endif
        );
}

DEFINE_TEST_MAIN(LOG_INFO);
