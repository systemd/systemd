#include "binfmt-util.h"
#include "tests.h"

TEST(disable_binfmt) {
        ASSERT_OK(disable_binfmt());
}

TEST(binfmt_mounted) {
        ASSERT_OK(binfmt_mounted());
}

static int intro(void) {
        log_show_color(true);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
