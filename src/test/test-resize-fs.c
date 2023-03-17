#include "resize-fs.h"
#include "tests.h"

TEST(resize_fs) {
        uint64_t *k = NULL;
        assert_se (resize_fs(2, UINT64_MAX, k) == -ERANGE);
}

DEFINE_TEST_MAIN(LOG_INFO);
