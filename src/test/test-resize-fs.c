#include "resize-fs.h"
#include "tests.h"
#include "ernno-util.h"

TEST(resize_fs) {
        uint64_t *k;
        assert_se (resize_fs(2, UINT64_MAX, k) == -ERANGE)
}
