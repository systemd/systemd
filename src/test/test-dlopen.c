/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dlfcn.h>
#include <stdlib.h>

#include "macro.h"

int main(int argc, char **argv) {
        void *handle;

        assert_se(handle = dlopen(argv[1], RTLD_NOW));
        assert_se(dlclose(handle) == 0);

        return EXIT_SUCCESS;
}
