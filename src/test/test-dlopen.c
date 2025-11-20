/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdlib.h>

#include "dlfcn-util.h"
#include "shared-forward.h"

int main(int argc, char **argv) {
        void *handles[argc - 1];
        int i;

        for (i = 0; i < argc - 1; i++)
                assert_se(dlopen_safe(argv[i + 1], handles + i, /* reterr_dlerror= */ NULL) >= 0);

        for (i--; i >= 0; i--)
                assert_se(dlclose(handles[i]) == 0);

        return EXIT_SUCCESS;
}
