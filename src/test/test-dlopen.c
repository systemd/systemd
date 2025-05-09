/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdlib.h>

#include "macro.h"

int main(int argc, char **argv) {
        void *handles[argc - 1];
        int i;

        for (i = 0; i < argc - 1; i++)
                assert_se(handles[i] = dlopen(argv[i + 1], RTLD_NOW|RTLD_NODELETE));

        for (i--; i >= 0; i--)
                assert_se(dlclose(handles[i]) == 0);

        return EXIT_SUCCESS;
}
