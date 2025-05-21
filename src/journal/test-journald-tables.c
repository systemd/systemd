/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-manager.h"
#include "test-tables.h"
#include "tests.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(SplitMode, split_mode, SPLIT);
        test_table(Storage, storage, STORAGE);

        return EXIT_SUCCESS;
}
