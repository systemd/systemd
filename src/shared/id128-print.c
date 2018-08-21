/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>

#include "sd-id128.h"

#include "id128-print.h"
#include "log.h"

int id128_generate_new(void) {
        sd_id128_t id;
        int r;
        unsigned i;

        r = sd_id128_randomize(&id);
        if (r < 0)
                return log_error_errno(r, "Failed to generate ID: %m");

        printf("As string:\n"
               SD_ID128_FORMAT_STR "\n\n"
               "As UUID:\n"
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n\n"
               "As man:sd-id128(3) macro:\n"
               "#define MESSAGE_XYZ SD_ID128_MAKE(",
               SD_ID128_FORMAT_VAL(id),
               SD_ID128_FORMAT_VAL(id));
        for (i = 0; i < 16; i++)
                printf("%02x%s", id.bytes[i], i != 15 ? "," : "");
        fputs(")\n\n", stdout);

        printf("As Python constant:\n"
               ">>> import uuid\n"
               ">>> MESSAGE_XYZ = uuid.UUID('" SD_ID128_FORMAT_STR "')\n",
               SD_ID128_FORMAT_VAL(id));

        return 0;
}
