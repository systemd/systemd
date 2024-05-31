/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-has-tpm2.h"
#include "tpm2-util.h"

int verb_has_tpm2(int argc, char **argv, void *userdata) {
        Tpm2Support s;

        s = tpm2_support();

        if (!arg_quiet) {
                if (s == TPM2_SUPPORT_FULL)
                        puts("yes");
                else if (s == TPM2_SUPPORT_NONE)
                        puts("no");
                else
                        puts("partial");

                printf("%sfirmware\n"
                       "%sdriver\n"
                       "%ssystem\n"
                       "%ssubsystem\n"
                       "%slibraries\n",
                       plus_minus(s & TPM2_SUPPORT_FIRMWARE),
                       plus_minus(s & TPM2_SUPPORT_DRIVER),
                       plus_minus(s & TPM2_SUPPORT_SYSTEM),
                       plus_minus(s & TPM2_SUPPORT_SUBSYSTEM),
                       plus_minus(s & TPM2_SUPPORT_LIBRARIES));
        }

        /* Return inverted bit flags. So that TPM2_SUPPORT_FULL becomes EXIT_SUCCESS and the other values
         * become some reasonable values 1…7. i.e. the flags we return here tell what is missing rather than
         * what is there, acknowledging the fact that for process exit statuses it is customary to return
         * zero (EXIT_FAILURE) when all is good, instead of all being bad. */
        return ~s & TPM2_SUPPORT_FULL;
}
