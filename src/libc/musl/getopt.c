/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static void move_to_end(int argc, char * const *argv, int target) {
        char **av = (char**) argv;
        char *saved = av[target];

        for (int i = target + 1; i < argc; i++)
                av[i - 1] = av[i];

        av[argc - 1] = saved;
}

int getopt_long_reorder(
                int argc,
                char * const *argv,
                const char *optstring,
                const struct option *longopts,
                int *longindex) {

        /* If this is not the first call, arguments should be already reordered if necessary. */
        if (optind != 0)
                return (getopt_long)(argc, argv, optstring, longopts, longindex);

        /* From getopt(3):
         * ========
         * If the first character of optstring is '+' or the  environment variable POSIXLY_CORRECT is set,
         * then option processing stops as soon as a nonoption argument is encountered.
         * ======== */
        if ((optstring && optstring[0] == '+') || secure_getenv("POSIXLY_CORRECT"))
                return (getopt_long)(argc, argv, optstring, longopts, longindex);

        /* From getopt(3):
         * ========
         * If the first character of optstring is '-', then each nonoption argv-element is handled as if it
         * were the argument of an option with character code 1.
         * ========
         * So, the prefix is unrelated to that if we should reorder arguments. Simply ignore it. */
        if (optstring && optstring[0] == '-')
                optstring++;

        int saved_argc = argc;

        /* Do not reorder arguments after "--". */
        for (int i = 1; i < argc; i++)
                if (strcmp(argv[i], "--") == 0) {
                        argc = i;
                        break;
                }

        bool dont_move = false;
        for (int i = 1, skipped = 0; i < argc - skipped; ) {
                if (argv[i][0] != '-') {
                        if (dont_move) {
                                i++; /* The previous argument takes an optional argument. Do not reorder this. */
                                dont_move = false;
                        } else {
                                move_to_end(argc, argv, i);
                                skipped++;
                        }
                        continue;
                }

                dont_move = false;

                if (argv[i][1] == '-')
                        for (const struct option *o = longopts; o && o->name; o++) {
                                size_t n = strlen(o->name);
                                if (strncmp(argv[i] + 2, o->name, n) != 0)
                                        continue;

                                if (argv[i][2 + n] == '\0') {
                                        if (o->has_arg == required_argument)
                                                i++; /* The long option takes an argument. */
                                } else if (argv[i][2 + n] == '=') {
                                        if (o->has_arg != no_argument)
                                                i++; /* The long option takes an (optional) argument. */
                                } else
                                        continue;

                                break; /* Found a valid long option. */
                        }
                else if (optstring)
                        for (const char *p = argv[i] + 1; *p != '0'; p++) {
                                const char *o = strchr(optstring, *p);
                                if (!o)
                                        continue; /* Invalid option, ignoring. */

                                if (o[1] != ':')
                                        continue; /* The option does not take an argument, proceeding. */

                                if (o[2] == ':') { /* The option takes an optional argument. */
                                        if (p[1] == '\0')
                                                dont_move = true; /* We may read it as an optional argument. Do not reorder. */
                                } else { /* The option takes an optional argument. */
                                        if (p[1] == '\0')
                                                i++; /* The next element is handled as the argument of this option. */
                                }

                                break; /* The remaining string is handled as the argument of this option. */
                        }

                i++; /* Found an option like string. Keep the ordering regardless if it is a valid option or not. */
        }

        return (getopt_long)(saved_argc, argv, optstring, longopts, longindex);
}
