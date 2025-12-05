/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdbool.h>
#include <string.h>

static int first_non_opt = 0, last_non_opt = 0;
static bool non_opt_found = false, dash_dash = false;

static void shift(char * const *argv, int start, int end) {
        char **av = (char**) argv;
        char *saved = av[end];

        for (int i = end; i > start; i--)
                av[i] = av[i - 1];

        av[start] = saved;
}

static void exchange(int argc, char * const *argv) {
        /* input:
         *
         *  first_non_opt            last_non_opt                          optind
         *       |                        |                                  |
         *       v                        v                                  v
         *     aaaaa       bbbbb        ccccc    --prev-opt  prev-opt-arg  ddddd     --next-opt
         *
         * output:
         *                          first_non_opt                       last_non_opt   optind
         *                                |                                  |           |
         *                                v                                  v           v
         *  --prev-opt  prev-opt-arg    aaaaa      bbbbb        ccccc      ddddd     --next-opt
         */

        /* First, move previous arguments. */
        int c = optind - 1 - last_non_opt;
        if (c > 0) {
                for (int i = 0; i < c; i++)
                        shift(argv, first_non_opt, optind - 1);
                first_non_opt += c;
                last_non_opt += c;
        }

        /* Then, skip entries that do not start with '-'. */
        while (optind < argc && (argv[optind][0] != '-' || argv[optind][1] == '\0')) {
                if (!non_opt_found) {
                        first_non_opt = optind;
                        non_opt_found = true;
                }
                last_non_opt = optind;
                optind++;
        }
}

int getopt_long_fix(
                int argc,
                char * const *argv,
                const char *optstring,
                const struct option *longopts,
                int *longindex) {

        int r;

        if (optind == 0 || first_non_opt == 0 || last_non_opt == 0) {
                /* initialize musl's internal variables. */
                (void) (getopt_long)(/* argc= */ -1, /* argv= */ NULL, /* optstring= */ NULL, /* longopts= */ NULL, /* longindex= */ NULL);
                first_non_opt = last_non_opt = 1;
                non_opt_found = dash_dash = false;
        }

        if (first_non_opt >= argc || last_non_opt >= argc || optind > argc || dash_dash)
                return -1;

        /* Do not shuffle arguments when optstring starts with '+' or '-'. */
        if (!optstring || optstring[0] == '+' || optstring[0] == '-')
                return (getopt_long)(argc, argv, optstring, longopts, longindex);

        exchange(argc, argv);

        if (optind < argc && strcmp(argv[optind], "--") == 0) {
                if (first_non_opt < optind)
                        shift(argv, first_non_opt, optind);
                first_non_opt++;
                optind++;
                dash_dash = true;
                if (non_opt_found)
                        optind = first_non_opt;
                return -1;
        }

        r = (getopt_long)(argc, argv, optstring, longopts, longindex);
        if (r < 0 && non_opt_found)
                optind = first_non_opt;

        return r;
}

int getopt_fix(int argc, char * const *argv, const char *optstring) {
        return getopt_long_fix(argc, argv, optstring, /* longopts= */ NULL, /* longindex= */ NULL);
}
