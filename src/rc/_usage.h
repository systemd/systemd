/*
 * Copyright (c) 2007-2015 The OpenRC Authors.
 * See the Authors file at the top-level directory of this distribution and
 * https://github.com/OpenRC/openrc/blob/master/AUTHORS
 *
 * This file is part of OpenRC. It is subject to the license terms in
 * the LICENSE file found in the top-level directory of this
 * distribution and at https://github.com/OpenRC/openrc/blob/master/LICENSE
 * This file may not be copied, modified, propagated, or distributed
 *    except according to the terms contained in the LICENSE file.
 */

#include <getopt.h>

#define getoptstring_COMMON "ChqVv"

#define longopts_COMMON							      \
	{ "help",           0, NULL, 'h'},				      \
	{ "nocolor",        0, NULL, 'C'},				      \
	{ "version",        0, NULL, 'V'},				      \
	{ "verbose",        0, NULL, 'v'},				      \
	{ "quiet",          0, NULL, 'q'},				      \
	{ NULL,             0, NULL,  0 }

#define longopts_help_COMMON						      \
	"Display this help output",					      \
	"Disable color output",						      \
	"Display software version",			              \
	"Run verbosely",						      \
	"Run quietly (repeat to suppress errors)"

#define case_RC_COMMON_getopt_case_C  setenv ("EINFO_COLOR", "NO", 1);
#define case_RC_COMMON_getopt_case_h  usage (EXIT_SUCCESS);
#define case_RC_COMMON_getopt_case_V  if (argc == 2) show_version();
#define case_RC_COMMON_getopt_case_v  setenv ("EINFO_VERBOSE", "YES", 1);
#define case_RC_COMMON_getopt_case_q  set_quiet_options();
#define case_RC_COMMON_getopt_default usage (EXIT_FAILURE);

#define case_RC_COMMON_GETOPT						      \
	case 'C': case_RC_COMMON_getopt_case_C; break;			      \
	case 'h': case_RC_COMMON_getopt_case_h; break;			      \
	case 'V': case_RC_COMMON_getopt_case_V; break;			      \
	case 'v': case_RC_COMMON_getopt_case_v; break;			      \
	case 'q': case_RC_COMMON_getopt_case_q; break;			      \
	default:  case_RC_COMMON_getopt_default; break;

extern const char *applet;
extern const char *extraopts;
extern const char *getoptstring;
extern const struct option longopts[];
extern const char * const longopts_help[];
extern const char *usagestring;

void set_quiet_options(void);
void show_version(void);
void usage(int exit_status);
