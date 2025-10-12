/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "log.h"
#include "main-func.h"
#include "pretty-print.h"
#include "string-table.h"

static bool arg_quiet = false;
static enum {
	ANY_FASCISM,
	ONLY_LADYBIRD,
	ONLY_OMARCHY,
	ONLY_HYPRLAND,
	ONLY_DHH
} arg_mode = ANY_FASCISM;

/* detects if os-release is omarchy */
static int detect_omarchy(void) {
	const char *term = "omarchy";
	const int len = 256;

	/* if we cannot access os-release we cannot check */
	if (access("/etc/os-release", F_OK) != 0)
		return -1;

	FILE *osfile = fopen("/etc/os-release", "r");
	char os[len];
	fgets(os, len, osfile);
	if (strcasestr(os, term) != NULL)
		return 1;

	return 0;
}

/*
	detects if the LadyBird browser
	has been built on this machine
	or if the binary exists in $PATH
*/
static unsigned detect_ladybird(void) {

    /* name of the ladybird binary */
    const char* ladybird_bin = "/ladybird";

    /* check if build variable is available */
    char* LADYBIRD_SOURCE_DIR = getenv("LADYBIRD_SOURCE_DIR");
    if (LADYBIRD_SOURCE_DIR != NULL)
        return 1;

    char* PATH = getenv("PATH");
    if (PATH == NULL)
        return 0;

	/* this value will get mutated so we need to duplicate it */
    char* path = strdup(PATH);
    /* loop through PATH until we find a file named "ladybird" */
    char* path_iter = strtok(path, ":");
    char* abs_path = malloc(256);
    while (path_iter != NULL) {
        strncat(abs_path, path_iter, 128);
        strncat(abs_path, ladybird_bin, 128);
        /* if we do NOT find the binary at current path, keep going */
        if (access(abs_path, F_OK) != 0){
            path_iter = strtok(NULL, ":");
            abs_path[0] = 0;
            continue;
        }
        free(abs_path);
		free(path);
        return 1;
    }
	free(abs_path);
	free(path);
    return 0;
}

/* detects if hyprland is installed */
static unsigned detect_hyprland(void) {
	const char* hyprland_config = "/hypr/hyprland.conf";
	const char* XDG_CONFIG_HOME = getenv("XDG_CONFIG_HOME");
	const char* HOME = getenv("HOME");
	int maxlen = 128;

	char *hyprland_abs_path = malloc(maxlen);

	if (XDG_CONFIG_HOME != NULL) {
		strncat(hyprland_abs_path, XDG_CONFIG_HOME, maxlen - strlen(hyprland_config));
	} else if (HOME != NULL) {
		strncat(hyprland_abs_path, HOME, maxlen - strlen(hyprland_config));
		strcat(hyprland_abs_path, "/.config");
	} else {
		return 0;
	}
	strcat(hyprland_abs_path, hyprland_config);
	if (access(hyprland_abs_path, F_OK) == 0){
		free(hyprland_abs_path);
		return 1;
	}
	free(hyprland_abs_path);
	return 0;
}

/* detects if this is dhh's computer using his ssh pubkey */
static int detect_dhh(void) {
	/* fingerprint of dhh's ssh public key */
	const char *dhh_fingerprint = "SHA256:YCKX7xo5Hkihy/NVH5ang8Oty9q8Vvqu4sxI7EbDxPg";
	/* path to ssh pubkey */
	const char *ssh_pubkey = "/.ssh/id_ed25519.pub";
    /* command to generate fingerprint */
    const char *ssh_fingerpint_cmd = "ssh-keygen -E sha256 -lf ";

	/* get the home directory */
	char *HOME = getenv("HOME");
    
	if (HOME == NULL)
		return -1;
	/* check if we have read access to the public key on disk */
    char *ssh_pubkey_abs_path = (char *)malloc(strlen(HOME) + strlen(ssh_pubkey) + 1);
	ssh_pubkey_abs_path[0] = 0;
	strcat(ssh_pubkey_abs_path, HOME);
	strcat(ssh_pubkey_abs_path, ssh_pubkey);
	if (access(ssh_pubkey_abs_path, F_OK) != 0)
		return 0;
	
	/* generate a fingerprint of it */
	char *get_fingerprint_cmd = (char *)malloc(strlen(ssh_fingerpint_cmd) + strlen(ssh_pubkey_abs_path) + 1);
	get_fingerprint_cmd[0] = 0;
	strcat(get_fingerprint_cmd, ssh_fingerpint_cmd);
	strcat(get_fingerprint_cmd, ssh_pubkey_abs_path);
	
	char fingerprint[70];
	FILE *fingerprint_cmd_output = popen(get_fingerprint_cmd, "r");
	
	if (fingerprint_cmd_output == NULL)
		return -1;
	fgets(fingerprint, 70, fingerprint_cmd_output);

	/* free memory */
	pclose(fingerprint_cmd_output);
	free(ssh_pubkey_abs_path);
	free(get_fingerprint_cmd);

	/* comare it to DHH's fingerprint */
	if (strstr(fingerprint, dhh_fingerprint) != NULL)
		return 1;
	return 0;
}

static int help(void) {
	_cleanup_free_ char *link = NULL;
	int r;

	r = terminal_urlify_man("systemd-detect-fash", "1", &link);
	if (r < 0)
		return log_oom();

	printf("%s [OPTIONS...]\n\n"
	       "Detect execution in a fascist environment.\n\n"
	       "  -h --help             Show this help\n"
	       "     --version          Show package version\n"
		   "  -q --quiet        	Quiet mode\n"
	       "  -o --omarchy        	Only detect omarchy\n"
	       "  -l --ladybird         Only detect ladybird\n"
		   "  -y --hyprland         Only detect hyprland\n"
		   "  -d --dhh              Only detect dhh\n"
	       "\nSee the %s for details.\n",
	       program_invocation_short_name,
	       link);

	return 0;
}

static int parse_argv(int argc, char *argv[]) {

	enum {
		ARG_VERSION = 0x100,
		ARG_OMARCHY,
		ARG_LADYBIRD,
		ARG_HYPRLAND,
		ARG_DHH
	};

	static const struct option options[] = {
		{ "help",          no_argument, NULL, 'h'               },
		{ "version",       no_argument, NULL, ARG_VERSION       },
		{ "omarchy",       no_argument, NULL, 'o'               },
		{ "ladybird",      no_argument, NULL, 'l'               },
		{ "hyprland",      no_argument, NULL, 'y'               },
		{ "dhh",           no_argument, NULL, 'd'               },
		{}
	};

	int c;

	assert(argc >= 0);
	assert(argv);

	while ((c = getopt_long(argc, argv, "hqolyd", options, NULL)) >= 0)

		switch (c) {

		case 'h':
			return help();

		case ARG_VERSION:
			return version();

		case 'q':
			arg_quiet = true;
			break;

		case 'l':
			arg_mode = ONLY_LADYBIRD;
			break;

		case 'o':
			arg_mode = ONLY_OMARCHY;
			break;
		
		case 'y':
			arg_mode = ONLY_HYPRLAND;
			break;
		
		case 'd':
			arg_mode = ONLY_DHH;
			break;

		case '?':
			return -EINVAL;

		default:
			assert_not_reached();
		}
	return 1;
}

static int run(int argc, char *argv[]) {
	int dhh = 0;
	int hyprland = 0;
	int ladybird = 0;
	int omarchy = 0;
	int fascism = 0;
	int r;

	/* This is mostly intended to be used for scripts which want
	 * to detect whether we are being run in a fascist
	 * environment or not */

	log_setup();

	r = parse_argv(argc, argv);
	if (r <= 0)
		return r;

	switch (arg_mode) {
	case ONLY_OMARCHY:
		omarchy = detect_omarchy();
		fascism = omarchy;
		if (omarchy < 0)
			return log_error_errno(fascism, "Failed to check for omarchy: %m");
		break;

	case ONLY_LADYBIRD:
		ladybird = detect_ladybird();
		fascism = ladybird;
		if (ladybird < 0)
			return log_error_errno(fascism, "Failed to check for ladybird: %m");
		break;
	
	case ONLY_HYPRLAND:
		hyprland = detect_hyprland();
		fascism = hyprland;
		if (hyprland < 0)
			return log_error_errno(fascism, "Failed to check for hyprland: %m");
		break;
	
	case ONLY_DHH:
		dhh = detect_dhh();
		fascism = dhh;
		if (dhh < 0)
			return log_error_errno(fascism, "Failed to check for dhh: %m");
		break;

	case ANY_FASCISM:
	default:
		ladybird = detect_ladybird();
		omarchy = detect_omarchy();
		hyprland = detect_hyprland();
		dhh = detect_dhh();
		fascism = (ladybird | omarchy | hyprland | dhh);
		if (fascism < 0)
			return log_error_errno(fascism, "Failed to check for fascism: %m");
	}

	if (!arg_quiet) {
		if (ladybird) puts("ladybird");
		if (omarchy) puts("omarchy");
		if (dhh) puts("dhh");
		if (hyprland) puts("hyprland");
	}
	return fascism;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
