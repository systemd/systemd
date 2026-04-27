/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © IBM Corp. 2003
 * Copyright © SUSE Linux Products GmbH, 2006
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "build.h"
#include "device-nodes.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "help-util.h"
#include "main-func.h"
#include "options.h"
#include "parse-util.h"
#include "scsi_id.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "udev-util.h"
#include "utf8.h"

static bool all_good = false;
static bool dev_specified = false;
static char config_file[MAX_PATH_LEN] = "/etc/scsi_id.config";
static enum page_code default_page_code = PAGE_UNSPECIFIED;
static int sg_version = 4;
static bool reformat_serial = false;
static bool export = false;
static char vendor_str[64];
static char model_str[64];
static char vendor_enc_str[256];
static char model_enc_str[256];
static char revision_str[16];
static char type_str[16];

static void set_type(unsigned type_num, char *to, size_t len) {
        const char *type;

        switch (type_num) {
        case 0:
                type = "disk";
                break;
        case 1:
                type = "tape";
                break;
        case 4:
                type = "optical";
                break;
        case 5:
                type = "cd";
                break;
        case 7:
                type = "optical";
                break;
        case 0xe:
                type = "disk";
                break;
        case 0xf:
                type = "optical";
                break;
        case 0x14:
                /*
                 * Use "zbc" here to be brief and consistent with "lsscsi" command.
                 * Other tools, e.g., "sg3_utils" would say "host managed zoned block".
                 */
                type = "zbc";
                break;
        default:
                type = "generic";
        }
        strscpy(to, len, type);
}

/*
 * get_file_options:
 *
 * If vendor == NULL, find a line in the config file with only "OPTIONS=";
 * if vendor and model are set find the first OPTIONS line in the config
 * file that matches. Set argc and argv to match the OPTIONS string.
 *
 * vendor and model can end in '\n'.
 */
static int get_file_options(const char *vendor, const char *model, char ***ret_argv) {
        _cleanup_free_ char *vendor_in = NULL, *model_in = NULL, *options_in = NULL; /* read in from file */
        _cleanup_strv_free_ char **options_argv = NULL;
        int r;

        _cleanup_fclose_ FILE *f = fopen(config_file, "re");
        if (!f) {
                if (errno == ENOENT)
                        goto finish;
                return log_error_errno(errno, "Cannot open %s: %m", config_file);
        }

        for (int lineno = 0;;) {
                _cleanup_free_ char *buffer = NULL, *key = NULL, *value = NULL;
                const char *buf;

                r = read_line(f, MAX_BUFFER_LEN, &buffer);
                if (r < 0)
                        return log_error_errno(r, "read_line() on line %d of %s failed: %m", lineno, config_file);
                if (r == 0)
                        break;
                buf = buffer;
                lineno++;

                while (isspace(*buf))
                        buf++;

                /* blank or all whitespace line */
                if (*buf == '\0')
                        continue;

                /* comment line */
                if (*buf == '#')
                        continue;

                r = extract_many_words(&buf, "=\",\n", 0, &key, &value);
                if (r < 2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);

                if (strcaseeq(key, "VENDOR")) {
                        vendor_in = TAKE_PTR(value);

                        key = mfree(key);
                        r = extract_many_words(&buf, "=\",\n", 0, &key, &value);
                        if (r < 2)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);

                        if (strcaseeq(key, "MODEL")) {
                                model_in = TAKE_PTR(value);

                                key = mfree(key);
                                r = extract_many_words(&buf, "=\",\n", 0, &key, &value);
                                if (r < 2)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);
                        }
                }

                if (strcaseeq(key, "OPTIONS"))
                        options_in = TAKE_PTR(value);

                /*
                 * Only allow: [vendor=foo[,model=bar]]options=stuff
                 */
                if (!options_in || (!vendor_in && model_in))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);
                if (!vendor) {
                        if (!vendor_in)
                                break;
                } else if (vendor_in &&
                           startswith(vendor, vendor_in) &&
                           (!model_in || startswith(model, model_in))) {
                                /*
                                 * Matched vendor and optionally model.
                                 *
                                 * Note: a short vendor_in or model_in can
                                 * give a partial match (that is FOO
                                 * matches FOOBAR).
                                 */
                                break;
                }

                vendor_in = mfree(vendor_in);
                model_in = mfree(model_in);
                options_in = mfree(options_in);

        }

        if (!vendor_in && !model_in && !options_in)
                goto finish;  /* No matches  */

        /* Something matched. Allocate newargv, and store values found in options_in. */
        options_argv = strv_split(options_in, " \t");
        if (!options_argv)
                return log_oom();
        r = strv_prepend(&options_argv, ""); /* argv[0] is skipped */
        if (r < 0)
                return r;

 finish:
        *ret_argv = TAKE_PTR(options_argv);
        return !!*ret_argv;  /* true if something matched, false otherwise */
}

static int parse_page_code(const char *value, enum page_code *ret) {
        assert(value);
        assert(ret);

        if (streq(value, "0x80"))
                *ret = PAGE_80;
        else if (streq(value, "0x83"))
                *ret = PAGE_83;
        else if (streq(value, "pre-spc3-83"))
                *ret = PAGE_83_PRE_SPC3;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Unknown page code '%s'", value);
        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        help_cmdline("[OPTION...] DEVICE");
        help_abstract("SCSI device identification.");
        help_section("Options:");

        return table_print_or_warn(options);
}

static int set_options(int argc, char **argv, char *maj_min_dev) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION_WITH_HIDDEN_V:
                        return version();

                OPTION('d', "device", "PATH", "Device node for SG_IO commands"):
                        dev_specified = true;
                        strscpy(maj_min_dev, MAX_PATH_LEN, arg);
                        break;

                OPTION('f', "config", "PATH", "Location of config file"):
                        strscpy(config_file, MAX_PATH_LEN, arg);
                        break;

                OPTION('p', "page", "0x80|0x83|pre-spc3-83", "SCSI page"):
                        r = parse_page_code(arg, &default_page_code);
                        if (r < 0)
                                return r;
                        break;

                OPTION('s', "sg-version", "3|4", "Use SGv3 or SGv4"):
                        r = safe_atoi(arg, &sg_version);
                        if (r < 0)
                                return log_error_errno(r, "Invalid SG version '%s'", arg);
                        if (!IN_SET(sg_version, 3, 4))
                                return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                                       "Unknown SG version '%s'", arg);
                        break;

                OPTION('b', "denylisted", NULL, "Treat device as denylisted"): {}
                OPTION('b', "blacklisted", NULL, /* help= */ NULL): /* backward compat */
                        all_good = false;
                        break;

                OPTION('g', "allowlisted", NULL, "Treat device as allowlisted"): {}
                OPTION('g', "whitelisted", NULL, /* help= */ NULL): /* backward compat */
                        all_good = true;
                        break;

                OPTION('u', "replace-whitespace", NULL, "Replace all whitespace by underscores"):
                        reformat_serial = true;
                        break;

                OPTION('v', "verbose", NULL, "Verbose logging"):
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_set_max_level(LOG_DEBUG);
                        log_open();
                        break;

                OPTION('x', "export", NULL, "Print values as environment keys"):
                        export = true;
                        break;
                }

        char **args = option_parser_get_args(&state);
        if (!strv_isempty(args) && !dev_specified) {
                dev_specified = true;
                strscpy(maj_min_dev, MAX_PATH_LEN, args[0]);
        }

        return 1;
}

static int per_dev_options(struct scsi_id_device *dev_scsi, int *good_bad, enum page_code *page_code) {
        int r;

        assert(dev_scsi);
        assert(good_bad);
        assert(page_code);

        *good_bad = all_good;
        *page_code = default_page_code;

        _cleanup_strv_free_ char **newargv = NULL;
        r = get_file_options(vendor_str, model_str, &newargv);
        if (r <= 0)
                return r;

        size_t newargc = strv_length(newargv);
        if (newargc > INT_MAX)
                return log_oom();  /* Close enough :) */

        OptionParser state = { newargc, newargv };
        const Option *opt;
        const char *arg;

        /* We reuse the option parser, but only a subset of the options is supported here.
         * If any others are encountered, return an error. */

        FOREACH_OPTION_FULL(&state, c, &opt, &arg, /* on_error= */ return c)
                if (opt->short_code == 'b')
                        *good_bad = 0;
                else if (opt->short_code == 'g')
                        *good_bad = 1;
                else if (opt->short_code == 'p') {
                        r = parse_page_code(arg, page_code);
                        if (r < 0)
                                return r;
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Option %s not supported in the config file.",
                                               strnull(option_get_synopsis("", opt, "/", /* show_metavar=*/ false)));

        return 0;
}

static int set_inq_values(struct scsi_id_device *dev_scsi, const char *path) {
        int r;

        dev_scsi->use_sg = sg_version;

        r = scsi_std_inquiry(dev_scsi, path);
        if (r < 0)
                return r;

        encode_devnode_name(dev_scsi->vendor, vendor_enc_str, sizeof(vendor_enc_str));
        encode_devnode_name(dev_scsi->model, model_enc_str, sizeof(model_enc_str));

        udev_replace_whitespace(dev_scsi->vendor, vendor_str, sizeof(vendor_str)-1);
        udev_replace_chars(vendor_str, NULL);
        udev_replace_whitespace(dev_scsi->model, model_str, sizeof(model_str)-1);
        udev_replace_chars(model_str, NULL);
        set_type(dev_scsi->type, type_str, sizeof(type_str));
        udev_replace_whitespace(dev_scsi->revision, revision_str, sizeof(revision_str)-1);
        udev_replace_chars(revision_str, NULL);
        return 0;
}

static bool scsi_string_is_valid(const char *s) {
        return !isempty(s) && utf8_is_valid(s) && !string_has_cc(s, /* ok= */ NULL);
}

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 */
static int scsi_id(char *maj_min_dev) {
        struct scsi_id_device dev_scsi = {};
        enum page_code page_code;
        int good_dev, r;

        r = set_inq_values(&dev_scsi, maj_min_dev);
        if (r < 0)
                return r;

        /* get per device (vendor + model) options from the config file */
        r = per_dev_options(&dev_scsi, &good_dev, &page_code);
        if (r < 0)
                return r;
        if (!good_dev)
                return -EIO;

        /* read serial number from mode pages (no values for optical drives) */
        (void) scsi_get_serial(&dev_scsi, maj_min_dev, page_code, MAX_SERIAL_LEN);

        if (export) {
                char serial_str[MAX_SERIAL_LEN];

                printf("ID_SCSI=1\n");
                printf("ID_VENDOR=%s\n", vendor_str);
                printf("ID_VENDOR_ENC=%s\n", vendor_enc_str);
                printf("ID_MODEL=%s\n", model_str);
                printf("ID_MODEL_ENC=%s\n", model_enc_str);
                printf("ID_REVISION=%s\n", revision_str);
                printf("ID_TYPE=%s\n", type_str);
                if (dev_scsi.serial[0] != '\0') {
                        udev_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str)-1);
                        udev_replace_chars(serial_str, NULL);
                        printf("ID_SERIAL=%s\n", serial_str);
                        udev_replace_whitespace(dev_scsi.serial_short, serial_str, sizeof(serial_str)-1);
                        udev_replace_chars(serial_str, NULL);
                        printf("ID_SERIAL_SHORT=%s\n", serial_str);
                }
                if (scsi_string_is_valid(dev_scsi.wwn)) {
                        printf("ID_WWN=0x%s\n", dev_scsi.wwn);
                        if (scsi_string_is_valid(dev_scsi.wwn_vendor_extension)) {
                                printf("ID_WWN_VENDOR_EXTENSION=0x%s\n", dev_scsi.wwn_vendor_extension);
                                printf("ID_WWN_WITH_EXTENSION=0x%s%s\n", dev_scsi.wwn, dev_scsi.wwn_vendor_extension);
                        } else
                                printf("ID_WWN_WITH_EXTENSION=0x%s\n", dev_scsi.wwn);
                }
                if (scsi_string_is_valid(dev_scsi.tgpt_group))
                        printf("ID_TARGET_PORT=%s\n", dev_scsi.tgpt_group);
                if (scsi_string_is_valid(dev_scsi.unit_serial_number))
                        printf("ID_SCSI_SERIAL=%s\n", dev_scsi.unit_serial_number);
                return 0;
        }

        if (dev_scsi.serial[0] == '\0')
                return -ENODATA;

        if (reformat_serial) {
                char serial_str[MAX_SERIAL_LEN];

                udev_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str)-1);
                udev_replace_chars(serial_str, NULL);
                printf("%s\n", serial_str);
                return 0;
        }

        printf("%s\n", dev_scsi.serial);
        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_strv_free_ char **newargv = NULL;
        char maj_min_dev[MAX_PATH_LEN];
        int r;

        (void) udev_parse_config();
        log_setup();

        /*
         * Get config file options.
         */
        r = get_file_options(NULL, NULL, &newargv);
        if (r < 0)
                return r;
        if (r == 1) {
                size_t newargc = strv_length(newargv);
                if (newargc > INT_MAX)
                        return log_oom();  /* Close enough :) */

                r = set_options(newargc, newargv, maj_min_dev);
                if (r <= 0)
                        return r;
        }

        /*
         * Get command line options (overriding any config file settings).
         */
        r = set_options(argc, argv, maj_min_dev);
        if (r <= 0)
                return r;

        if (!dev_specified)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No device specified.");

        return scsi_id(maj_min_dev);
}

DEFINE_MAIN_FUNCTION(run);
