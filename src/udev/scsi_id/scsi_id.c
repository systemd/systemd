/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © IBM Corp. 2003
 * Copyright © SUSE Linux Products GmbH, 2006
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "device-nodes.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "scsi_id.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "udev-util.h"

static const struct option options[] = {
        { "device",             required_argument, NULL, 'd' },
        { "config",             required_argument, NULL, 'f' },
        { "page",               required_argument, NULL, 'p' },
        { "denylisted",         no_argument,       NULL, 'b' },
        { "allowlisted",        no_argument,       NULL, 'g' },
        { "blacklisted",        no_argument,       NULL, 'b' }, /* backward compat */
        { "whitelisted",        no_argument,       NULL, 'g' }, /* backward compat */
        { "replace-whitespace", no_argument,       NULL, 'u' },
        { "sg-version",         required_argument, NULL, 's' },
        { "verbose",            no_argument,       NULL, 'v' },
        { "version",            no_argument,       NULL, 'V' }, /* don't advertise -V */
        { "export",             no_argument,       NULL, 'x' },
        { "help",               no_argument,       NULL, 'h' },
        {}
};

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
                type = "zbc";
                break;
        default:
                type = "generic";
                break;
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
static int get_file_options(const char *vendor, const char *model,
                            int *argc, char ***newargv) {
        _cleanup_free_ char *vendor_in = NULL, *model_in = NULL, *options_in = NULL; /* read in from file */
        _cleanup_strv_free_ char **options_argv = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int lineno, r;

        f = fopen(config_file, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 1;
                else {
                        log_error_errno(errno, "can't open %s: %m", config_file);
                        return -1;
                }
        }

        *newargv = NULL;
        lineno = 0;
        for (;;) {
                _cleanup_free_ char *buffer = NULL, *key = NULL, *value = NULL;
                const char *buf;

                vendor_in = model_in = options_in = NULL;

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

                r = extract_many_words(&buf, "=\",\n", 0, &key, &value, NULL);
                if (r < 2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);

                if (strcaseeq(key, "VENDOR")) {
                        vendor_in = TAKE_PTR(value);

                        key = mfree(key);
                        r = extract_many_words(&buf, "=\",\n", 0, &key, &value, NULL);
                        if (r < 2)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error parsing config file line %d '%s'", lineno, buffer);

                        if (strcaseeq(key, "MODEL")) {
                                model_in = TAKE_PTR(value);

                                key = mfree(key);
                                r = extract_many_words(&buf, "=\",\n", 0, &key, &value, NULL);
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

        if (vendor_in == NULL && model_in == NULL && options_in == NULL)
                return 1; /* No matches  */

        /*
        * Something matched. Allocate newargv, and store
        * values found in options_in.
        */
        options_argv = strv_split(options_in, " \t");
        if (!options_argv)
                return log_oom();
        r = strv_prepend(&options_argv, ""); /* getopt skips over argv[0] */
        if (r < 0)
                return r;
        *newargv = TAKE_PTR(options_argv);
        *argc = strv_length(*newargv);

        return 0;
}

static void help(void) {
        printf("Usage: %s [OPTION...] DEVICE\n\n"
               "SCSI device identification.\n\n"
               "  -h --help                        Print this message\n"
               "     --version                     Print version of the program\n\n"
               "  -d --device=                     Device node for SG_IO commands\n"
               "  -f --config=                     Location of config file\n"
               "  -p --page=0x80|0x83|pre-spc3-83  SCSI page (0x80, 0x83, pre-spc3-83)\n"
               "  -s --sg-version=3|4              Use SGv3 or SGv4\n"
               "  -b --denylisted                  Treat device as denylisted\n"
               "  -g --allowlisted                 Treat device as allowlisted\n"
               "  -u --replace-whitespace          Replace all whitespace by underscores\n"
               "  -v --verbose                     Verbose logging\n"
               "  -x --export                      Print values as environment keys\n",
               program_invocation_short_name);
}

static int set_options(int argc, char **argv,
                       char *maj_min_dev) {
        int option;

        /*
         * optind is a global extern used by getopt. Since we can call
         * set_options twice (once for command line, and once for config
         * file) we have to reset this back to 1.
         */
        optind = 1;
        while ((option = getopt_long(argc, argv, "d:f:gp:uvVxhbs:", options, NULL)) >= 0)
                switch (option) {
                case 'b':
                        all_good = false;
                        break;

                case 'd':
                        dev_specified = true;
                        strscpy(maj_min_dev, MAX_PATH_LEN, optarg);
                        break;

                case 'f':
                        strscpy(config_file, MAX_PATH_LEN, optarg);
                        break;

                case 'g':
                        all_good = true;
                        break;

                case 'h':
                        help();
                        exit(EXIT_SUCCESS);

                case 'p':
                        if (streq(optarg, "0x80"))
                                default_page_code = PAGE_80;
                        else if (streq(optarg, "0x83"))
                                default_page_code = PAGE_83;
                        else if (streq(optarg, "pre-spc3-83"))
                                default_page_code = PAGE_83_PRE_SPC3;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown page code '%s'",
                                                       optarg);
                        break;

                case 's':
                        sg_version = atoi(optarg);
                        if (sg_version < 3 || sg_version > 4)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown SG version '%s'",
                                                       optarg);
                        break;

                case 'u':
                        reformat_serial = true;
                        break;

                case 'v':
                        log_set_target(LOG_TARGET_CONSOLE);
                        log_set_max_level(LOG_DEBUG);
                        log_open();
                        break;

                case 'V':
                        version();
                        exit(EXIT_SUCCESS);

                case 'x':
                        export = true;
                        break;

                case '?':
                        return -1;

                default:
                        assert_not_reached();
                }

        if (optind < argc && !dev_specified) {
                dev_specified = true;
                strscpy(maj_min_dev, MAX_PATH_LEN, argv[optind]);
        }

        return 0;
}

static int per_dev_options(struct scsi_id_device *dev_scsi, int *good_bad, int *page_code) {
        _cleanup_strv_free_ char **newargv = NULL;
        int retval;
        int newargc;
        int option;

        *good_bad = all_good;
        *page_code = default_page_code;

        retval = get_file_options(vendor_str, model_str, &newargc, &newargv);

        optind = 1; /* reset this global extern */
        while (retval == 0) {
                option = getopt_long(newargc, newargv, "bgp:", options, NULL);
                if (option == -1)
                        break;

                switch (option) {
                case 'b':
                        *good_bad = 0;
                        break;

                case 'g':
                        *good_bad = 1;
                        break;

                case 'p':
                        if (streq(optarg, "0x80")) {
                                *page_code = PAGE_80;
                        } else if (streq(optarg, "0x83")) {
                                *page_code = PAGE_83;
                        } else if (streq(optarg, "pre-spc3-83")) {
                                *page_code = PAGE_83_PRE_SPC3;
                        } else {
                                log_error("Unknown page code '%s'", optarg);
                                retval = -1;
                        }
                        break;

                default:
                        log_error("Unknown or bad option '%c' (0x%x)", option, (unsigned) option);
                        retval = -1;
                        break;
                }
        }

        return retval;
}

static int set_inq_values(struct scsi_id_device *dev_scsi, const char *path) {
        int retval;

        dev_scsi->use_sg = sg_version;

        retval = scsi_std_inquiry(dev_scsi, path);
        if (retval)
                return retval;

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

/*
 * scsi_id: try to get an id, if one is found, printf it to stdout.
 * returns a value passed to exit() - 0 if printed an id, else 1.
 */
static int scsi_id(char *maj_min_dev) {
        struct scsi_id_device dev_scsi = {};
        int good_dev;
        int page_code;
        int retval = 0;

        if (set_inq_values(&dev_scsi, maj_min_dev) < 0) {
                retval = 1;
                goto out;
        }

        /* get per device (vendor + model) options from the config file */
        per_dev_options(&dev_scsi, &good_dev, &page_code);
        if (!good_dev) {
                retval = 1;
                goto out;
        }

        /* read serial number from mode pages (no values for optical drives) */
        scsi_get_serial(&dev_scsi, maj_min_dev, page_code, MAX_SERIAL_LEN);

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
                if (dev_scsi.wwn[0] != '\0') {
                        printf("ID_WWN=0x%s\n", dev_scsi.wwn);
                        if (dev_scsi.wwn_vendor_extension[0] != '\0') {
                                printf("ID_WWN_VENDOR_EXTENSION=0x%s\n", dev_scsi.wwn_vendor_extension);
                                printf("ID_WWN_WITH_EXTENSION=0x%s%s\n", dev_scsi.wwn, dev_scsi.wwn_vendor_extension);
                        } else
                                printf("ID_WWN_WITH_EXTENSION=0x%s\n", dev_scsi.wwn);
                }
                if (dev_scsi.tgpt_group[0] != '\0')
                        printf("ID_TARGET_PORT=%s\n", dev_scsi.tgpt_group);
                if (dev_scsi.unit_serial_number[0] != '\0')
                        printf("ID_SCSI_SERIAL=%s\n", dev_scsi.unit_serial_number);
                goto out;
        }

        if (dev_scsi.serial[0] == '\0') {
                retval = 1;
                goto out;
        }

        if (reformat_serial) {
                char serial_str[MAX_SERIAL_LEN];

                udev_replace_whitespace(dev_scsi.serial, serial_str, sizeof(serial_str)-1);
                udev_replace_chars(serial_str, NULL);
                printf("%s\n", serial_str);
                goto out;
        }

        printf("%s\n", dev_scsi.serial);
out:
        return retval;
}

int main(int argc, char **argv) {
        _cleanup_strv_free_ char **newargv = NULL;
        int retval = 0;
        char maj_min_dev[MAX_PATH_LEN];
        int newargc;

        log_set_target(LOG_TARGET_AUTO);
        udev_parse_config();
        log_parse_environment();
        log_open();

        /*
         * Get config file options.
         */
        retval = get_file_options(NULL, NULL, &newargc, &newargv);
        if (retval < 0) {
                retval = 1;
                goto exit;
        }
        if (retval == 0) {
                assert(newargv);

                if (set_options(newargc, newargv, maj_min_dev) < 0) {
                        retval = 2;
                        goto exit;
                }
        }

        /*
         * Get command line options (overriding any config file settings).
         */
        if (set_options(argc, argv, maj_min_dev) < 0)
                exit(EXIT_FAILURE);

        if (!dev_specified) {
                log_error("No device specified.");
                retval = 1;
                goto exit;
        }

        retval = scsi_id(maj_min_dev);

exit:
        log_close();
        return retval;
}
