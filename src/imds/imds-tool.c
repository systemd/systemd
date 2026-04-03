/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "build-path.h"
#include "creds-util.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "imds-util.h"
#include "in-addr-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "pcrextend-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"

static enum {
        ACTION_SUMMARY,
        ACTION_GET,
        ACTION_USERDATA,
        ACTION_IMPORT,
        _ACTION_INVALID = -EINVAL,
} arg_action = _ACTION_INVALID;
static char *arg_key = NULL;
static ImdsWellKnown arg_well_known = _IMDS_WELL_KNOWN_INVALID;
static int arg_cache = -1;
static usec_t arg_refresh_usec = 0;
static bool arg_refresh_usec_set = false;

STATIC_DESTRUCTOR_REGISTER(arg_key, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-imds", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [KEY]\n"
               "\n%sIMDS data acquisition.%s\n\n"
               "  -h --help            Show this help\n"
               "     --version         Show package version\n"
               "  -K --well-known=[hostname|region|zone|ipv4-public|ipv6-public|ssh-key|\n"
               "                  userdata|userdata-base|userdata-base64]\n"
               "                       Select well-known key/base\n"
               "     --refresh=SEC     Set minimum freshness time for returned data\n"
               "     --cache=no        Disable cache use\n"
               "  -u --userdata        Dump user data\n"
               "     --import          Import system credentials from IMDS userdata\n"
               "                       and place them in /run/credstore/\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_REFRESH,
                ARG_CACHE,
                ARG_IMPORT,
        };

        static const struct option options[] = {
                { "help",       no_argument,       NULL, 'h'         },
                { "version",    no_argument,       NULL, ARG_VERSION },
                { "well-known", required_argument, NULL, 'K'         },
                { "refresh",    required_argument, NULL, ARG_REFRESH },
                { "cache",      required_argument, NULL, ARG_CACHE   },
                { "userdata",   no_argument,       NULL, 'u'         },
                { "import",     no_argument,       NULL, ARG_IMPORT  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hK:u", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'K': {
                        if (isempty(optarg)) {
                                arg_well_known = _IMDS_WELL_KNOWN_INVALID;
                                break;
                        }

                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(imds_well_known, ImdsWellKnown, _IMDS_WELL_KNOWN_MAX);

                        ImdsWellKnown wk = imds_well_known_from_string(optarg);
                        if (wk < 0)
                                return log_error_errno(wk, "Failed to parse --well-known= argument: %s", optarg);

                        arg_well_known = wk;
                        break;
                }

                case ARG_CACHE:
                        r = parse_tristate_argument_with_auto("--cache=", optarg, &arg_cache);
                        if (r < 0)
                                return r;

                        break;

                case ARG_REFRESH: {
                        if (isempty(optarg)) {
                                arg_refresh_usec_set = false;
                                break;
                        }

                        usec_t t;
                        r = parse_sec(optarg, &t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse refresh timeout: %s", optarg);

                        arg_refresh_usec = t;
                        arg_refresh_usec_set = true;
                        break;
                }

                case 'u':
                        arg_action = ACTION_USERDATA;
                        break;

                case ARG_IMPORT:
                        arg_action = ACTION_IMPORT;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (IN_SET(arg_action, ACTION_USERDATA, ACTION_IMPORT)) {
                if (argc != optind)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No parameters expected.");

        } else {
                assert(arg_action < 0);

                if (argc > optind + 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "None or one argument expected.");

                if (argc == optind && arg_well_known < 0)
                        arg_action = ACTION_SUMMARY;
                else {
                        if (arg_well_known < 0)
                                arg_well_known = IMDS_BASE;

                        if (argc > optind) {
                                if (!imds_key_is_valid(argv[optind]))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified IMDS key is not valid, refusing: %s", argv[optind]);

                                if (!imds_well_known_can_suffix(arg_well_known))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Well known key '%s' does not take a key suffix, refusing.", imds_well_known_to_string(arg_well_known));

                                r = free_and_strdup_warn(&arg_key, argv[optind]);
                                if (r < 0)
                                        return r;
                        }

                        arg_action = ACTION_GET;
                }
        }

        return 1;
}

static int acquire_imds_key(
                sd_varlink *link,
                ImdsWellKnown wk,
                const char *key,
                struct iovec *ret) {

        int r;

        assert(link);
        assert(wk >= 0);
        assert(wk < _IMDS_WELL_KNOWN_MAX);
        assert(ret);

        const char *error_id = NULL;
        sd_json_variant *reply = NULL;
        r = sd_varlink_callbo(
                        link,
                        "io.systemd.InstanceMetadata.Get",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR_CONDITION(wk != IMDS_BASE, "wellKnown", JSON_BUILD_STRING_UNDERSCORIFY(imds_well_known_to_string(wk))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("key", key),
                        SD_JSON_BUILD_PAIR_CONDITION(arg_refresh_usec_set, "refreshUSec", SD_JSON_BUILD_UNSIGNED(arg_refresh_usec)),
                        SD_JSON_BUILD_PAIR_CONDITION(arg_cache >= 0, "cache", SD_JSON_BUILD_BOOLEAN(arg_cache)));
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.InstanceMetadata.Get(): %m");
        if (error_id) {
                if (STR_IN_SET(error_id, "io.systemd.InstanceMetadata.KeyNotFound", "io.systemd.InstanceMetadata.WellKnownKeyUnset")) {
                        *ret = (struct iovec) {};
                        return 0;
                }

                return log_error_errno(sd_varlink_error_to_errno(error_id, reply), "Failed to issue io.systemd.InstanceMetadata.Get(): %s", error_id);
        }

        _cleanup_(iovec_done) struct iovec data = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "data", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec, 0, SD_JSON_MANDATORY },
                {},
        };
        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &data);
        if (r < 0)
                return r;

        *ret = TAKE_STRUCT(data);
        return 1;
}

static int acquire_imds_key_as_string(
                sd_varlink *link,
                ImdsWellKnown wk,
                const char *key,
                char **ret) {

        int r;

        assert(link);
        assert(wk >= 0);
        assert(wk < _IMDS_WELL_KNOWN_MAX);
        assert(ret);

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_key(link, wk, key, &data);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *s = NULL;
        r = make_cstring(data.iov_base, data.iov_len, MAKE_CSTRING_REFUSE_TRAILING_NUL, &s);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 1;
}

static int acquire_imds_key_as_ip_address(
                sd_varlink *link,
                ImdsWellKnown wk,
                const char *key,
                int family,
                union in_addr_union *ret) {
        int r;

        assert(link);
        assert(wk >= 0);
        assert(wk < _IMDS_WELL_KNOWN_MAX);
        assert(ret);

        _cleanup_free_ char *s = NULL;
        r = acquire_imds_key_as_string(link, wk, key, &s);
        if (r < 0)
                return r;
        if (r == 0 || isempty(s)) {
                *ret = (union in_addr_union) {};
                return 0;
        }

        r = in_addr_from_string(family, s, ret);
        if (r < 0)
                return r;

        return 1;
}

static int action_summary(sd_varlink *link) {
        int r;

        assert(link);

        _cleanup_(table_unrefp) Table *table = table_new_vertical();
        if (!table)
                return log_oom();

        const char *error_id = NULL;
        sd_json_variant *reply = NULL;
        r = sd_varlink_call(
                        link,
                        "io.systemd.InstanceMetadata.GetVendorInfo",
                        /* parameters= */ NULL,
                        &reply,
                        &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to issue io.systemd.InstanceMetadata.GetVendorInfo(): %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply), "Failed to issue io.systemd.InstanceMetadata.GetVendorInfo(): %s", error_id);

        const char *vendor = NULL;
        static const sd_json_dispatch_field dispatch_table[] = {
                { "vendor",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
                {}
        };
        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &vendor);
        if (r < 0)
                return r;
        if (vendor) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Vendor",
                                   TABLE_SET_JSON_FIELD_NAME, "vendor",
                                   TABLE_STRING, vendor);
                if (r < 0)
                        return table_log_add_error(r);
        }

        static const struct {
                ImdsWellKnown well_known;
                const char *field;
        } wktable[] = {
                { IMDS_HOSTNAME,     "Hostname"            },
                { IMDS_REGION,       "Region"              },
                { IMDS_ZONE,         "Zone"                },
                { IMDS_IPV4_PUBLIC,  "Public IPv4 Address" },
                { IMDS_IPV6_PUBLIC,  "Public IPv6 Address" },
        };
        FOREACH_ELEMENT(i, wktable) {
                _cleanup_free_ char *text = NULL;

                r = acquire_imds_key_as_string(link, i->well_known, /* key= */ NULL, &text);
                if (r < 0)
                        return r;
                if (r == 0 || isempty(text))
                        continue;

                r = table_add_many(table,
                                   TABLE_FIELD, i->field,
                                   TABLE_SET_JSON_FIELD_NAME, imds_well_known_to_string(i->well_known),
                                   TABLE_STRING, text);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (table_isempty(table))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "No well-known IMDS data available.");

        return table_print_or_warn(table);
}

static const char* detect_json_object(const char *text) {
        assert(text);

        /* Checks if the provided text looks like a JSON object. It checks if the first non-whitespace
         * characters are {" or {}. */

        text += strspn(text, WHITESPACE);
        if (*text != '{')
                return NULL;

        const char *e = text + 1;
        e += strspn(e, WHITESPACE);
        if (!IN_SET(*e, '"', '}'))
                return NULL;

        return text;
}

static int write_credential(const char *dir, const char *name, const struct iovec *data) {
        int r;

        assert(dir);
        assert(name);

        _cleanup_close_ int dfd = open_mkdir(dir, O_CLOEXEC|O_PATH, 0700);
        if (dfd < 0)
                return log_error_errno(dfd, "Failed to open credential directory '%s': %m", dir);

        if (faccessat(dfd, name, F_OK, AT_SYMLINK_NOFOLLOW) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to check if '%s' exists in credential directory '%s': %m", name, dir);
        } else {
                log_notice("Skipping importing of credential '%s', it already exists locally in '%s'.", name, dir);
                return 0;
        }

        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = open_tmpfile_linkable_at(dfd, name, O_WRONLY|O_CLOEXEC, &t);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create credential file '%s/%s': %m", dir, name);

        CLEANUP_TMPFILE_AT(dfd, t);

        r = loop_write(fd, data->iov_base, data->iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to write credential file '%s/%s': %m", dir, name);

        if (fchmod(fd, 0400) < 0)
                return log_error_errno(errno, "Failed to set access mode on credential file '%s/%s': %m", dir, name);

        r = link_tmpfile_at(fd, dfd, t, name, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to move credential file '%s/%s' into place: %m", dir, name);

        t = mfree(t); /* Disarm auto-cleanup */
        return 1;
}

typedef struct CredentialData {
        const char *name;
        const char *text;
        struct iovec data, encrypted;
} CredentialData;

static void credential_data_done(CredentialData *d) {
        assert(d);

        iovec_done(&d->data);
        iovec_done(&d->encrypted);
}

static int import_credential_one(CredentialData *d) {
        int r;

        assert(d);
        assert(d->name);

        log_debug("Importing credential '%s' from IMDS.", d->name);

        const char *dir = "/run/credstore";
        struct iovec *v, _v;
        if (d->text) {
                _v = IOVEC_MAKE_STRING(d->text);
                v = &_v;
        } else if (iovec_is_set(&d->data))
                v = &d->data;
        else if (iovec_is_set(&d->encrypted)) {
                dir = "/run/credstore.encrypted";
                v = &d->encrypted;
        } else
                assert_not_reached();

        r = write_credential(dir, d->name, v);
        if (r <= 0)
                return r;

        log_info("Imported credential '%s' from IMDS (%s).", d->name, FORMAT_BYTES(v->iov_len));
        return 1;
}

static int import_credentials(const char *text) {
        int r;

        assert(text);

        /* We cannot be sure if the data is actually intended for us. Hence let's be somewhat defensive, and
         * accept data in two ways: either immediately as a JSON object, or alternatively marked with a first
         * line of "#systemd-userdata". The latter mimics the markers cloud-init employs. */

        const char *e = startswith(text, "#systemd-userdata\n");
        if (!e) {
                e = detect_json_object(text);
                if (!e) {
                        log_info("IMDS user data does not look like JSON or systemd userdata, not processing.");
                        return 0;
                }
        }

        log_debug("Detected JSON userdata");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse(e, /* flags= */ 0, &j, &line, &column);
        if (r < 0) {
                if (line > 0)
                        log_syntax(/* unit= */ NULL, LOG_WARNING, /* filename= */ NULL, line, r, "JSON parse failure.");
                else
                        log_error_errno(r, "Failed to parse IMDS userdata JSON: %m");
                return 0;
        }

        static const sd_json_dispatch_field top_table[] = {
                { "systemd.credentials", SD_JSON_VARIANT_ARRAY, sd_json_dispatch_variant_noref, 0, 0 },
                {},
        };

        sd_json_variant *creds = NULL;
        r = sd_json_dispatch(j, top_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &creds);
        if (r < 0)
                return r;

        unsigned n_imported = 0;
        int ret = 0;
        if (creds) {
                log_debug("Found 'systemd.credentials' field");

                sd_json_variant *c;
                JSON_VARIANT_ARRAY_FOREACH(c, creds) {
                        static const sd_json_dispatch_field credential_table[] = {
                                { "name",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(CredentialData, name),      SD_JSON_MANDATORY },
                                { "text",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(CredentialData, text),      0                 },
                                { "data",      SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec,  offsetof(CredentialData, data),      0                 },
                                { "encrypted", SD_JSON_VARIANT_STRING, json_dispatch_unbase64_iovec,  offsetof(CredentialData, encrypted), 0                 },
                                {},
                        };

                        _cleanup_(credential_data_done) CredentialData d = {};
                        r = sd_json_dispatch(c, credential_table, SD_JSON_LOG|SD_JSON_WARNING, &d);
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                continue;
                        }

                        if (!credential_name_valid(d.name)) {
                                RET_GATHER(ret, log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Credential name '%s' is not valid, refusing.", d.name));
                                continue;
                        }

                        if ((!!d.text + !!iovec_is_set(&d.data) + !!iovec_is_set(&d.encrypted)) != 1) {
                                RET_GATHER(ret, log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Exactly one of 'text', 'data', 'encrypted' must be set for credential '%s', refusing.", d.name));
                                continue;
                        }

                        r = import_credential_one(&d);
                        if (r < 0)
                                RET_GATHER(ret, r);
                        else if (r > 0)
                                n_imported++;
                }
        }

        log_full(n_imported == 0 ? LOG_DEBUG : LOG_INFO, "Imported %u credentials from IMDS.", n_imported);
        return ret;
}

static int add_public_address_to_json_array(sd_json_variant **array, int family, const union in_addr_union *addr) {
        int r;

        assert(array);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(addr);

        if (in_addr_is_null(family, addr))
                return 0;

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        if (dns_resource_record_new_address(&rr, family, addr, "_public") < 0)
                return log_oom();

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *rrj = NULL;
        r = dns_resource_record_to_json(rr, &rrj);
        if (r < 0)
                return log_error_errno(r, "Failed to convert A RR to JSON: %m");

        r = sd_json_variant_append_array(array, rrj);
        if (r < 0)
                return log_error_errno(r, "Failed to append A RR to JSON array: %m");

        log_debug("Writing IMDS RR for: %s", dns_resource_record_to_string(rr));
        return 1;
}

static int import_imds_public_addresses(sd_varlink *link) {
        int r, ret = 0;

        assert(link);

        /* Creates local RRs (honoured by systemd-resolved) for our public addresses. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *aj = NULL;

        union in_addr_union u = {};
        r = acquire_imds_key_as_ip_address(link, IMDS_IPV4_PUBLIC, /* key= */ NULL, AF_INET, &u);
        if (r < 0)
                RET_GATHER(ret, r);
        else if (r > 0) {
                r = add_public_address_to_json_array(&aj, AF_INET, &u);
                if (r < 0)
                        return r;
        }

        u = (union in_addr_union) {};
        r = acquire_imds_key_as_ip_address(link, IMDS_IPV6_PUBLIC, /* key= */ NULL, AF_INET6, &u);
        if (r < 0)
                RET_GATHER(ret, r);
        else if (r > 0) {
                r = add_public_address_to_json_array(&aj, AF_INET6, &u);
                if (r < 0)
                        return r;
        }

        if (sd_json_variant_elements(aj) == 0) {
                log_debug("No IMDS public addresses known, not writing our RRs.");
                return 0;
        }

        _cleanup_free_ char *text = NULL;
        r = sd_json_variant_format(aj, SD_JSON_FORMAT_NEWLINE, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format JSON text: %m");

        r = write_string_file("/run/systemd/resolve/static.d/imds-public.rr", text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write IMDS RR data: %m");

        log_debug("IMDS public addresses written out.");
        return 1;
}

static int import_imds_ssh_key(sd_varlink *link) {
        int r;

        assert(link);

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_key(link, IMDS_SSH_KEY, /* key= */ NULL, &data);
        if (r < 0)
                return r;
        if (r == 0 || !iovec_is_set(&data)) {
                log_debug("No SSH key supplied via IMDS, not importing.");
                return 0;
        }

        r = write_credential("/run/credstore", "ssh.authorized_keys.root", &data);
        if (r <= 0)
                return r;

        log_info("Imported SSH key as credential 'ssh.authorized_keys.root'.");
        return 0;
}

static int import_imds_hostname(sd_varlink *link) {
        int r;

        assert(link);

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_key(link, IMDS_HOSTNAME, /* key= */ NULL, &data);
        if (r < 0)
                return r;
        if (r == 0 || !iovec_is_set(&data)) {
                log_debug("No hostname supplied via IMDS, not importing.");
                return 0;
        }

        r = write_credential("/run/credstore", "firstboot.hostname", &data);
        if (r <= 0)
                return r;

        log_info("Imported hostname as credential 'firstboot.hostname'.");
        return 0;
}

static int acquire_imds_userdata(sd_varlink *link, struct iovec *ret) {
        int r;

        assert(link);
        assert(ret);

        /* First try our private namespace, if the concept exists, and then fall back to the singleton */
        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_key(link, IMDS_USERDATA_BASE, "/systemd-userdata", &data);
        if (r == 0)
                r = acquire_imds_key(link, IMDS_USERDATA, /* key= */ NULL, &data);
        if (r < 0)
                return r;
        if (r > 0) {
                if (!iovec_is_set(&data)) { /* Treat empty user data like empty */
                        *ret = (struct iovec) {};
                        return 0;
                }

                *ret = TAKE_STRUCT(data);
                return 1;
        }

        r = acquire_imds_key(link, IMDS_USERDATA_BASE64, /* key= */ NULL, &data);
        if (r < 0)
                return r;
        _cleanup_(iovec_done) struct iovec decoded = {};
        if (r > 0) {
                r = unbase64mem_full(data.iov_base, data.iov_len, /* secure= */ false, &decoded.iov_base, &decoded.iov_len);
                if (r < 0)
                        return r;
        }

        if (!iovec_is_set(&decoded)) { /* Treat empty user data like empty */
                *ret = (struct iovec) {};
                return 0;
        }

        *ret = TAKE_STRUCT(decoded);
        return 1;
}

static int action_get(sd_varlink *link) {
        int r;

        assert(link);

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_key(link, arg_well_known, arg_key, &data);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Key not available.");

        r = loop_write(STDOUT_FILENO, data.iov_base, data.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to write data to standard output: %m");

        return 0;
}

static int action_userdata(sd_varlink *link) {
        int r;

        assert(link);

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_userdata(link, &data);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "User data not available.");

        r = loop_write(STDOUT_FILENO, data.iov_base, data.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to write data to standard output: %m");

        return 0;
}

static int remove_userdata(const char *path) {
        assert(path);

        if (unlink(path) < 0) {

                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to remove '%s', ignoring: %m", path);

                return 0;
        }

        log_debug("Removed '%s'.", path);
        return 1;
}

static int save_userdata(const struct iovec *data, const char *path) {
        int r;

        assert(data);
        assert(path);

        if (!iovec_is_set(data))
                return remove_userdata(path);

        r = write_data_file_atomic_at(AT_FDCWD, path, data, WRITE_DATA_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to save userdata to '%s': %m", path);

        log_debug("Saved userdata to '%s'.", path);
        return 1;
}

static int action_import(sd_varlink *link) {
        int r;

        assert(link);

        int ret = 0;
        RET_GATHER(ret, import_imds_public_addresses(link));
        RET_GATHER(ret, import_imds_hostname(link));
        RET_GATHER(ret, import_imds_ssh_key(link));

        _cleanup_(iovec_done) struct iovec data = {};
        r = acquire_imds_userdata(link, &data);
        if (r < 0)
                return RET_GATHER(ret, r);
        if (r == 0) {
                log_info("No IMDS data available, not importing credentials.");
                (void) remove_userdata("/run/systemd/imds/userdata");
                return ret;
        }

        /* Measure the userdata before we use it */
        (void) pcrextend_imds_userdata_now(&data);

        /* Keep a pristine copy of the userdata we actually applied. (Note that this data is typically also
         * kept as cached item on systemd-imdsd, but that one is possibly subject to cache invalidation,
         * while this one is supposed to pin the data actually in effect.) */
        (void) save_userdata(&data, "/run/systemd/imds/userdata");

        /* Ensure no inner NUL byte */
        if (memchr(data.iov_base, 0, data.iov_len)) {
                log_info("IMDS user data contains NUL byte, not processing.");
                return ret;
        }

        /* Turn this into a proper C string */
        if (!iovec_append(&data, &IOVEC_MAKE_BYTE(0)))
                return log_oom();

        return RET_GATHER(ret, import_credentials(data.iov_base));
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        r = sd_varlink_connect_address(&link, "/run/systemd/io.systemd.InstanceMetadata");
        if (r < 0) {
                if (r != -ENOENT && !ERRNO_IS_NEG_DISCONNECT(r))
                        return log_error_errno(r, "Failed to connect to systemd-imdsd: %m");

                log_debug_errno(r, "Couldn't connect to /run/systemd/io.systemd.InstanceMetadata, will try to fork off systemd-imdsd as child now.");

                /* Try to fork off systemd-imdsd as a child as a fallback. If we have privileges and the
                 * SO_FWMARK trickery is not necessary, then this might just work. */
                _cleanup_free_ char *p = NULL;
                _cleanup_close_ int pin_fd =
                        pin_callout_binary(LIBEXECDIR "/systemd-imdsd", &p);
                if (pin_fd < 0)
                        return log_error_errno(pin_fd, "Failed to pick up imdsd binary: %m");

                r = sd_varlink_connect_exec(&link, p, /* argv[]= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to imdsd service: %m");
        }

        switch (arg_action) {

        case ACTION_SUMMARY:
                return action_summary(link);

        case ACTION_GET:
                return action_get(link);

        case ACTION_USERDATA:
                return action_userdata(link);

        case ACTION_IMPORT:
                return action_import(link);

        default:
                assert_not_reached();
        }
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
