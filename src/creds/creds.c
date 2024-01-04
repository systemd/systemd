/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "build.h"
#include "bus-polkit.h"
#include "creds-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fileio.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "json.h"
#include "main-func.h"
#include "memory-util.h"
#include "missing_magic.h"
#include "pager.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "terminal-util.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "user-util.h"
#include "varlink.h"
#include "varlink-io.systemd.Credentials.h"
#include "verbs.h"

typedef enum TranscodeMode {
        TRANSCODE_OFF,
        TRANSCODE_BASE64,
        TRANSCODE_UNBASE64,
        TRANSCODE_HEX,
        TRANSCODE_UNHEX,
        _TRANSCODE_MAX,
        _TRANSCODE_INVALID = -EINVAL,
} TranscodeMode;

static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_system = false;
static TranscodeMode arg_transcode = TRANSCODE_OFF;
static int arg_newline = -1;
static sd_id128_t arg_with_key = _CRED_AUTO;
static const char *arg_tpm2_device = NULL;
static uint32_t arg_tpm2_pcr_mask = UINT32_MAX;
static char *arg_tpm2_public_key = NULL;
static uint32_t arg_tpm2_public_key_pcr_mask = UINT32_MAX;
static char *arg_tpm2_signature = NULL;
static const char *arg_name = NULL;
static bool arg_name_any = false;
static usec_t arg_timestamp = USEC_INFINITY;
static usec_t arg_not_after = USEC_INFINITY;
static bool arg_pretty = false;
static bool arg_quiet = false;
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_tpm2_public_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_signature, freep);

static const char* transcode_mode_table[_TRANSCODE_MAX] = {
        [TRANSCODE_OFF] = "off",
        [TRANSCODE_BASE64] = "base64",
        [TRANSCODE_UNBASE64] = "unbase64",
        [TRANSCODE_HEX] = "hex",
        [TRANSCODE_UNHEX] = "unhex",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(transcode_mode, TranscodeMode);

static int open_credential_directory(
                bool encrypted,
                DIR **ret_dir,
                const char **ret_prefix) {

        const char *p;
        DIR *d;
        int r;

        assert(ret_dir);

        if (arg_system)
                /* PID 1 ensures that system credentials are always accessible under the same fixed path. It
                 * will create symlinks if necessary to guarantee that. */
                p = encrypted ?
                        ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY :
                        SYSTEM_CREDENTIALS_DIRECTORY;
        else {
                /* Otherwise take the dirs from the env vars we got passed */
                r = (encrypted ? get_encrypted_credentials_dir : get_credentials_dir)(&p);
                if (r == -ENXIO) /* No environment variable? */
                        goto not_found;
                if (r < 0)
                        return log_error_errno(r, "Failed to get credentials directory: %m");
        }

        d = opendir(p);
        if (!d) {
                /* No such dir? Then no creds where passed. (We conditionalize this on arg_system, since for
                 * the per-service case a non-existing path would indicate an issue since the env var would
                 * be set incorrectly in that case.) */
                if (arg_system && errno == ENOENT)
                        goto not_found;

                return log_error_errno(errno, "Failed to open credentials directory '%s': %m", p);
        }

        *ret_dir = d;

        if (ret_prefix)
                *ret_prefix = p;

        return 1;

not_found:
        *ret_dir = NULL;

        if (ret_prefix)
                *ret_prefix = NULL;

        return 0;
}

static int add_credentials_to_table(Table *t, bool encrypted) {
        _cleanup_closedir_ DIR *d = NULL;
        const char *prefix;
        int r;

        assert(t);

        r = open_credential_directory(encrypted, &d, &prefix);
        if (r < 0)
                return r;
        if (!d)
                return 0; /* No creds dir set */

        for (;;) {
                _cleanup_free_ char *j = NULL;
                const char *secure, *secure_color = NULL;
                _cleanup_close_ int fd = -EBADF;
                struct dirent *de;
                struct stat st;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno == 0)
                                break;

                        return log_error_errno(errno, "Failed to read credentials directory: %m");
                }

                if (!IN_SET(de->d_type, DT_REG, DT_UNKNOWN))
                        continue;

                if (!credential_name_valid(de->d_name))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (fd < 0) {
                        if (errno == ENOENT) /* Vanished by now? */
                                continue;

                        return log_error_errno(errno, "Failed to open credential '%s': %m", de->d_name);
                }

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat credential '%s': %m", de->d_name);

                if (!S_ISREG(st.st_mode))
                        continue;

                if (encrypted) {
                        secure = "encrypted";
                        secure_color = ansi_highlight_green();
                } else if ((st.st_mode & 0377) != 0) {
                        secure = "insecure"; /* Anything that is accessible more than read-only to its owner is insecure */
                        secure_color = ansi_highlight_red();
                } else {
                        r = fd_is_fs_type(fd, RAMFS_MAGIC);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine backing file system of '%s': %m", de->d_name);

                        secure = r > 0 ? "secure" : "weak"; /* ramfs is not swappable, hence "secure", everything else is "weak" */
                        secure_color = r > 0 ? ansi_highlight_green() : ansi_highlight_yellow4();
                }

                j = path_join(prefix, de->d_name);
                if (!j)
                        return log_oom();

                r = table_add_many(
                                t,
                                TABLE_STRING, de->d_name,
                                TABLE_STRING, secure,
                                TABLE_SET_COLOR, secure_color,
                                TABLE_SIZE, (uint64_t) st.st_size,
                                TABLE_STRING, j);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return 1; /* Creds dir set */
}

static int verb_list(int argc, char **argv, void *userdata) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r, q;

        t = table_new("name", "secure", "size", "path");
        if (!t)
                return log_oom();

        (void) table_set_align_percent(t, table_get_cell(t, 0, 2), 100);

        r = add_credentials_to_table(t, /* encrypted= */ true);
        if (r < 0)
                return r;

        q = add_credentials_to_table(t, /* encrypted= */ false);
        if (q < 0)
                return q;

        if (r == 0 && q == 0) {
                if (arg_system)
                        return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "No credentials passed to system.");

                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "No credentials passed. (i.e. $CREDENTIALS_DIRECTORY not set.)");
        }

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF) && table_isempty(t)) {
                log_info("No credentials");
                return 0;
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int transcode(
                const void *input,
                size_t input_size,
                void **ret_output,
                size_t *ret_output_size) {

        int r;

        assert(input);
        assert(input_size);
        assert(ret_output);
        assert(ret_output_size);

        switch (arg_transcode) {

        case TRANSCODE_BASE64: {
                char *buf;
                ssize_t l;

                l = base64mem_full(input, input_size, 79, &buf);
                if (l < 0)
                        return l;

                *ret_output = buf;
                *ret_output_size = l;
                return 0;
        }

        case TRANSCODE_UNBASE64:
                r = unbase64mem_full(input, input_size, true, ret_output, ret_output_size);
                if (r == -EPIPE) /* Uneven number of chars */
                        return -EINVAL;

                return r;

        case TRANSCODE_HEX: {
                char *buf;

                buf = hexmem(input, input_size);
                if (!buf)
                        return -ENOMEM;

                *ret_output = buf;
                *ret_output_size = input_size * 2;
                return 0;
        }

        case TRANSCODE_UNHEX:
                r = unhexmem_full(input, input_size, true, ret_output, ret_output_size);
                if (r == -EPIPE) /* Uneven number of chars */
                        return -EINVAL;

                return r;

        default:
                assert_not_reached();
        }
}

static int print_newline(FILE *f, const char *data, size_t l) {
        int fd;

        assert(f);
        assert(data || l == 0);

        /* If turned off explicitly, don't print newline */
        if (arg_newline == 0)
                return 0;

        /* If data already has newline, don't print either */
        if (l > 0 && data[l-1] == '\n')
                return 0;

        /* Don't bother unless this is a tty */
        fd = fileno(f);
        if (fd >= 0 && !isatty_safe(fd))
                return 0;

        if (fputc('\n', f) != '\n')
                return log_error_errno(errno, "Failed to write trailing newline: %m");

        return 1;
}

static int write_blob(FILE *f, const void *data, size_t size) {
        _cleanup_(erase_and_freep) void *transcoded = NULL;
        int r;

        if (arg_transcode == TRANSCODE_OFF &&
            arg_json_format_flags != JSON_FORMAT_OFF) {
                _cleanup_(erase_and_freep) char *suffixed = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                r = make_cstring(data, size, MAKE_CSTRING_REFUSE_TRAILING_NUL, &suffixed);
                if (r < 0)
                        return log_error_errno(r, "Unable to convert binary string to C string: %m");

                r = json_parse(suffixed, JSON_PARSE_SENSITIVE, &v, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON: %m");

                json_variant_dump(v, arg_json_format_flags, f, NULL);
                return 0;
        }

        if (arg_transcode != TRANSCODE_OFF) {
                r = transcode(data, size, &transcoded, &size);
                if (r < 0)
                        return log_error_errno(r, "Failed to transcode data: %m");

                data = transcoded;
        }

        if (fwrite(data, 1, size, f) != size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to write credential data.");

        r = print_newline(f, data, size);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to flush output: %m");

        return 0;
}

static int verb_cat(int argc, char **argv, void *userdata) {
        usec_t timestamp;
        int r, ret = 0;

        timestamp = arg_timestamp != USEC_INFINITY ? arg_timestamp : now(CLOCK_REALTIME);

        STRV_FOREACH(cn, strv_skip(argv, 1)) {
                _cleanup_(erase_and_freep) void *data = NULL;
                size_t size = 0;
                int encrypted;

                if (!credential_name_valid(*cn)) {
                        log_error("Credential name '%s' is not valid.", *cn);
                        if (ret >= 0)
                                ret = -EINVAL;
                        continue;
                }

                /* Look both in regular and in encrypted credentials */
                for (encrypted = 0; encrypted < 2; encrypted++) {
                        _cleanup_closedir_ DIR *d = NULL;

                        r = open_credential_directory(encrypted, &d, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open credentials directory: %m");
                        if (!d) /* Not set */
                                continue;

                        r = read_full_file_full(
                                        dirfd(d), *cn,
                                        UINT64_MAX, SIZE_MAX,
                                        READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE,
                                        NULL,
                                        (char**) &data, &size);
                        if (r == -ENOENT) /* Not found */
                                continue;
                        if (r >= 0) /* Found */
                                break;

                        log_error_errno(r, "Failed to read credential '%s': %m", *cn);
                        if (ret >= 0)
                                ret = r;
                }

                if (encrypted >= 2) { /* Found nowhere */
                        log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Credential '%s' not set.", *cn);
                        if (ret >= 0)
                                ret = -ENOENT;

                        continue;
                }

                if (encrypted) {
                        _cleanup_(erase_and_freep) void *plaintext = NULL;
                        size_t plaintext_size;

                        r = decrypt_credential_and_warn(
                                        *cn,
                                        timestamp,
                                        arg_tpm2_device,
                                        arg_tpm2_signature,
                                        data, size,
                                        &plaintext, &plaintext_size);
                        if (r < 0)
                                return r;

                        erase_and_free(data);
                        data = TAKE_PTR(plaintext);
                        size = plaintext_size;
                }

                r = write_blob(stdout, data, size);
                if (r < 0)
                        return r;
        }

        return ret;
}

static int verb_encrypt(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *base64_buf = NULL, *fname = NULL;
        _cleanup_(erase_and_freep) char *plaintext = NULL;
        const char *input_path, *output_path, *name;
        _cleanup_free_ void *output = NULL;
        size_t plaintext_size, output_size;
        ssize_t base64_size;
        usec_t timestamp;
        int r;

        assert(argc == 3);

        input_path = empty_or_dash(argv[1]) ? NULL : argv[1];

        if (input_path)
                r = read_full_file_full(AT_FDCWD, input_path, UINT64_MAX, CREDENTIAL_SIZE_MAX, READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &plaintext, &plaintext_size);
        else
                r = read_full_stream_full(stdin, NULL, UINT64_MAX, CREDENTIAL_SIZE_MAX, READ_FULL_FILE_SECURE|READ_FULL_FILE_FAIL_WHEN_LARGER, &plaintext, &plaintext_size);
        if (r == -E2BIG)
                return log_error_errno(r, "Plaintext too long for credential (allowed size: %zu).", (size_t) CREDENTIAL_SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to read plaintext: %m");

        output_path = empty_or_dash(argv[2]) ? NULL : argv[2];

        if (arg_name_any)
                name = NULL;
        else if (arg_name)
                name = arg_name;
        else if (output_path) {
                r = path_extract_filename(output_path, &fname);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from '%s': %m", output_path);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Path '%s' refers to directory, refusing.", output_path);

                name = fname;
        } else {
                log_warning("No credential name specified, not embedding credential name in encrypted data. (Disable this warning with --name=)");
                name = NULL;
        }

        timestamp = arg_timestamp != USEC_INFINITY ? arg_timestamp : now(CLOCK_REALTIME);

        if (arg_not_after != USEC_INFINITY && arg_not_after < timestamp)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential is invalidated before it is valid.");

        r = encrypt_credential_and_warn(
                        arg_with_key,
                        name,
                        timestamp,
                        arg_not_after,
                        arg_tpm2_device,
                        arg_tpm2_pcr_mask,
                        arg_tpm2_public_key,
                        arg_tpm2_public_key_pcr_mask,
                        plaintext, plaintext_size,
                        &output, &output_size);
        if (r < 0)
                return r;

        base64_size = base64mem_full(output, output_size, arg_pretty ? 69 : 79, &base64_buf);
        if (base64_size < 0)
                return base64_size;

        /* Pretty print makes sense only if we're printing stuff to stdout
         * and if a cred name is provided via --name= (since we can't use
         * the output file name as the cred name here) */
        if (arg_pretty && !output_path && name) {
                _cleanup_free_ char *escaped = NULL, *indented = NULL, *j = NULL;

                escaped = cescape(name);
                if (!escaped)
                        return log_oom();

                indented = strreplace(base64_buf, "\n", " \\\n        ");
                if (!indented)
                        return log_oom();

                j = strjoin("SetCredentialEncrypted=", escaped, ": \\\n        ", indented, "\n");
                if (!j)
                        return log_oom();

                free_and_replace(base64_buf, j);
        }

        if (output_path)
                r = write_string_file(output_path, base64_buf, WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_CREATE);
        else
                r = write_string_stream(stdout, base64_buf, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to write result: %m");

        return EXIT_SUCCESS;
}

static int verb_decrypt(int argc, char **argv, void *userdata) {
        _cleanup_(erase_and_freep) void *plaintext = NULL;
        _cleanup_free_ char *input = NULL, *fname = NULL;
        _cleanup_fclose_ FILE *output_file = NULL;
        const char *input_path, *output_path, *name;
        size_t input_size, plaintext_size;
        usec_t timestamp;
        FILE *f;
        int r;

        assert(IN_SET(argc, 2, 3));

        input_path = empty_or_dash(argv[1]) ? NULL : argv[1];

        if (input_path)
                r = read_full_file_full(AT_FDCWD, argv[1], UINT64_MAX, CREDENTIAL_ENCRYPTED_SIZE_MAX, READ_FULL_FILE_UNBASE64|READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &input, &input_size);
        else
                r = read_full_stream_full(stdin, NULL, UINT64_MAX, CREDENTIAL_ENCRYPTED_SIZE_MAX, READ_FULL_FILE_UNBASE64|READ_FULL_FILE_FAIL_WHEN_LARGER, &input, &input_size);
        if (r == -E2BIG)
                return log_error_errno(r, "Data too long for encrypted credential (allowed size: %zu).", (size_t) CREDENTIAL_ENCRYPTED_SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to read encrypted credential data: %m");

        output_path = (argc < 3 || empty_or_dash(argv[2])) ? NULL : argv[2];

        if (arg_name_any)
                name = NULL;
        else if (arg_name)
                name = arg_name;
        else if (input_path) {
                r = path_extract_filename(input_path, &fname);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from '%s': %m", input_path);
                if (r == O_DIRECTORY)
                        return log_error_errno(SYNTHETIC_ERRNO(EISDIR), "Path '%s' refers to directory, refusing.", input_path);

                name = fname;
        } else {
                log_warning("No credential name specified, not validating credential name embedded in encrypted data. (Disable this warning with --name=.)");
                name = NULL;
        }

        timestamp = arg_timestamp != USEC_INFINITY ? arg_timestamp : now(CLOCK_REALTIME);

        r = decrypt_credential_and_warn(
                        name,
                        timestamp,
                        arg_tpm2_device,
                        arg_tpm2_signature,
                        input, input_size,
                        &plaintext, &plaintext_size);
        if (r < 0)
                return r;

        if (output_path) {
                output_file = fopen(output_path, "we");
                if (!output_file)
                        return log_error_errno(errno, "Failed to create output file '%s': %m", output_path);

                f = output_file;
        } else
                f = stdout;

        r = write_blob(f, plaintext, plaintext_size);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}

static int verb_setup(int argc, char **argv, void *userdata) {
        size_t size;
        int r;

        r = get_credential_host_secret(CREDENTIAL_SECRET_GENERATE|CREDENTIAL_SECRET_WARN_NOT_ENCRYPTED, NULL, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to setup credentials host key: %m");

        log_info("%zu byte credentials host key set up.", size);

        return EXIT_SUCCESS;
}

static int verb_has_tpm2(int argc, char **argv, void *userdata) {
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

static int verb_help(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-creds", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n"
               "\n%5$sDisplay and Process Credentials.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list                    Show installed and available versions\n"
               "  cat CREDENTIAL...       Show specified credentials\n"
               "  setup                   Generate credentials host key, if not existing yet\n"
               "  encrypt INPUT OUTPUT    Encrypt plaintext credential file and write to\n"
               "                          ciphertext credential file\n"
               "  decrypt INPUT [OUTPUT]  Decrypt ciphertext credential file and write to\n"
               "                          plaintext credential file\n"
               "  has-tpm2                Report whether TPM2 support is available\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "     --system             Show credentials passed to system\n"
               "     --transcode=base64|unbase64|hex|unhex\n"
               "                          Transcode credential data\n"
               "     --newline=auto|yes|no\n"
               "                          Suffix output with newline\n"
               "  -p --pretty             Output as SetCredentialEncrypted= line\n"
               "     --name=NAME          Override filename included in encrypted credential\n"
               "     --timestamp=TIME     Include specified timestamp in encrypted credential\n"
               "     --not-after=TIME     Include specified invalidation time in encrypted\n"
               "                          credential\n"
               "     --with-key=host|tpm2|host+tpm2|tpm2-absent|auto|auto-initrd\n"
               "                          Which keys to encrypt with\n"
               "  -H                      Shortcut for --with-key=host\n"
               "  -T                      Shortcut for --with-key=tpm2\n"
               "     --tpm2-device=PATH\n"
               "                          Pick TPM2 device\n"
               "     --tpm2-pcrs=PCR1+PCR2+PCR3+…\n"
               "                          Specify TPM2 PCRs to seal against (fixed hash)\n"
               "     --tpm2-public-key=PATH\n"
               "                          Specify PEM certificate to seal against\n"
               "     --tpm2-public-key-pcrs=PCR1+PCR2+PCR3+…\n"
               "                          Specify TPM2 PCRs to seal against (public key)\n"
               "     --tpm2-signature=PATH\n"
               "                          Specify signature for public key PCR policy\n"
               "  -q --quiet              Suppress output for 'has-tpm2' verb\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
               , ansi_underline(), ansi_normal()
               , ansi_highlight(), ansi_normal()
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_JSON,
                ARG_SYSTEM,
                ARG_TRANSCODE,
                ARG_NEWLINE,
                ARG_WITH_KEY,
                ARG_TPM2_DEVICE,
                ARG_TPM2_PCRS,
                ARG_TPM2_PUBLIC_KEY,
                ARG_TPM2_PUBLIC_KEY_PCRS,
                ARG_TPM2_SIGNATURE,
                ARG_NAME,
                ARG_TIMESTAMP,
                ARG_NOT_AFTER,
        };

        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "version",              no_argument,       NULL, ARG_VERSION              },
                { "no-pager",             no_argument,       NULL, ARG_NO_PAGER             },
                { "no-legend",            no_argument,       NULL, ARG_NO_LEGEND            },
                { "json",                 required_argument, NULL, ARG_JSON                 },
                { "system",               no_argument,       NULL, ARG_SYSTEM               },
                { "transcode",            required_argument, NULL, ARG_TRANSCODE            },
                { "newline",              required_argument, NULL, ARG_NEWLINE              },
                { "pretty",               no_argument,       NULL, 'p'                      },
                { "with-key",             required_argument, NULL, ARG_WITH_KEY             },
                { "tpm2-device",          required_argument, NULL, ARG_TPM2_DEVICE          },
                { "tpm2-pcrs",            required_argument, NULL, ARG_TPM2_PCRS            },
                { "tpm2-public-key",      required_argument, NULL, ARG_TPM2_PUBLIC_KEY      },
                { "tpm2-public-key-pcrs", required_argument, NULL, ARG_TPM2_PUBLIC_KEY_PCRS },
                { "tpm2-signature",       required_argument, NULL, ARG_TPM2_SIGNATURE       },
                { "name",                 required_argument, NULL, ARG_NAME                 },
                { "timestamp",            required_argument, NULL, ARG_TIMESTAMP            },
                { "not-after",            required_argument, NULL, ARG_NOT_AFTER            },
                { "quiet",                no_argument,       NULL, 'q'                      },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hHTpq", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return verb_help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_SYSTEM:
                        arg_system = true;
                        break;

                case ARG_TRANSCODE:
                        if (parse_boolean(optarg) == 0) /* If specified as "false", turn transcoding off */
                                arg_transcode = TRANSCODE_OFF;
                        else {
                                TranscodeMode m;

                                m = transcode_mode_from_string(optarg);
                                if (m < 0)
                                        return log_error_errno(m, "Failed to parse transcode mode: %m");

                                arg_transcode = m;
                        }

                        break;

                case ARG_NEWLINE:
                        if (isempty(optarg) || streq(optarg, "auto"))
                                arg_newline = -1;
                        else {
                                r = parse_boolean_argument("--newline=", optarg, NULL);
                                if (r < 0)
                                        return r;

                                arg_newline = r;
                        }
                        break;

                case 'p':
                        arg_pretty = true;
                        break;

                case ARG_WITH_KEY:
                        if (isempty(optarg) || streq(optarg, "auto"))
                                arg_with_key = _CRED_AUTO;
                        else if (streq(optarg, "auto-initrd"))
                                arg_with_key = _CRED_AUTO_INITRD;
                        else if (streq(optarg, "host"))
                                arg_with_key = CRED_AES256_GCM_BY_HOST;
                        else if (streq(optarg, "tpm2"))
                                arg_with_key = CRED_AES256_GCM_BY_TPM2_HMAC;
                        else if (streq(optarg, "tpm2-with-public-key"))
                                arg_with_key = CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK;
                        else if (STR_IN_SET(optarg, "host+tpm2", "tpm2+host"))
                                arg_with_key = CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC;
                        else if (STR_IN_SET(optarg, "host+tpm2-with-public-key", "tpm2-with-public-key+host"))
                                arg_with_key = CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK;
                        else if (streq(optarg, "tpm2-absent"))
                                arg_with_key = CRED_AES256_GCM_BY_TPM2_ABSENT;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown key type: %s", optarg);

                        break;

                case 'H':
                        arg_with_key = CRED_AES256_GCM_BY_HOST;
                        break;

                case 'T':
                        arg_with_key = CRED_AES256_GCM_BY_TPM2_HMAC;
                        break;

                case ARG_TPM2_DEVICE:
                        if (streq(optarg, "list"))
                                return tpm2_list_devices();

                        arg_tpm2_device = streq(optarg, "auto") ? NULL : optarg;
                        break;

                case ARG_TPM2_PCRS: /* For fixed hash PCR policies only */
                        r = tpm2_parse_pcr_argument_to_mask(optarg, &arg_tpm2_pcr_mask);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_public_key);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_PUBLIC_KEY_PCRS: /* For public key PCR policies only */
                        r = tpm2_parse_pcr_argument_to_mask(optarg, &arg_tpm2_public_key_pcr_mask);
                        if (r < 0)
                                return r;

                        break;

                case ARG_TPM2_SIGNATURE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm2_signature);
                        if (r < 0)
                                return r;

                        break;

                case ARG_NAME:
                        if (isempty(optarg)) {
                                arg_name = NULL;
                                arg_name_any = true;
                                break;
                        }

                        if (!credential_name_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid credential name: %s", optarg);

                        arg_name = optarg;
                        arg_name_any = false;
                        break;

                case ARG_TIMESTAMP:
                        r = parse_timestamp(optarg, &arg_timestamp);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp: %s", optarg);

                        break;

                case ARG_NOT_AFTER:
                        r = parse_timestamp(optarg, &arg_not_after);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --not-after= timestamp: %s", optarg);

                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (arg_tpm2_pcr_mask == UINT32_MAX)
                arg_tpm2_pcr_mask = TPM2_PCR_MASK_DEFAULT;
        if (arg_tpm2_public_key_pcr_mask == UINT32_MAX)
                arg_tpm2_public_key_pcr_mask = UINT32_C(1) << TPM2_PCR_KERNEL_BOOT;

        r = varlink_invocation(VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        arg_varlink = r;

        return 1;
}

static int creds_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "list",     VERB_ANY, 1,        VERB_DEFAULT, verb_list     },
                { "cat",      2,        VERB_ANY, 0,            verb_cat      },
                { "encrypt",  3,        3,        0,            verb_encrypt  },
                { "decrypt",  2,        3,        0,            verb_decrypt  },
                { "setup",    VERB_ANY, 1,        0,            verb_setup    },
                { "help",     VERB_ANY, 1,        0,            verb_help     },
                { "has-tpm2", VERB_ANY, 1,        0,            verb_has_tpm2 },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

typedef struct MethodEncryptParameters {
        const char *name;
        const char *text;
        struct iovec data;
        uint64_t timestamp;
        uint64_t not_after;
} MethodEncryptParameters;

static void method_encrypt_parameters_done(MethodEncryptParameters *p) {
        assert(p);

        iovec_done_erase(&p->data);
}

static int vl_method_encrypt(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "name",      JSON_VARIANT_STRING,        json_dispatch_const_string,   offsetof(MethodEncryptParameters, name),      0 },
                { "text",      JSON_VARIANT_STRING,        json_dispatch_const_string,   offsetof(MethodEncryptParameters, text),      0 },
                { "data",      JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec, offsetof(MethodEncryptParameters, data),      0 },
                { "timestamp", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,         offsetof(MethodEncryptParameters, timestamp), 0 },
                { "notAfter",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,         offsetof(MethodEncryptParameters, not_after), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        _cleanup_(method_encrypt_parameters_done) MethodEncryptParameters p = {
                .timestamp = UINT64_MAX,
                .not_after = UINT64_MAX,
        };
        _cleanup_(iovec_done) struct iovec output = {};
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int r;

        assert(link);

        json_variant_sensitive(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.name && !credential_name_valid(p.name))
                return varlink_error_invalid_parameter_name(link, "name");
        /* Specifying both or neither the text string and the binary data is not allowed */
        if (!!p.text == !!p.data.iov_base)
                return varlink_error_invalid_parameter_name(link, "data");
        if (p.timestamp == UINT64_MAX)
                p.timestamp = now(CLOCK_REALTIME);
        if (p.not_after != UINT64_MAX && p.not_after < p.timestamp)
                return varlink_error_invalid_parameter_name(link, "notAfter");

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.credentials.encrypt",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        polkit_registry);
        if (r <= 0)
                return r;

        r = encrypt_credential_and_warn(
                        arg_with_key,
                        p.name,
                        p.timestamp,
                        p.not_after,
                        arg_tpm2_device,
                        arg_tpm2_pcr_mask,
                        arg_tpm2_public_key,
                        arg_tpm2_public_key_pcr_mask,
                        p.text ?: p.data.iov_base, p.text ? strlen(p.text) : p.data.iov_len,
                        &output.iov_base, &output.iov_len);
        if (r < 0)
                return r;

        _cleanup_(json_variant_unrefp) JsonVariant *reply = NULL;

        r = json_build(&reply, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_IOVEC_BASE64("blob", &output)));
        if (r < 0)
                return r;

        /* Let's also mark the (theoretically encrypted) reply as sensitive, in case the NULL encryption scheme was used. */
        json_variant_sensitive(reply);

        return varlink_reply(link, reply);
}

typedef struct MethodDecryptParameters {
        const char *name;
        struct iovec blob;
        uint64_t timestamp;
} MethodDecryptParameters;

static void method_decrypt_parameters_done(MethodDecryptParameters *p) {
        assert(p);

        iovec_done_erase(&p->blob);
}

static int vl_method_decrypt(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "name",      JSON_VARIANT_STRING,        json_dispatch_const_string,   offsetof(MethodDecryptParameters, name),      0              },
                { "blob",      JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec, offsetof(MethodDecryptParameters, blob),      JSON_MANDATORY },
                { "timestamp", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint64,         offsetof(MethodDecryptParameters, timestamp), 0              },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        _cleanup_(method_decrypt_parameters_done) MethodDecryptParameters p = {
                .timestamp = UINT64_MAX,
        };
        _cleanup_(iovec_done_erase) struct iovec output = {};
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int r;

        assert(link);

        /* Let's also mark the (theoretically encrypted) input as sensitive, in case the NULL encryption scheme was used. */
        json_variant_sensitive(parameters);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.name && !credential_name_valid(p.name))
                return varlink_error_invalid_parameter_name(link, "name");
        if (p.timestamp == UINT64_MAX)
                p.timestamp = now(CLOCK_REALTIME);

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.credentials.decrypt",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        polkit_registry);
        if (r <= 0)
                return r;

        r = decrypt_credential_and_warn(
                        p.name,
                        p.timestamp,
                        arg_tpm2_device,
                        arg_tpm2_signature,
                        p.blob.iov_base, p.blob.iov_len,
                        &output.iov_base, &output.iov_len);
        if (r == -EBADMSG)
                return varlink_error(link, "io.systemd.Credentials.BadFormat", NULL);
        if (r == -EREMOTE)
                return varlink_error(link, "io.systemd.Credentials.NameMismatch", NULL);
        if (r == -ESTALE)
                return varlink_error(link, "io.systemd.Credentials.TimeMismatch", NULL);
        if (r < 0)
                return r;

        _cleanup_(json_variant_unrefp) JsonVariant *reply = NULL;

        r = json_build(&reply, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_IOVEC_BASE64("data", &output)));
        if (r < 0)
                return r;

        json_variant_sensitive(reply);

        return varlink_reply(link, reply);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink) {
                _cleanup_(varlink_server_unrefp) VarlinkServer *varlink_server = NULL;
                _cleanup_(hashmap_freep) Hashmap *polkit_registry = NULL;

                /* Invocation as Varlink service */

                r = varlink_server_new(&varlink_server, VARLINK_SERVER_ACCOUNT_UID|VARLINK_SERVER_INHERIT_USERDATA);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate Varlink server: %m");

                r = varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_Credentials);
                if (r < 0)
                        return log_error_errno(r, "Failed to add Varlink interface: %m");

                r = varlink_server_bind_method_many(
                                varlink_server,
                                "io.systemd.Credentials.Encrypt", vl_method_encrypt,
                                "io.systemd.Credentials.Decrypt", vl_method_decrypt);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind Varlink methods: %m");

                varlink_server_set_userdata(varlink_server, &polkit_registry);

                r = varlink_server_loop_auto(varlink_server);
                if (r < 0)
                        return log_error_errno(r, "Failed to run Varlink event loop: %m");

                return 0;
        }

        return creds_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
