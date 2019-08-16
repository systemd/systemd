/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <getopt.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "bus-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "log.h"
#include "logs-show.h"
#include "main-func.h"
#include "microhttpd-util.h"
#include "os-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "sigbus.h"
#include "tmpfile-util.h"
#include "util.h"

#define JOURNAL_WAIT_TIMEOUT (10*USEC_PER_SEC)

static char *arg_key_pem = NULL;
static char *arg_cert_pem = NULL;
static char *arg_trust_pem = NULL;
static const char *arg_directory = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_key_pem, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cert_pem, freep);
STATIC_DESTRUCTOR_REGISTER(arg_trust_pem, freep);

typedef struct RequestMeta {
        sd_journal *journal;

        OutputMode mode;

        char *cursor;
        int64_t n_skip;
        uint64_t n_entries;
        bool n_entries_set;

        FILE *tmp;
        uint64_t delta, size;

        int argument_parse_error;

        bool follow;
        bool discrete;

        uint64_t n_fields;
        bool n_fields_set;
} RequestMeta;

static const char* const mime_types[_OUTPUT_MODE_MAX] = {
        [OUTPUT_SHORT] = "text/plain",
        [OUTPUT_JSON] = "application/json",
        [OUTPUT_JSON_SSE] = "text/event-stream",
        [OUTPUT_JSON_SEQ] = "application/json-seq",
        [OUTPUT_EXPORT] = "application/vnd.fdo.journal",
};

static RequestMeta *request_meta(void **connection_cls) {
        RequestMeta *m;

        assert(connection_cls);
        if (*connection_cls)
                return *connection_cls;

        m = new0(RequestMeta, 1);
        if (!m)
                return NULL;

        *connection_cls = m;
        return m;
}

static void request_meta_free(
                void *cls,
                struct MHD_Connection *connection,
                void **connection_cls,
                enum MHD_RequestTerminationCode toe) {

        RequestMeta *m = *connection_cls;

        if (!m)
                return;

        sd_journal_close(m->journal);

        safe_fclose(m->tmp);

        free(m->cursor);
        free(m);
}

static int open_journal(RequestMeta *m) {
        assert(m);

        if (m->journal)
                return 0;

        if (arg_directory)
                return sd_journal_open_directory(&m->journal, arg_directory, 0);
        else
                return sd_journal_open(&m->journal, SD_JOURNAL_LOCAL_ONLY|SD_JOURNAL_SYSTEM);
}

static int request_meta_ensure_tmp(RequestMeta *m) {
        assert(m);

        if (m->tmp)
                rewind(m->tmp);
        else {
                int fd;

                fd = open_tmpfile_unlinkable("/tmp", O_RDWR|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                m->tmp = fdopen(fd, "w+");
                if (!m->tmp) {
                        safe_close(fd);
                        return -errno;
                }
        }

        return 0;
}

static ssize_t request_reader_entries(
                void *cls,
                uint64_t pos,
                char *buf,
                size_t max) {

        RequestMeta *m = cls;
        int r;
        size_t n, k;

        assert(m);
        assert(buf);
        assert(max > 0);
        assert(pos >= m->delta);

        pos -= m->delta;

        while (pos >= m->size) {
                off_t sz;

                /* End of this entry, so let's serialize the next
                 * one */

                if (m->n_entries_set &&
                    m->n_entries <= 0)
                        return MHD_CONTENT_READER_END_OF_STREAM;

                if (m->n_skip < 0)
                        r = sd_journal_previous_skip(m->journal, (uint64_t) -m->n_skip + 1);
                else if (m->n_skip > 0)
                        r = sd_journal_next_skip(m->journal, (uint64_t) m->n_skip + 1);
                else
                        r = sd_journal_next(m->journal);

                if (r < 0) {
                        log_error_errno(r, "Failed to advance journal pointer: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                } else if (r == 0) {

                        if (m->follow) {
                                r = sd_journal_wait(m->journal, (uint64_t) JOURNAL_WAIT_TIMEOUT);
                                if (r < 0) {
                                        log_error_errno(r, "Couldn't wait for journal event: %m");
                                        return MHD_CONTENT_READER_END_WITH_ERROR;
                                }
                                if (r == SD_JOURNAL_NOP)
                                        break;

                                continue;
                        }

                        return MHD_CONTENT_READER_END_OF_STREAM;
                }

                if (m->discrete) {
                        assert(m->cursor);

                        r = sd_journal_test_cursor(m->journal, m->cursor);
                        if (r < 0) {
                                log_error_errno(r, "Failed to test cursor: %m");
                                return MHD_CONTENT_READER_END_WITH_ERROR;
                        }

                        if (r == 0)
                                return MHD_CONTENT_READER_END_OF_STREAM;
                }

                pos -= m->size;
                m->delta += m->size;

                if (m->n_entries_set)
                        m->n_entries -= 1;

                m->n_skip = 0;

                r = request_meta_ensure_tmp(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to create temporary file: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                r = show_journal_entry(m->tmp, m->journal, m->mode, 0, OUTPUT_FULL_WIDTH,
                                   NULL, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to serialize item: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                sz = ftello(m->tmp);
                if (sz == (off_t) -1) {
                        log_error_errno(errno, "Failed to retrieve file position: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                m->size = (uint64_t) sz;
        }

        if (m->tmp == NULL && m->follow)
                return 0;

        if (fseeko(m->tmp, pos, SEEK_SET) < 0) {
                log_error_errno(errno, "Failed to seek to position: %m");
                return MHD_CONTENT_READER_END_WITH_ERROR;
        }

        n = m->size - pos;
        if (n < 1)
                return 0;
        if (n > max)
                n = max;

        errno = 0;
        k = fread(buf, 1, n, m->tmp);
        if (k != n) {
                log_error("Failed to read from file: %s", errno != 0 ? strerror_safe(errno) : "Premature EOF");
                return MHD_CONTENT_READER_END_WITH_ERROR;
        }

        return (ssize_t) k;
}

static int request_parse_accept(
                RequestMeta *m,
                struct MHD_Connection *connection) {

        const char *header;

        assert(m);
        assert(connection);

        header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Accept");
        if (!header)
                return 0;

        if (streq(header, mime_types[OUTPUT_JSON]))
                m->mode = OUTPUT_JSON;
        else if (streq(header, mime_types[OUTPUT_JSON_SSE]))
                m->mode = OUTPUT_JSON_SSE;
        else if (streq(header, mime_types[OUTPUT_JSON_SEQ]))
                m->mode = OUTPUT_JSON_SEQ;
        else if (streq(header, mime_types[OUTPUT_EXPORT]))
                m->mode = OUTPUT_EXPORT;
        else
                m->mode = OUTPUT_SHORT;

        return 0;
}

static int request_parse_range(
                RequestMeta *m,
                struct MHD_Connection *connection) {

        const char *range, *colon, *colon2;
        int r;

        assert(m);
        assert(connection);

        range = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Range");
        if (!range)
                return 0;

        if (!startswith(range, "entries="))
                return 0;

        range += 8;
        range += strspn(range, WHITESPACE);

        colon = strchr(range, ':');
        if (!colon)
                m->cursor = strdup(range);
        else {
                const char *p;

                colon2 = strchr(colon + 1, ':');
                if (colon2) {
                        _cleanup_free_ char *t;

                        t = strndup(colon + 1, colon2 - colon - 1);
                        if (!t)
                                return -ENOMEM;

                        r = safe_atoi64(t, &m->n_skip);
                        if (r < 0)
                                return r;
                }

                p = (colon2 ? colon2 : colon) + 1;
                if (*p) {
                        r = safe_atou64(p, &m->n_entries);
                        if (r < 0)
                                return r;

                        if (m->n_entries <= 0)
                                return -EINVAL;

                        m->n_entries_set = true;
                }

                m->cursor = strndup(range, colon - range);
        }

        if (!m->cursor)
                return -ENOMEM;

        m->cursor[strcspn(m->cursor, WHITESPACE)] = 0;
        if (isempty(m->cursor))
                m->cursor = mfree(m->cursor);

        return 0;
}

static int request_parse_arguments_iterator(
                void *cls,
                enum MHD_ValueKind kind,
                const char *key,
                const char *value) {

        RequestMeta *m = cls;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(m);

        if (isempty(key)) {
                m->argument_parse_error = -EINVAL;
                return MHD_NO;
        }

        if (streq(key, "follow")) {
                if (isempty(value)) {
                        m->follow = true;
                        return MHD_YES;
                }

                r = parse_boolean(value);
                if (r < 0) {
                        m->argument_parse_error = r;
                        return MHD_NO;
                }

                m->follow = r;
                return MHD_YES;
        }

        if (streq(key, "discrete")) {
                if (isempty(value)) {
                        m->discrete = true;
                        return MHD_YES;
                }

                r = parse_boolean(value);
                if (r < 0) {
                        m->argument_parse_error = r;
                        return MHD_NO;
                }

                m->discrete = r;
                return MHD_YES;
        }

        if (streq(key, "boot")) {
                if (isempty(value))
                        r = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0) {
                                m->argument_parse_error = r;
                                return MHD_NO;
                        }
                }

                if (r) {
                        char match[9 + 32 + 1] = "_BOOT_ID=";
                        sd_id128_t bid;

                        r = sd_id128_get_boot(&bid);
                        if (r < 0) {
                                log_error_errno(r, "Failed to get boot ID: %m");
                                return MHD_NO;
                        }

                        sd_id128_to_string(bid, match + 9);
                        r = sd_journal_add_match(m->journal, match, sizeof(match)-1);
                        if (r < 0) {
                                m->argument_parse_error = r;
                                return MHD_NO;
                        }
                }

                return MHD_YES;
        }

        p = strjoin(key, "=", strempty(value));
        if (!p) {
                m->argument_parse_error = log_oom();
                return MHD_NO;
        }

        r = sd_journal_add_match(m->journal, p, 0);
        if (r < 0) {
                m->argument_parse_error = r;
                return MHD_NO;
        }

        return MHD_YES;
}

static int request_parse_arguments(
                RequestMeta *m,
                struct MHD_Connection *connection) {

        assert(m);
        assert(connection);

        m->argument_parse_error = 0;
        MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, request_parse_arguments_iterator, m);

        return m->argument_parse_error;
}

static int request_handler_entries(
                struct MHD_Connection *connection,
                void *connection_cls) {

        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response = NULL;
        RequestMeta *m = connection_cls;
        int r;

        assert(connection);
        assert(m);

        r = open_journal(m);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to open journal: %m");

        if (request_parse_accept(m, connection) < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to parse Accept header.");

        if (request_parse_range(m, connection) < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to parse Range header.");

        if (request_parse_arguments(m, connection) < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to parse URL arguments.");

        if (m->discrete) {
                if (!m->cursor)
                        return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Discrete seeks require a cursor specification.");

                m->n_entries = 1;
                m->n_entries_set = true;
        }

        if (m->cursor)
                r = sd_journal_seek_cursor(m->journal, m->cursor);
        else if (m->n_skip >= 0)
                r = sd_journal_seek_head(m->journal);
        else if (m->n_skip < 0)
                r = sd_journal_seek_tail(m->journal);
        if (r < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to seek in journal.");

        response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 4*1024, request_reader_entries, m, NULL);
        if (!response)
                return respond_oom(connection);

        MHD_add_response_header(response, "Content-Type", mime_types[m->mode]);
        return MHD_queue_response(connection, MHD_HTTP_OK, response);
}

static int output_field(FILE *f, OutputMode m, const char *d, size_t l) {
        const char *eq;
        size_t j;

        eq = memchr(d, '=', l);
        if (!eq)
                return -EINVAL;

        j = l - (eq - d + 1);

        if (m == OUTPUT_JSON) {
                fprintf(f, "{ \"%.*s\" : ", (int) (eq - d), d);
                json_escape(f, eq+1, j, OUTPUT_FULL_WIDTH);
                fputs(" }\n", f);
        } else {
                fwrite(eq+1, 1, j, f);
                fputc('\n', f);
        }

        return 0;
}

static ssize_t request_reader_fields(
                void *cls,
                uint64_t pos,
                char *buf,
                size_t max) {

        RequestMeta *m = cls;
        int r;
        size_t n, k;

        assert(m);
        assert(buf);
        assert(max > 0);
        assert(pos >= m->delta);

        pos -= m->delta;

        while (pos >= m->size) {
                off_t sz;
                const void *d;
                size_t l;

                /* End of this field, so let's serialize the next
                 * one */

                if (m->n_fields_set &&
                    m->n_fields <= 0)
                        return MHD_CONTENT_READER_END_OF_STREAM;

                r = sd_journal_enumerate_unique(m->journal, &d, &l);
                if (r < 0) {
                        log_error_errno(r, "Failed to advance field index: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                } else if (r == 0)
                        return MHD_CONTENT_READER_END_OF_STREAM;

                pos -= m->size;
                m->delta += m->size;

                if (m->n_fields_set)
                        m->n_fields -= 1;

                r = request_meta_ensure_tmp(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to create temporary file: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                r = output_field(m->tmp, m->mode, d, l);
                if (r < 0) {
                        log_error_errno(r, "Failed to serialize item: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                sz = ftello(m->tmp);
                if (sz == (off_t) -1) {
                        log_error_errno(errno, "Failed to retrieve file position: %m");
                        return MHD_CONTENT_READER_END_WITH_ERROR;
                }

                m->size = (uint64_t) sz;
        }

        if (fseeko(m->tmp, pos, SEEK_SET) < 0) {
                log_error_errno(errno, "Failed to seek to position: %m");
                return MHD_CONTENT_READER_END_WITH_ERROR;
        }

        n = m->size - pos;
        if (n > max)
                n = max;

        errno = 0;
        k = fread(buf, 1, n, m->tmp);
        if (k != n) {
                log_error("Failed to read from file: %s", errno != 0 ? strerror_safe(errno) : "Premature EOF");
                return MHD_CONTENT_READER_END_WITH_ERROR;
        }

        return (ssize_t) k;
}

static int request_handler_fields(
                struct MHD_Connection *connection,
                const char *field,
                void *connection_cls) {

        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response = NULL;
        RequestMeta *m = connection_cls;
        int r;

        assert(connection);
        assert(m);

        r = open_journal(m);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to open journal: %m");

        if (request_parse_accept(m, connection) < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to parse Accept header.");

        r = sd_journal_query_unique(m->journal, field);
        if (r < 0)
                return mhd_respond(connection, MHD_HTTP_BAD_REQUEST, "Failed to query unique fields.");

        response = MHD_create_response_from_callback(MHD_SIZE_UNKNOWN, 4*1024, request_reader_fields, m, NULL);
        if (!response)
                return respond_oom(connection);

        MHD_add_response_header(response, "Content-Type", mime_types[m->mode == OUTPUT_JSON ? OUTPUT_JSON : OUTPUT_SHORT]);
        return MHD_queue_response(connection, MHD_HTTP_OK, response);
}

static int request_handler_redirect(
                struct MHD_Connection *connection,
                const char *target) {

        char *page;
        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response = NULL;

        assert(connection);
        assert(target);

        if (asprintf(&page, "<html><body>Please continue to the <a href=\"%s\">journal browser</a>.</body></html>", target) < 0)
                return respond_oom(connection);

        response = MHD_create_response_from_buffer(strlen(page), page, MHD_RESPMEM_MUST_FREE);
        if (!response) {
                free(page);
                return respond_oom(connection);
        }

        MHD_add_response_header(response, "Content-Type", "text/html");
        MHD_add_response_header(response, "Location", target);
        return MHD_queue_response(connection, MHD_HTTP_MOVED_PERMANENTLY, response);
}

static int request_handler_file(
                struct MHD_Connection *connection,
                const char *path,
                const char *mime_type) {

        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response = NULL;
        _cleanup_close_ int fd = -1;
        struct stat st;

        assert(connection);
        assert(path);
        assert(mime_type);

        fd = open(path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return mhd_respondf(connection, errno, MHD_HTTP_NOT_FOUND, "Failed to open file %s: %m", path);

        if (fstat(fd, &st) < 0)
                return mhd_respondf(connection, errno, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to stat file: %m");

        response = MHD_create_response_from_fd_at_offset64(st.st_size, fd, 0);
        if (!response)
                return respond_oom(connection);
        TAKE_FD(fd);

        MHD_add_response_header(response, "Content-Type", mime_type);
        return MHD_queue_response(connection, MHD_HTTP_OK, response);
}

static int get_virtualization(char **v) {
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        char *b = NULL;
        int r;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return r;

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "Virtualization",
                        NULL,
                        &b);
        if (r < 0)
                return r;

        if (isempty(b)) {
                free(b);
                *v = NULL;
                return 0;
        }

        *v = b;
        return 1;
}

static int request_handler_machine(
                struct MHD_Connection *connection,
                void *connection_cls) {

        _cleanup_(MHD_destroy_responsep) struct MHD_Response *response = NULL;
        RequestMeta *m = connection_cls;
        int r;
        _cleanup_free_ char* hostname = NULL, *os_name = NULL;
        uint64_t cutoff_from = 0, cutoff_to = 0, usage = 0;
        sd_id128_t mid, bid;
        _cleanup_free_ char *v = NULL, *json = NULL;

        assert(connection);
        assert(m);

        r = open_journal(m);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to open journal: %m");

        r = sd_id128_get_machine(&mid);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to determine machine ID: %m");

        r = sd_id128_get_boot(&bid);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to determine boot ID: %m");

        hostname = gethostname_malloc();
        if (!hostname)
                return respond_oom(connection);

        r = sd_journal_get_usage(m->journal, &usage);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to determine disk usage: %m");

        r = sd_journal_get_cutoff_realtime_usec(m->journal, &cutoff_from, &cutoff_to);
        if (r < 0)
                return mhd_respondf(connection, r, MHD_HTTP_INTERNAL_SERVER_ERROR, "Failed to determine disk usage: %m");

        (void) parse_os_release(NULL, "PRETTY_NAME", &os_name, NULL);
        (void) get_virtualization(&v);

        r = asprintf(&json,
                     "{ \"machine_id\" : \"" SD_ID128_FORMAT_STR "\","
                     "\"boot_id\" : \"" SD_ID128_FORMAT_STR "\","
                     "\"hostname\" : \"%s\","
                     "\"os_pretty_name\" : \"%s\","
                     "\"virtualization\" : \"%s\","
                     "\"usage\" : \"%"PRIu64"\","
                     "\"cutoff_from_realtime\" : \"%"PRIu64"\","
                     "\"cutoff_to_realtime\" : \"%"PRIu64"\" }\n",
                     SD_ID128_FORMAT_VAL(mid),
                     SD_ID128_FORMAT_VAL(bid),
                     hostname_cleanup(hostname),
                     os_name ? os_name : "Linux",
                     v ? v : "bare",
                     usage,
                     cutoff_from,
                     cutoff_to);
        if (r < 0)
                return respond_oom(connection);

        response = MHD_create_response_from_buffer(strlen(json), json, MHD_RESPMEM_MUST_FREE);
        if (!response)
                return respond_oom(connection);
        TAKE_PTR(json);

        MHD_add_response_header(response, "Content-Type", "application/json");
        return MHD_queue_response(connection, MHD_HTTP_OK, response);
}

static int request_handler(
                void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **connection_cls) {
        int r, code;

        assert(connection);
        assert(connection_cls);
        assert(url);
        assert(method);

        if (!streq(method, "GET"))
                return mhd_respond(connection, MHD_HTTP_NOT_ACCEPTABLE, "Unsupported method.");

        if (!*connection_cls) {
                if (!request_meta(connection_cls))
                        return respond_oom(connection);
                return MHD_YES;
        }

        if (arg_trust_pem) {
                r = check_permissions(connection, &code, NULL);
                if (r < 0)
                        return code;
        }

        if (streq(url, "/"))
                return request_handler_redirect(connection, "/browse");

        if (streq(url, "/entries"))
                return request_handler_entries(connection, *connection_cls);

        if (startswith(url, "/fields/"))
                return request_handler_fields(connection, url + 8, *connection_cls);

        if (streq(url, "/browse"))
                return request_handler_file(connection, DOCUMENT_ROOT "/browse.html", "text/html");

        if (streq(url, "/machine"))
                return request_handler_machine(connection, *connection_cls);

        return mhd_respond(connection, MHD_HTTP_NOT_FOUND, "Not found.");
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-journal-gatewayd.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] ...\n\n"
               "HTTP server for journal events.\n\n"
               "  -h --help           Show this help\n"
               "     --version        Show package version\n"
               "     --cert=CERT.PEM  Server certificate in PEM format\n"
               "     --key=KEY.PEM    Server key in PEM format\n"
               "     --trust=CERT.PEM Certificate authority certificate in PEM format\n"
               "  -D --directory=PATH Serve journal files in directory\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_KEY,
                ARG_CERT,
                ARG_TRUST,
        };

        int r, c;

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h'           },
                { "version",   no_argument,       NULL, ARG_VERSION   },
                { "key",       required_argument, NULL, ARG_KEY       },
                { "cert",      required_argument, NULL, ARG_CERT      },
                { "trust",     required_argument, NULL, ARG_TRUST     },
                { "directory", required_argument, NULL, 'D'           },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hD:", options, NULL)) >= 0)

                switch(c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_KEY:
                        if (arg_key_pem)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Key file specified twice");
                        r = read_full_file(optarg, &arg_key_pem, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read key file: %m");
                        assert(arg_key_pem);
                        break;

                case ARG_CERT:
                        if (arg_cert_pem)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Certificate file specified twice");
                        r = read_full_file(optarg, &arg_cert_pem, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read certificate file: %m");
                        assert(arg_cert_pem);
                        break;

                case ARG_TRUST:
#if HAVE_GNUTLS
                        if (arg_trust_pem)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "CA certificate file specified twice");
                        r = read_full_file(optarg, &arg_trust_pem, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read CA certificate file: %m");
                        assert(arg_trust_pem);
                        break;
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Option --trust is not available.");
#endif
                case 'D':
                        arg_directory = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program does not take arguments.");

        if (!!arg_key_pem != !!arg_cert_pem)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Certificate and key files must be specified together");

        if (arg_trust_pem && !arg_key_pem)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "CA certificate can only be used with certificate file");

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(MHD_stop_daemonp) struct MHD_Daemon *d = NULL;
        struct MHD_OptionItem opts[] = {
                { MHD_OPTION_NOTIFY_COMPLETED,
                  (intptr_t) request_meta_free, NULL },
                { MHD_OPTION_EXTERNAL_LOGGER,
                  (intptr_t) microhttpd_logger, NULL },
                { MHD_OPTION_END, 0, NULL },
                { MHD_OPTION_END, 0, NULL },
                { MHD_OPTION_END, 0, NULL },
                { MHD_OPTION_END, 0, NULL },
                { MHD_OPTION_END, 0, NULL },
        };
        int opts_pos = 2;

        /* We force MHD_USE_ITC here, in order to make sure
         * libmicrohttpd doesn't use shutdown() on our listening
         * socket, which would break socket re-activation. See
         *
         * https://lists.gnu.org/archive/html/libmicrohttpd/2015-09/msg00014.html
         * https://github.com/systemd/systemd/pull/1286
         */

        int flags =
                MHD_USE_DEBUG |
                MHD_USE_DUAL_STACK |
                MHD_USE_ITC |
                MHD_USE_POLL_INTERNAL_THREAD |
                MHD_USE_THREAD_PER_CONNECTION;
        int r, n;

        log_setup_service();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        sigbus_install();

        r = setup_gnutls_logger(NULL);
        if (r < 0)
                return r;

        n = sd_listen_fds(1);
        if (n < 0)
                return log_error_errno(n, "Failed to determine passed sockets: %m");
        if (n > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Can't listen on more than one socket.");

        if (n == 1)
                opts[opts_pos++] = (struct MHD_OptionItem)
                        { MHD_OPTION_LISTEN_SOCKET, SD_LISTEN_FDS_START };

        if (arg_key_pem) {
                assert(arg_cert_pem);
                opts[opts_pos++] = (struct MHD_OptionItem)
                        { MHD_OPTION_HTTPS_MEM_KEY, 0, arg_key_pem };
                opts[opts_pos++] = (struct MHD_OptionItem)
                        { MHD_OPTION_HTTPS_MEM_CERT, 0, arg_cert_pem };
                flags |= MHD_USE_TLS;
        }

        if (arg_trust_pem) {
                assert(flags & MHD_USE_TLS);
                opts[opts_pos++] = (struct MHD_OptionItem)
                        { MHD_OPTION_HTTPS_MEM_TRUST, 0, arg_trust_pem };
        }

        d = MHD_start_daemon(flags, 19531,
                             NULL, NULL,
                             request_handler, NULL,
                             MHD_OPTION_ARRAY, opts,
                             MHD_OPTION_END);
        if (!d)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to start daemon!");

        pause();

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
