/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "creds-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "log.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "ssh-generator-util.h"
#include "string-util.h"
#include "strv.h"

/* A small generator binding potentially five or more SSH sockets:
 *
 *     1. Listen on AF_VSOCK port 22 if we run in a VM with AF_VSOCK enabled
 *     2. Listen on AF_UNIX socket /run/host/unix-export/ssh if we run in a container with /run/host/ support
 *     3. Listen on AF_UNIX socket /run/ssh-unix-local/socket (always)
 *     4. Listen on any socket specified via kernel command line option systemd.ssh_listen=
 *     5. Similar, but from system credential ssh.listen
 *
 * The first two provide a nice way for hosts to connect to containers and VMs they invoke via the usual SSH
 * logic, but without waiting for networking or suchlike. The third allows the same for local clients. */

static bool arg_auto = true;
static char **arg_listen_extra = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_listen_extra, strv_freep);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.ssh_auto")) {
                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.ssh_auto switch \"%s\", ignoring: %m", value);
                else
                        arg_auto = r;

        } else if (proc_cmdline_key_streq(key, "systemd.ssh_listen")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                SocketAddress sa;
                r = socket_address_parse(&sa, value);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.ssh_listen= expression, ignoring: %s", value);
                else {
                        _cleanup_free_ char *s = NULL;
                        r = socket_address_print(&sa, &s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to format socket address: %m");

                        if (strv_consume(&arg_listen_extra, TAKE_PTR(s)) < 0)
                                return log_oom();
                }
        }

        return 0;
}

static int parse_credentials(void) {
        _cleanup_free_ char *b = NULL;
        size_t sz = 0;
        int r;

        r = read_credential_with_decryption("ssh.listen", (void**) &b, &sz);
        if (r <= 0)
                return r;

        _cleanup_fclose_ FILE *f = NULL;
        f = fmemopen_unlocked(b, sz, "r");
        if (!f)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *item = NULL;

                r = read_stripped_line(f, LINE_MAX, &item);
                if (r == 0)
                        break;
                if (r < 0) {
                        log_error_errno(r, "Failed to parse credential 'ssh.listen': %m");
                        break;
                }

                if (startswith(item, "#"))
                        continue;

                SocketAddress sa;
                r = socket_address_parse(&sa, item);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse systemd.ssh_listen= expression, ignoring: %s", item);
                        continue;
                }

                _cleanup_free_ char *s = NULL;
                r = socket_address_print(&sa, &s);
                if (r < 0)
                        return log_error_errno(r, "Failed to format socket address: %m");

                if (strv_consume(&arg_listen_extra, TAKE_PTR(s)) < 0)
                        return log_oom();
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert(dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        (void) parse_credentials();

        strv_sort_uniq(arg_listen_extra);

        if (!arg_auto && strv_isempty(arg_listen_extra)) {
                log_debug("Disabling SSH generator logic, because it has been turned off explicitly.");
                return 0;
        }

        _cleanup_free_ char *sshd_binary = NULL, *found_sshd_template_unit = NULL;
        r = find_sshd(&sshd_binary, &found_sshd_template_unit);
        if (r < 0)
                return r;

        _cleanup_free_ char *generated_sshd_template_unit = NULL;
        RET_GATHER(r, add_extra_sockets(arg_listen_extra, dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));

        if (arg_auto) {
                RET_GATHER(r, add_vsock_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
                RET_GATHER(r, add_local_unix_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
                RET_GATHER(r, add_export_unix_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
        }

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
