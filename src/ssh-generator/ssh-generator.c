/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "install.h"
#include "log.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "socket-netlink.h"
#include "socket-util.h"
#include "special.h"
#include "ssh-util.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

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

static const char *arg_dest = NULL;
static bool arg_auto = true;
static char **arg_listen_extra = NULL;

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

static int make_sshd_template_unit(
                const char *dest,
                const char *template,
                const char *sshd_binary,
                const char *found_sshd_template_service,
                char **generated_sshd_template_unit) {

        int r;

        assert(dest);
        assert(template);
        assert(sshd_binary);
        assert(generated_sshd_template_unit);

        /* If the system has a suitable template already, symlink it to the name we want to reuse it */
        if (found_sshd_template_service)
                return generator_add_symlink(
                                dest,
                                template,
                                /* dep_type= */ NULL,
                                found_sshd_template_service);

        if (!*generated_sshd_template_unit) {
                _cleanup_fclose_ FILE *f = NULL;

                r = generator_open_unit_file_full(
                                dest,
                                /* source= */ NULL,
                                "sshd-generated@.service", /* Give this generated unit a generic name, since we want to use it for both AF_UNIX and AF_VSOCK */
                                &f,
                                generated_sshd_template_unit,
                                /* ret_temp_path= */ NULL);
                if (r < 0)
                        return r;

                fprintf(f,
                        "[Unit]\n"
                        "Description=OpenSSH Per-Connection Server Daemon\n"
                        "Documentation=man:systemd-ssh-generator(8) man:sshd(8)\n"
                        "\n"
                        "[Service]\n"
                        "ExecStart=-%s -i -o \"AuthorizedKeysFile ${CREDENTIALS_DIRECTORY}/ssh.ephemeral-authorized_keys-all .ssh/authorized_keys\"\n"
                        "StandardInput=socket\n"
                        "ImportCredential=ssh.ephemeral-authorized_keys-all\n",
                        sshd_binary);

                r = fflush_and_check(f);
                if (r < 0)
                        return log_error_errno(r, "Failed to write sshd template: %m");
        }

        return generator_add_symlink(
                        dest,
                        template,
                        /* dep_type= */ NULL,
                        *generated_sshd_template_unit);
}

static int write_socket_unit(
                const char *dest,
                const char *unit,
                const char *listen_stream,
                const char *comment,
                const char *extra,
                bool with_ssh_access_target_dependency) {

        int r;

        assert(dest);
        assert(unit);
        assert(listen_stream);
        assert(comment);

        _cleanup_fclose_ FILE *f = NULL;
        r = generator_open_unit_file(
                        dest,
                        /* source= */ NULL,
                        unit,
                        &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Description=OpenSSH Server Socket (systemd-ssh-generator, %s)\n"
                "Documentation=man:systemd-ssh-generator(8)\n",
                comment);

        /* When this is a remotely accessible socket let's mark this with a milestone: ssh-access.target */
        if (with_ssh_access_target_dependency)
                fputs("Wants=ssh-access.target\n"
                      "Before=ssh-access.target\n",
                      f);

        fprintf(f,
                "\n[Socket]\n"
                "ListenStream=%s\n"
                "Accept=yes\n"
                "PollLimitIntervalSec=30s\n"
                "PollLimitBurst=50\n",
                listen_stream);

        if (extra)
                fputs(extra, f);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s SSH socket unit: %m", comment);

        r = generator_add_symlink(
                        dest,
                        SPECIAL_SOCKETS_TARGET,
                        "wants",
                        unit);
        if (r < 0)
                return r;

        return 0;
}

static int add_vsock_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit) {

        int r;

        assert(dest);
        assert(generated_sshd_template_unit);

        Virtualization v = detect_virtualization();
        if (v < 0)
                return log_error_errno(v, "Failed to detect if we run in a VM: %m");
        if (!VIRTUALIZATION_IS_VM(v)) {
                /* NB: if we are running in a container inside a VM, then we'll *not* do AF_VSOCK stuff */
                log_debug("Not running in a VM, not listening on AF_VSOCK.");
                return 0;
        }

        r = vsock_open_or_warn(/* ret= */ NULL);
        if (r <= 0)
                return r;

        /* Determine the local CID so that we can log it to help users to connect to this VM */
        unsigned local_cid;
        r = vsock_get_local_cid_or_warn(&local_cid);
        if (r <= 0)
                return r;

        r = make_sshd_template_unit(
                        dest,
                        "sshd-vsock@.service",
                        sshd_binary,
                        found_sshd_template_unit,
                        generated_sshd_template_unit);
        if (r < 0)
                return r;

        r = write_socket_unit(
                        dest,
                        "sshd-vsock.socket",
                        "vsock::22",
                        "AF_VSOCK",
                        "ExecStartPost=-/usr/lib/systemd/systemd-ssh-issue --make-vsock\n"
                        "ExecStopPre=-/usr/lib/systemd/systemd-ssh-issue --rm-vsock\n",
                        /* with_ssh_access_target_dependency= */ true);
        if (r < 0)
                return r;

        log_debug("Binding SSH to AF_VSOCK vsock::22.\n"
                  "→ connect via 'ssh vsock/%u' from host", local_cid);
        return 0;
}

static int add_local_unix_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit) {

        int r;

        assert(dest);
        assert(sshd_binary);
        assert(generated_sshd_template_unit);

        r = make_sshd_template_unit(
                        dest,
                        "sshd-unix-local@.service",
                        sshd_binary,
                        found_sshd_template_unit,
                        generated_sshd_template_unit);
        if (r < 0)
                return r;

        r = write_socket_unit(
                        dest,
                        "sshd-unix-local.socket",
                        "/run/ssh-unix-local/socket",
                        "AF_UNIX Local",
                        /* extra= */ NULL,
                        /* with_ssh_access_target_dependency= */ false);
        if (r < 0)
                return r;

        log_debug("Binding SSH to AF_UNIX socket /run/ssh-unix-local/socket.\n"
                  "→ connect via 'ssh .host' locally");
        return 0;
}

static int add_export_unix_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit) {

        int r;

        assert(dest);
        assert(sshd_binary);
        assert(generated_sshd_template_unit);

        Virtualization v = detect_container();
        if (v < 0)
                return log_error_errno(v, "Failed to detect if we run in a container: %m");
        if (v == VIRTUALIZATION_NONE) {
                log_debug("Not running in container, not listening on /run/host/unix-export/ssh");
                return 0;
        }

        if (access("/run/host/unix-export/", W_OK) < 0) {
                if (errno == ENOENT) {
                        log_debug("Container manager does not provide /run/host/unix-export/ mount, not binding AF_UNIX socket there.");
                        return 0;
                }
                if (ERRNO_IS_FS_WRITE_REFUSED(errno)) {
                        log_debug("Container manager does not provide write access to /run/host/unix-export/, not binding AF_UNIX socket there.");
                        return 0;
                }

                return log_error_errno(errno, "Unable to check if /run/host/unix-export exists: %m");
        }

        r = make_sshd_template_unit(
                        dest,
                        "sshd-unix-export@.service",
                        sshd_binary,
                        found_sshd_template_unit,
                        generated_sshd_template_unit);
        if (r < 0)
                return r;

        r = write_socket_unit(
                        dest,
                        "sshd-unix-export.socket",
                        "/run/host/unix-export/ssh",
                        "AF_UNIX Export",
                        /* extra= */ NULL,
                        /* with_ssh_access_target_dependency= */ true);
        if (r < 0)
                return r;

        log_debug("Binding SSH to AF_UNIX socket /run/host/unix-export/ssh\n"
                  "→ connect via 'ssh unix/run/systemd/nspawn/unix-export/\?\?\?/ssh' from host");

        return 0;
}

static int add_extra_sockets(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit) {

        unsigned n = 1;
        int r;

        assert(dest);
        assert(sshd_binary);
        assert(generated_sshd_template_unit);

        if (strv_isempty(arg_listen_extra))
                return 0;

        STRV_FOREACH(i, arg_listen_extra) {
                _cleanup_free_ char *service = NULL, *socket = NULL;

                if (n > 1) {
                        if (asprintf(&service, "sshd-extra-%u@.service", n) < 0)
                                return log_oom();

                        if (asprintf(&socket, "sshd-extra-%u.socket", n) < 0)
                                return log_oom();
                }

                r = make_sshd_template_unit(
                                dest,
                                service ?: "sshd-extra@.service",
                                sshd_binary,
                                found_sshd_template_unit,
                                generated_sshd_template_unit);
                if (r < 0)
                        return r;

                r = write_socket_unit(
                                dest,
                                socket ?: "sshd-extra.socket",
                                *i,
                                *i,
                                /* extra= */ NULL,
                                /* with_ssh_access_target_dependency= */ true);
                if (r < 0)
                        return r;

                log_debug("Binding SSH to socket %s.", *i);
                n++;
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

        assert_se(arg_dest = dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, /* flags= */ 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        (void) parse_credentials();

        strv_sort_uniq(arg_listen_extra);

        if (!arg_auto && strv_isempty(arg_listen_extra)) {
                log_debug("Disabling SSH generator logic, because it has been turned off explicitly.");
                return 0;
        }

        _cleanup_free_ char *sshd_binary = NULL;
        r = find_executable("sshd", &sshd_binary);
        if (r == -ENOENT) {
                log_debug("Disabling SSH generator logic, since sshd is not installed.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine if sshd is installed: %m");

        _cleanup_(lookup_paths_done) LookupPaths lp = {};
        r = lookup_paths_init_or_warn(&lp, RUNTIME_SCOPE_SYSTEM, LOOKUP_PATHS_EXCLUDE_GENERATED, /* root_dir= */ NULL);
        if (r < 0)
                return r;

        _cleanup_free_ char *found_sshd_template_unit = NULL;
        r = unit_file_exists_full(RUNTIME_SCOPE_SYSTEM, &lp, "sshd@.service", &found_sshd_template_unit);
        if (r < 0)
                return log_error_errno(r, "Unable to detect if sshd@.service exists: %m");

        _cleanup_free_ char *generated_sshd_template_unit = NULL;
        RET_GATHER(r, add_extra_sockets(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));

        if (arg_auto) {
                RET_GATHER(r, add_vsock_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
                RET_GATHER(r, add_local_unix_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
                RET_GATHER(r, add_export_unix_socket(dest, sshd_binary, found_sshd_template_unit, &generated_sshd_template_unit));
        }

        return r;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
