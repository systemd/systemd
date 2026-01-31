/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "install.h"
#include "log.h"
#include "path-lookup.h"
#include "path-util.h"
#include "special.h"
#include "ssh-generator-util.h"
#include "ssh-util.h"
#include "strv.h"
#include "virt.h"

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

        /* If the system has a suitable template already, symlink it under the name we want to use */
        if (found_sshd_template_service)
                return generator_add_symlink(
                                dest,
                                template,
                                /* dep_type= */ NULL,
                                found_sshd_template_service);

        if (!*generated_sshd_template_unit) {
                _cleanup_fclose_ FILE *f = NULL;

                /* We use a generic name for the unit, since we'll use it for both AF_UNIX and AF_VSOCK  */
                r = generator_open_unit_file_full(
                                dest,
                                /* source= */ NULL,
                                "sshd-generated@.service",
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

int add_vsock_socket(
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
        return 1;
}

int add_local_unix_socket(
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
        return 1;
}

int add_export_unix_socket(
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

        return 1;
}

int add_extra_sockets(
                char * const *listen_extra,
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit) {

        unsigned n = 1;
        int r;

        assert(dest);
        assert(sshd_binary);
        assert(generated_sshd_template_unit);

        STRV_FOREACH(i, listen_extra) {
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

        return n > 0;
}

int find_sshd(char **ret_sshd_binary, char **ret_sshd_template_unit) {
        int r;

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

        _cleanup_free_ char *sshd_template_unit = NULL;
        r = unit_file_exists_full(RUNTIME_SCOPE_SYSTEM, &lp, "sshd@.service", &sshd_template_unit);
        if (r < 0)
                return log_error_errno(r, "Unable to detect if sshd@.service exists: %m");

        *ret_sshd_binary = TAKE_PTR(sshd_binary);
        *ret_sshd_template_unit = TAKE_PTR(sshd_template_unit);
        return 0;
}
