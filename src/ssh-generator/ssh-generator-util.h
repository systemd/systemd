/* SPDX-License-Identifier: LGPL-2.1-or-later */

int add_vsock_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit);

int add_local_unix_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit);

int add_export_unix_socket(
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit);

int add_extra_sockets(
                char * const *listen_extra,
                const char *dest,
                const char *sshd_binary,
                const char *found_sshd_template_unit,
                char **generated_sshd_template_unit);

int find_sshd(char **ret_sshd_binary, char **ret_sshd_template_unit);
