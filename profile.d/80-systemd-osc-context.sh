# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
# shellcheck disable=SC2016
# shellcheck disable=SC1003

#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# Not bash?
[ -n "${BASH_VERSION:-}" ] || return 0

__systemd_osc_context_escape() {
    # Escape according to the OSC 3008 spec. Since this requires shelling out
    # to 'sed' we'll only do it where it's strictly necessary, and skip it when
    # processing strings we are pretty sure we won't need it for, such as
    # uuids, id128, hostnames, usernames, since they all come with syntax
    # requirements that exclude \ and ; anyway. This hence primarily is about
    # escaping the current working directory.
    echo "$1" | sed -e 's/\\/\\x5x/g' -e 's/;/\\x3b/g'
}

__systemd_osc_context_common() {
    printf ";user=%s;hostname=%s;machineid=%s;bootid=%s;pid=%s" "$USER" "$HOSTNAME" "$(</etc/machine-id)" "$(</proc/sys/kernel/random/boot_id)" "$$"
}

__systemd_osc_context_precmdline() {
    local systemd_exitstatus="$?"

    # Close previous command
    if [ -n "${systemd_osc_context_cmd_id:-}" ]; then
        if [ "$systemd_exitstatus" -ge 127 ]; then
            printf "\033]3008;end=%s;exit=interrupt;signal=%s\033\\" "$systemd_osc_context_cmd_id" $((systemd_exitstatus-127))
        elif [ "$systemd_exitstatus" -ne 0 ]; then
            printf "\033]3008;end=%s;exit=failure;status=%s\033\\" "$systemd_osc_context_cmd_id" $((systemd_exitstatus))
        else
            printf "\033]3008;end=%s;exit=success\033\\" "$systemd_osc_context_cmd_id"
        fi
    fi

    # Prepare a context ID for this shell if we have none
    if [ -z "${systemd_osc_context_shell_id:-}" ]; then
        read -r systemd_osc_context_shell_id </proc/sys/kernel/random/uuid
    fi

    # Create or update the shell session
    printf "\033]3008;start=%s%s;type=shell;cwd=%s\033\\" "$systemd_osc_context_shell_id" "$(__systemd_osc_context_common)" "$(__systemd_osc_context_escape "$PWD")"

    # Prepare cmd id for next command
    read -r systemd_osc_context_cmd_id </proc/sys/kernel/random/uuid
}

if [[ -n "${BASH_VERSION:-}" ]] && [[ "${TERM:-}" != "dumb" ]]; then
    # Whenever a new prompt is shown close the previous command, and prepare new command
    PROMPT_COMMAND+=(__systemd_osc_context_precmdline)

    # PS0 is shown right after a prompt completed, but before the command is executed
    PS0='\033]3008;start=$systemd_osc_context_cmd_id$(__systemd_osc_context_common);type=command;cwd=$(__systemd_osc_context_escape "$PWD")\033\\'"${PS0:-}"
fi
