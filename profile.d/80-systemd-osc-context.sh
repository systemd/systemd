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

# This implements the UAPI.15 "OSC 3008: Hierarchical Context Signalling"
# specification for the shell prompt. For details see:
# https://uapi-group.org/specifications/specs/osc_context/

# Not bash?
[ -n "${BASH_VERSION:-}" ] || return 0

# If we're on a "dumb" terminal, do not install the prompt.
# Treat missing $TERM same as "dumb".
[ "${TERM:-dumb}" = "dumb" ] && return 0

__systemd_osc_context_escape() {
    # Escape according to the OSC 3008 spec. Since this requires shelling out
    # to 'sed' we'll only do it where it's strictly necessary, and skip it when
    # processing strings we are pretty sure we won't need it for, such as
    # uuids, id128, hostnames, usernames, since they all come with syntax
    # requirements that exclude \ and ; anyway. This hence primarily is about
    # escaping the current working directory.
    echo "$1" | sed -e 's/\\/\\x5c/g' -e 's/;/\\x3b/g' -e 's/[[:cntrl:]]/⍰/g'
}

__systemd_osc_context_common() {
    if [ -f /etc/machine-id ]; then
        printf ";machineid=%.36s" "$(</etc/machine-id)"
    fi
    printf ";user=%.255s;hostname=%.255s;bootid=%.36s;pid=%.20d" "$USER" "$HOSTNAME" "$(</proc/sys/kernel/random/boot_id)" "$$"
}

__systemd_osc_context_precmdline() {
    local systemd_exitstatus="$?" systemd_signal

    # Close previous command
    if [ -n "${systemd_osc_context_cmd_id:-}" ]; then
        if [ "$systemd_exitstatus" -gt 128 ] && systemd_signal=$(kill -l "$systemd_exitstatus" 2>&-); then
            printf "\033]3008;end=%.64s;exit=failure;status=%d;signal=SIG%s\033\\" "$systemd_osc_context_cmd_id" "$systemd_exitstatus" "$systemd_signal"
        elif [ "$systemd_exitstatus" -ne 0 ]; then
            printf "\033]3008;end=%.64s;exit=failure;status=%d\033\\" "$systemd_osc_context_cmd_id" $((systemd_exitstatus))
        else
            printf "\033]3008;end=%.64s;exit=success\033\\" "$systemd_osc_context_cmd_id"
        fi
    fi

    # Prepare a context ID for this shell if we have none
    if [ -z "${systemd_osc_context_shell_id:-}" ]; then
        read -r systemd_osc_context_shell_id </proc/sys/kernel/random/uuid
    fi

    # Create or update the shell session
    printf "\033]3008;start=%.64s%s;type=shell;cwd=%.255s\033\\" "$systemd_osc_context_shell_id" "$(__systemd_osc_context_common)" "$(__systemd_osc_context_escape "$PWD")"

    # Prepare cmd id for next command
    read -r systemd_osc_context_cmd_id </proc/sys/kernel/random/uuid
}

__systemd_osc_context_ps0() {
    # Skip if PROMPT_COMMAND= is cleared manually or by other profiles.
    [ -n "${systemd_osc_context_cmd_id:-}" ] || return

    printf "\033]3008;start=%.64s%s;type=command;cwd=%.255s\033\\" "$systemd_osc_context_cmd_id" "$(__systemd_osc_context_common)" "$(__systemd_osc_context_escape "$PWD")"
}

if [ -n "${BASH_VERSION:-}" ]; then
    # Legacy bashrc will assign PROMPT_COMMAND=, which is equivalent to assigning
    # index 0 in the array. Leave an empty spot to handle this gracefully.
    [ -n "$(declare -p PROMPT_COMMAND 2>/dev/null)" ] || PROMPT_COMMAND+=('')

    # Whenever a new prompt is shown, close the previous command, and prepare new command
    PROMPT_COMMAND+=(__systemd_osc_context_precmdline)

    # PS0 is shown right after a prompt completed, but before the command is executed
    PS0='$(__systemd_osc_context_ps0)'"${PS0:-}"
fi
