# shellcheck shell=sh

#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# Import the additional shell prompt prefix and suffix strings into $PS1, and
# show the shell welcome string. These can be provisioned as system or service
# credentials shell.prompt.prefix, shell.prompt.suffix and shell.welcome, and
# are propagated into these environment variables by pam_systemd(8).

if [ -n "${SHELL_PROMPT_PREFIX-}" ]; then
    PS1="$SHELL_PROMPT_PREFIX$PS1"
fi

if [ -n "${SHELL_PROMPT_SUFFIX-}" ]; then
    PS1="$PS1$SHELL_PROMPT_SUFFIX"
fi

if [ -n "${SHELL_WELCOME-}" ]; then
   printf '%b\n' "$SHELL_WELCOME"
fi
