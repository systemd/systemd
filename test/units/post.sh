#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

(! journalctl -q -o short-monotonic --grep "didn't pass validation" | grep -v "test-varlink-idl")

# Here, the redundant '[ ]' in the pattern is required in order not to match the logged command itself.
(! journalctl -q -o short-monotonic --grep 'Warning: cannot close sd-bus connection[ ].*after fork')

# Check if sd-executor doesn't complain about not being able to (de)serialize stuff
(! journalctl -q -o short-monotonic --grep "[F]ailed to parse serialized line")
(! journalctl -q -o short-monotonic --grep "[F]ailed to (de)?serialize \w+")
