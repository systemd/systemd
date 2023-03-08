#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Test for udevadm verify.

udevadm verify -h
udevadm verify --help
udevadm verify -V
udevadm verify --version
udevadm verify /dev/null

# No rules file specified.
(! udevadm verify)
# unrecognized option '--unknown'
(! udevadm verify --unknown)
# option requires an argument -- 'N'
(! udevadm verify -N)
# --resolve-names= takes "early" or "never"
(! udevadm verify -N now)
# option '--resolve-names' requires an argument
(! udevadm verify --resolve-names)
# --resolve-names= takes "early" or "never"
(! udevadm verify --resolve-names=now)
# Failed to parse rules file .: Is a directory
(! udevadm verify .)
# Failed to parse rules file .: Is a directory
(! udevadm verify /dev/null . /dev/null)

# UDEV_LINE_SIZE 16384
printf '%16383s\n' ' ' >sample.rules
udevadm verify sample.rules

# Failed to parse rules file sample.rules: No buffer space available
printf '%16384s\n' ' ' >sample.rules
(! udevadm verify sample.rules)

printf 'RUN+="/bin/true"%8175s\\\n' ' ' ' ' >sample.rules
echo >>sample.rules
udevadm verify sample.rules

printf 'RUN+="/bin/true"%8176s\\\n #\n' ' ' ' ' >sample.rules
echo >>sample.rules
cat >exp <<'EOF'
sample.rules:5 Line is too long, ignored
sample.rules: udev rules check failed
EOF
(! udevadm verify sample.rules 2>err)
diff exp err

printf '\\\n' >sample.rules
cat >exp <<'EOF'
sample.rules:1 Unexpected EOF after line continuation, line ignored
sample.rules: udev rules check failed
EOF
(! udevadm verify sample.rules 2>err)
diff exp err

test_syntax_error() {
	local rule msg
	rule="$1"; shift
	msg="$1"; shift

	printf '%s\n' "$rule" > sample.rules
	cat >exp <<-EOF
		sample.rules:1 $msg
		sample.rules: udev rules check failed
	EOF
	(! udevadm verify sample.rules 2>err)
	diff exp err
}

test_syntax_error '=' 'Invalid key/value pair, ignoring.'
test_syntax_error 'ACTION{a}=="b"' 'Invalid attribute for ACTION.'
test_syntax_error 'ACTION:="b"' 'Invalid operator for ACTION.'
test_syntax_error 'ACTION=="b"' 'The line takes no effect, ignoring.'
test_syntax_error 'DEVPATH{a}=="b"' 'Invalid attribute for DEVPATH.'
test_syntax_error 'DEVPATH:="b"' 'Invalid operator for DEVPATH.'
test_syntax_error 'KERNEL{a}=="b"' 'Invalid attribute for KERNEL.'
test_syntax_error 'KERNEL:="b"' 'Invalid operator for KERNEL.'
test_syntax_error 'KERNELS{a}=="b"' 'Invalid attribute for KERNELS.'
test_syntax_error 'KERNELS:="b"' 'Invalid operator for KERNELS.'
test_syntax_error 'SYMLINK{a}=="b"' 'Invalid attribute for SYMLINK.'
test_syntax_error 'SYMLINK:="%?"' 'Invalid value "%?" for SYMLINK (char 1: invalid substitution type), ignoring.'
test_syntax_error 'NAME{a}=="b"' 'Invalid attribute for NAME.'
test_syntax_error 'NAME-="b"' 'Invalid operator for NAME.'
test_syntax_error 'NAME+="a"' "NAME key takes '==', '!=', '=', or ':=' operator, assuming '='."
test_syntax_error 'NAME:=""' 'Ignoring NAME="", as udev will not delete any network interfaces.'
test_syntax_error 'NAME="%k"' 'Ignoring NAME="%k", as it will take no effect.'
test_syntax_error 'ENV=="b"' 'Invalid attribute for ENV.'
test_syntax_error 'ENV{a}-="b"' 'Invalid operator for ENV.'
test_syntax_error 'ENV{a}:="b"' "ENV key takes '==', '!=', '=', or '+=' operator, assuming '='."
test_syntax_error 'ENV{ACTION}="b"' "Invalid ENV attribute. 'ACTION' cannot be set."
test_syntax_error 'CONST=="b"' 'Invalid attribute for CONST.'
test_syntax_error 'CONST{a}=="b"' 'Invalid attribute for CONST.'
test_syntax_error 'CONST{arch}="b"' 'Invalid operator for CONST.'
test_syntax_error 'TAG{a}=="b"' 'Invalid attribute for TAG.'
test_syntax_error 'TAG:="a"' "TAG key takes '==', '!=', '=', or '+=' operator, assuming '='."
test_syntax_error 'TAG="%?"' 'Invalid value "%?" for TAG (char 1: invalid substitution type), ignoring.'
test_syntax_error 'TAGS{a}=="b"' 'Invalid attribute for TAGS.'
test_syntax_error 'TAGS:="a"' 'Invalid operator for TAGS.'
test_syntax_error 'SUBSYSTEM{a}=="b"' 'Invalid attribute for SUBSYSTEM.'
test_syntax_error 'SUBSYSTEM:="b"' 'Invalid operator for SUBSYSTEM.'
test_syntax_error 'SUBSYSTEM=="bus" NAME="b"' '"bus" must be specified as "subsystem".'
test_syntax_error 'SUBSYSTEMS{a}=="b"' 'Invalid attribute for SUBSYSTEMS.'
test_syntax_error 'SUBSYSTEMS:="b"' 'Invalid operator for SUBSYSTEMS.'
test_syntax_error 'DRIVER{a}=="b"' 'Invalid attribute for DRIVER.'
test_syntax_error 'DRIVER:="b"' 'Invalid operator for DRIVER.'
test_syntax_error 'DRIVERS{a}=="b"' 'Invalid attribute for DRIVERS.'
test_syntax_error 'DRIVERS:="b"' 'Invalid operator for DRIVERS.'
test_syntax_error 'ATTR="b"' 'Invalid attribute for ATTR.'
test_syntax_error 'ATTR{%}="b"' 'Invalid attribute "%" for ATTR (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTR{a}-="b"' 'Invalid operator for ATTR.'
test_syntax_error 'ATTR{a}+="b"' "ATTR key takes '==', '!=', or '=' operator, assuming '='."
test_syntax_error 'ATTR{a}="%?"' 'Invalid value "%?" for ATTR (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SYSCTL=""' 'Invalid attribute for SYSCTL.'
test_syntax_error 'SYSCTL{%}="b"' 'Invalid attribute "%" for SYSCTL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SYSCTL{a}-="b"' 'Invalid operator for SYSCTL.'
test_syntax_error 'SYSCTL{a}+="b"' "SYSCTL key takes '==', '!=', or '=' operator, assuming '='."
test_syntax_error 'SYSCTL{a}="%?"' 'Invalid value "%?" for SYSCTL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTRS=""' 'Invalid attribute for ATTRS.'
test_syntax_error 'ATTRS{%}=="b" NAME="b"' 'Invalid attribute "%" for ATTRS (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTRS{a}-="b"' 'Invalid operator for ATTRS.'
test_syntax_error 'ATTRS{device/}!="a" NAME="b"' "'device' link may not be available in future kernels."
test_syntax_error 'ATTRS{../}!="a" NAME="b"' 'Direct reference to parent sysfs directory, may break in future kernels.'
test_syntax_error 'TEST{a}=="b"' "Failed to parse mode 'a': Invalid argument"
test_syntax_error 'TEST{0}=="%" NAME="b"' 'Invalid value "%" for TEST (char 1: invalid substitution type), ignoring.'
test_syntax_error 'TEST{0644}="b"' 'Invalid operator for TEST.'
test_syntax_error 'PROGRAM{a}=="b"' 'Invalid attribute for PROGRAM.'
test_syntax_error 'PROGRAM-="b"' 'Invalid operator for PROGRAM.'
test_syntax_error 'PROGRAM=="%" NAME="b"' 'Invalid value "%" for PROGRAM (char 1: invalid substitution type), ignoring.'
test_syntax_error 'IMPORT="b"' 'Invalid attribute for IMPORT.'
test_syntax_error 'IMPORT{a}="b"' 'Invalid attribute for IMPORT.'
test_syntax_error 'IMPORT{a}-="b"' 'Invalid operator for IMPORT.'
test_syntax_error 'IMPORT{file}=="%" NAME="b"' 'Invalid value "%" for IMPORT (char 1: invalid substitution type), ignoring.'
test_syntax_error 'IMPORT{builtin}!="foo"' 'Unknown builtin command: foo'
test_syntax_error 'RESULT{a}=="b"' 'Invalid attribute for RESULT.'
test_syntax_error 'RESULT:="b"' 'Invalid operator for RESULT.'
test_syntax_error 'OPTIONS{a}="b"' 'Invalid attribute for OPTIONS.'
test_syntax_error 'OPTIONS-="b"' 'Invalid operator for OPTIONS.'
test_syntax_error 'OPTIONS!="b"' 'Invalid operator for OPTIONS.'
test_syntax_error 'OPTIONS+="link_priority=a"' "Failed to parse link priority 'a': Invalid argument"
test_syntax_error 'OPTIONS:="log_level=a"' "Failed to parse log level 'a': Invalid argument"
test_syntax_error 'OPTIONS="a" NAME="b"' "Invalid value for OPTIONS key, ignoring: 'a'"
test_syntax_error 'OWNER{a}="b"' 'Invalid attribute for OWNER.'
test_syntax_error 'OWNER-="b"' 'Invalid operator for OWNER.'
test_syntax_error 'OWNER!="b"' 'Invalid operator for OWNER.'
test_syntax_error 'OWNER+="0"' "OWNER key takes '=' or ':=' operator, assuming '='."
test_syntax_error 'OWNER="nosuchuser"' "Unknown user 'nosuchuser', ignoring"
test_syntax_error 'GROUP{a}="b"' 'Invalid attribute for GROUP.'
test_syntax_error 'GROUP-="b"' 'Invalid operator for GROUP.'
test_syntax_error 'GROUP!="b"' 'Invalid operator for GROUP.'
test_syntax_error 'GROUP+="0"' "GROUP key takes '=' or ':=' operator, assuming '='."
test_syntax_error 'GROUP="nosuchuser"' "Unknown group 'nosuchuser', ignoring"
test_syntax_error 'MODE{a}="b"' 'Invalid attribute for MODE.'
test_syntax_error 'MODE-="b"' 'Invalid operator for MODE.'
test_syntax_error 'MODE!="b"' 'Invalid operator for MODE.'
test_syntax_error 'MODE+="0"' "MODE key takes '=' or ':=' operator, assuming '='."
test_syntax_error 'MODE="%"' 'Invalid value "%" for MODE (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SECLABEL="b"' 'Invalid attribute for SECLABEL.'
test_syntax_error 'SECLABEL{a}="%"' 'Invalid value "%" for SECLABEL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SECLABEL{a}!="b"' 'Invalid operator for SECLABEL.'
test_syntax_error 'SECLABEL{a}-="b"' 'Invalid operator for SECLABEL.'
test_syntax_error 'SECLABEL{a}:="b"' "SECLABEL key takes '=' or '+=' operator, assuming '='."
test_syntax_error 'RUN=="b"' 'Invalid operator for RUN.'
test_syntax_error 'RUN-="b"' 'Invalid operator for RUN.'
test_syntax_error 'RUN="%"' 'Invalid value "%" for RUN (char 1: invalid substitution type), ignoring.'
test_syntax_error 'RUN{builtin}+="foo"' "Unknown builtin command 'foo', ignoring"
test_syntax_error 'GOTO{a}="b"' 'Invalid attribute for GOTO.'
test_syntax_error 'GOTO=="b"' 'Invalid operator for GOTO.'
test_syntax_error 'NAME="a" GOTO="b"' 'GOTO="b" has no matching label, ignoring'
test_syntax_error 'GOTO="a" GOTO="b"
LABEL="a"' 'Contains multiple GOTO keys, ignoring GOTO="b".'
test_syntax_error 'LABEL{a}="b"' 'Invalid attribute for LABEL.'
test_syntax_error 'LABEL=="b"' 'Invalid operator for LABEL.'
test_syntax_error 'LABEL="b"' 'LABEL="b" is unused.'
test_syntax_error 'a="b"' "Invalid key 'a'"

echo 'GOTO="a"' >sample.rules
cat >exp <<'EOF'
sample.rules:1 GOTO="a" has no matching label, ignoring
sample.rules:1 The line takes no effect any more, dropping
sample.rules: udev rules check failed
EOF
(! udevadm verify sample.rules 2>err)
diff exp err

cat >sample.rules <<'EOF'
GOTO="a"
LABEL="a"
EOF
udevadm verify sample.rules

cat >sample.rules <<'EOF'
GOTO="b"
LABEL="b"
LABEL="b"
EOF
cat >exp <<'EOF'
sample.rules:3 LABEL="b" is unused.
sample.rules: udev rules check failed
EOF
(! udevadm verify sample.rules 2>err)
diff exp err

exit 0
