#!/usr/bin/env bash
# This test makes some basic checks that RPM macros work correctly.
# RPM is a simple C program available on different Linux distros, not only RPM-based ones,
# and even BSD systems, so it must not be a problem to require it.
# rpmspec utility is required (so this test will work with RPM 4 but won't work with RPM 5).
set -xefu

trap 'echo "Some tests of RPM macros failed!"' ERR
trap 'rm -f $TMP_RPM_SPEC $crp_tmp' EXIT

RPM_MACROS_FILE="${TEST_BASE_DIR}/../src/core/macros.systemd.in"

if ! command -v rpmspec >/dev/null 2>&1 ; then
	echo "rpmspec(8) is needed to run test 54!"
	exit 1
fi

if [ ! -f "$RPM_MACROS_FILE" ]; then
	echo "RPM macros file not found in ${RPM_MACROS_FILE}!"
	exit 1
fi

TMP_RPM_SPEC="$(mktemp)"
RPM_SPEC_HEADER="
Summary: systemd test 54
Name: systemd-test-54
License: xxx
Version: 1
Release: 1
%description
%{summary}
END_OF_INITIAL_SPEC
"

mk_mini_spec(){
	# prepare minimal spec file
	echo "%{load:$RPM_MACROS_FILE}" > "$TMP_RPM_SPEC"
	echo "$RPM_SPEC_HEADER" >> "$TMP_RPM_SPEC"
}

mk_mini_spec
# ensure its loadability (macros will be just loaded and not used for now)
# also check that rpm supports %load
rpmspec --parse "$TMP_RPM_SPEC"

# %systemd_requires
mk_mini_spec
# The idea of tests is the following:
# - make a minimal spec file
# - add macros into its %description section
# - use rpmspec(8) to print spec file with expanded macros
# - check that macros have been expanded as required.
echo "%systemd_requires" >> "$TMP_RPM_SPEC"
o="$(rpmspec --parse "$TMP_RPM_SPEC" | grep '^Requires(')"
for i in post preun postun
do
	grep -q "^Requires($i): systemd$" <<< "$o"
done

# %systemd_ordering
mk_mini_spec
echo "%systemd_ordering" >> "$TMP_RPM_SPEC"
o="$(rpmspec --parse "$TMP_RPM_SPEC" | grep '^OrderWithRequires')"
for i in post preun postun
do
	grep -q "^OrderWithRequires($i): systemd$" <<< "$o"
done

# test that macros which require some arguements throw an error if no arguement is passed
for i in \
	systemd_post \
	systemd_preun \
	systemd_postun \
	systemd_postun_with_restart \
	systemd_user_preun \
	systemd_user_postun \
	systemd_user_postun_with_restart \
	tmpfiles_create \
	tmpfiles_create_package \
	sysusers_create \
	sysusers_create_package
do
	mk_mini_spec
	echo "%${i}" >> "$TMP_RPM_SPEC"
	# check that rpmspec failed - that macros gave an error
	o="$(! rpmspec --parse "$TMP_RPM_SPEC" 2>&1)"
	[ $? = 0 ]
done

# test that some macros correctly require 2 arguements
for i in \
	tmpfiles_create_package \
	sysusers_create_package
do
	mk_mini_spec
	# test with 1 arg
	echo "%${i} 1arg" >> "$TMP_RPM_SPEC"
	# check that rpmspec failed - that macros gave an error
	o="$(! rpmspec --parse "$TMP_RPM_SPEC" 2>&1)"
	[ $? = 0 ]
	# test with >2 args
	echo "%${i} 1arg 2arg 3arg" >> "$TMP_RPM_SPEC"
	# check that rpmspec failed - that macros gave an error
	o="$(! rpmspec --parse "$TMP_RPM_SPEC" 2>&1)"
	[ $? = 0 ]
done

# Test that:
# - *_create_package macros do work correctly
# - shell syntax is correct (https://github.com/systemd/systemd/commit/93406fd37)
# - RPM macros, loaded from macros.in, are actually expanded
crp_tmp="$(mktemp)"

echo 'TEST_DATA' > "$crp_tmp"
mk_mini_spec
echo "%sysusers_create_package TEST_NAME ${crp_tmp}" >> "$TMP_RPM_SPEC"
required_output='systemd-sysusers --replace=@sysusersdir@/TEST_NAME.conf - <<SYSTEMD_INLINE_EOF || :
TEST_DATA
SYSTEMD_INLINE_EOF'
# note no trailing whitespace above!
o="$(rpmspec --parse "$TMP_RPM_SPEC" | grep '^TEST_DATA$' -A1 -B1)"
# diff(1) returns 0 if there are no differences, that is what we need
# XXX /dev/fd/* may be not available in some environments (?)
diff -u <(echo "$required_output") <(echo "$o")
[ $? = 0 ]

mk_mini_spec
echo "%tmpfiles_create_package TEST_NAME ${crp_tmp}" >> "$TMP_RPM_SPEC"
required_output='systemd-tmpfiles --replace=@tmpfilesdir@/TEST_NAME.conf --create - <<SYSTEMD_INLINE_EOF || :
TEST_DATA
SYSTEMD_INLINE_EOF'
# not no trailing whitespace above!
o="$(rpmspec --parse "$TMP_RPM_SPEC" | grep '^TEST_DATA$' -A1 -B1)"
# diff(1) returns 0 if there are no differences, that is what we need
diff -u <(echo "$required_output") <(echo "$o")
[ $? = 0 ]
