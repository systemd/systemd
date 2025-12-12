# SPDX-License-Identifier: LGPL-2.1-or-later

# We're generating a header file here intended to be included
# by audit-type.c. To make that work, we have to add the generated
# header file's directory to the include directories for libsystemd.
# In meson, adding include directories is done via include_directories(),
# which always adds two include directories for each argument, one relative to
# the source directory and one relative to the build directory. We don't
# want to add src/libsystemd to the include directories, yet custom_target()
# does not allow path segments in its output argument, so to make sure the
# generated header is written to src/libsystemd/sd-journal in the build directory,
# the custom_target() has to be defined here in src/libsystemd/sd-journal
# in the source directory.

generate_audit_type_list = files('generate-audit_type-list.sh')
audit_type_list_txt = custom_target(
        input : [generate_audit_type_list, audit_sources],
        output : 'audit_type-list.txt',
        command : [env, 'bash', generate_audit_type_list, cpp, system_include_args],
        capture : true)

audit_type_to_name = custom_target(
        input : ['audit_type-to-name.awk', audit_type_list_txt],
        output : 'audit_type-to-name.inc',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)
