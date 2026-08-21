# SPDX-License-Identifier: LGPL-2.1-or-later

# Build-time-only tool exposing the compiled-in Varlink IDL interfaces, so documentation
# and other machine-readable artifacts can be generated hermetically from them.

varlink_introspect_interface_sources = [
        sd_varlink_idl_interface_sources,
        varlink_idl_interface_sources,
]

varlink_introspect_interfaces_inc = custom_target(
        'varlink-introspect-interfaces.inc',
        input : varlink_introspect_interface_sources,
        output : 'varlink-introspect-interfaces.inc',
        command : [generate_varlink_introspect_py, '@OUTPUT@', '@INPUT@'])

varlink_idl_json_sources = files('varlink-idl-json.c')

varlink_introspect_sources = files('varlink-introspect.c') + varlink_idl_json_sources
test_varlink_introspect_sources = files('test-varlink-introspect.c') + varlink_idl_json_sources

# The generated interface table is a build artifact of this directory: the test does not get it
# on the include path automatically.
varlink_introspect_includes = includes + [include_directories('.')]

executables += [
        executable_template + {
                'name' : 'systemd-varlink-introspect',
                'sources' : varlink_introspect_sources + [varlink_introspect_interfaces_inc],
                'include_directories' : varlink_introspect_includes,
                'install' : 'no',
        },
        test_template + {
                'sources' : test_varlink_introspect_sources + [varlink_introspect_interfaces_inc],
                'include_directories' : varlink_introspect_includes,
        },
]
