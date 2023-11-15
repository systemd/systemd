# SPDX-License-Identifier: LGPL-2.1-or-later

generate_directives_py = find_program('generate-directives.py')

fuzz_regression_tests = {}

directives = [['fuzz-network-parser', 'directives.network', networkd_network_gperf_gperf],
              ['fuzz-netdev-parser', 'directives.netdev',   networkd_netdev_gperf_gperf],
              ['fuzz-link-parser', 'directives.link',       udev_link_gperf_gperf],
             ]

foreach tuple : directives
        directive = custom_target(
                tuple[1],
                output: tuple[1],
                command: [generate_directives_py, tuple[2]],
                capture: true)

        dict = { 'directives' : [directive] }
        fuzz_regression_tests += { tuple[0] : dict }
endforeach

unit_directives = []
foreach section : ['Automount', 'Mount', 'Path', 'Scope', 'Service', 'Slice', 'Socket', 'Swap', 'Timer']
        unit_type = section.to_lower()
        sec_rx = section == 'Service' ? '(Service|Unit|Install)' : section
        name = 'directives.@0@'.format(unit_type)
        unit_directives += custom_target(
                name,
                output: name,
                command: [generate_directives_py, load_fragment_gperf_gperf, sec_rx, unit_type],
                capture: true)
endforeach
dict = { 'directives' : unit_directives }
fuzz_regression_tests += { 'fuzz-unit-file' : dict }

############################################################

# TODO: Use native string formatting with meson >= 1.3.0
if get_option('auto_features').enabled()
        sanitize_auto_features = 'enabled'
elif get_option('auto_features').disabled()
        sanitize_auto_features = 'disabled'
else
        sanitize_auto_features = 'auto'
endif

fuzz_c_args = get_option('c_args')
fuzz_cpp_args = cxx_cmd != '' ? get_option('cpp_args') : []

sanitize_address_undefined = custom_target(
        'sanitize-address-undefined-fuzzers',
        output : 'sanitize-address-undefined-fuzzers',
        command : [meson_build_sh,
                   project_source_root,
                   '@OUTPUT@',
                   'fuzzers',
                   ' '.join(fuzz_c_args + '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'),
                   ' '.join(fuzz_cpp_args + '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'),
                   '-Dfuzz-tests=true -Db_lundef=false -Db_sanitize=address,undefined --optimization=@0@ @1@ --auto-features=@2@'.format(
                           get_option('optimization'),
                           get_option('werror') ? '--werror' : '',
                           sanitize_auto_features
                   ),
                   ' '.join(cc.cmd_array()),
                   cxx_cmd])

fuzz_sanitizers = [['address,undefined', sanitize_address_undefined]]
fuzz_testsdir = 'test/fuzz'

if git.found() and fs.is_dir(project_source_root / '.git')
        out = run_command(env, '-u', 'GIT_WORK_TREE',
                          git, '--git-dir=@0@/.git'.format(project_source_root),
                          'ls-files', ':/@0@/*/*'.format(fuzz_testsdir),
                          check: true)
else
        out = run_command(sh, '-c', 'cd "@0@"; echo @1@/*/*'.format(project_source_root, fuzz_testsdir), check: true)
endif

# Add crafted fuzz inputs we have in the repo
foreach p : out.stdout().split()
        # Remove the last entry which is ''.
        #
        # Also, backslashes get mangled, so skip test. See
        # https://github.com/mesonbuild/meson/issues/1564.
        if p.contains('\\')
                continue
        endif
        fuzzer = fs.name(fs.parent(p))
        fuzz_in = fs.name(p)

        dict = fuzz_regression_tests.get(fuzzer, {})
        dict += { 'files' : dict.get('files', []) + files(fuzzer / fuzz_in) }
        fuzz_regression_tests += { fuzzer : dict }
endforeach
