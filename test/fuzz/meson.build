# SPDX-License-Identifier: LGPL-2.1-or-later

generate_directives_py = find_program('generate-directives.py')
fuzz_generated_in_dir = meson.current_build_dir()

fuzz_generated_directives = []

directives = [['fuzz-network-parser_directives',        'src/network/networkd-network-gperf.gperf'],
              ['fuzz-netdev-parser_directives.netdev',  'src/network/netdev/netdev-gperf.gperf'],
              ['fuzz-link-parser_directives.link',      'src/udev/net/link-config-gperf.gperf'],
             ]

foreach tuple : directives
        fuzz_generated_directives += custom_target(
                tuple[0],
                output: tuple[0],
                command: [generate_directives_py, files(project_source_root / tuple[1])],
                capture: true)
endforeach

foreach section : ['Automount', 'Mount', 'Path', 'Scope', 'Service', 'Slice', 'Socket', 'Swap', 'Timer']
        unit_type = section.to_lower()
        sec_rx = section == 'Service' ? '(Service|Unit|Install)' : section
        fuzz_generated_directives += custom_target(
                'fuzz-unit-file_directives.@0@'.format(unit_type),
                output: 'fuzz-unit-file_directives.@0@'.format(unit_type),
                command: [generate_directives_py, load_fragment_gperf_gperf, sec_rx, unit_type],
                capture: true)
endforeach


############################################################

sanitize_address_undefined = custom_target(
        'sanitize-address-undefined-fuzzers',
        output : 'sanitize-address-undefined-fuzzers',
        command : [meson_build_sh,
                   project_source_root,
                   '@OUTPUT@',
                   'fuzzers',
                   '-Dfuzz-tests=true -Db_lundef=false -Db_sanitize=address,undefined --optimization=@0@ @1@ -Dc_args=@2@ -Dcpp_args=@2@ -Dskip-deps=@3@'.format(
                           get_option('optimization'),
                           get_option('werror') ? '--werror' : '',
                           '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
                           get_option('skip-deps')
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

# Fuzz inputs that we generate (see above fuzz_generated_directives)
fuzz_regression_tests = {
        'fuzz-link-parser':    [['', 'directives.link']],
        'fuzz-netdev-parser':  [['', 'directives.netdev']],
        'fuzz-network-parser': [['', 'directives']],
        'fuzz-unit-file':      [['', 'directives.automount'],
                                ['', 'directives.mount'],
                                ['', 'directives.path'],
                                ['', 'directives.scope'],
                                ['', 'directives.service'],
                                ['', 'directives.slice'],
                                ['', 'directives.socket'],
                                ['', 'directives.swap'],
                                ['', 'directives.timer']]}

# Add crafted fuzz inputs we have in the repo
foreach p : out.stdout().split()
        # Remove the last entry which is ''.
        #
        # Also, backslashes get mangled, so skip test. See
        # https://github.com/mesonbuild/meson/issues/1564.
        if p.contains('\\')
                continue
        endif
        fuzzer = p.split('/')[-2]
        fuzz_in = p.split('/')[-1]
        if fuzzer not in fuzz_regression_tests
                fuzz_regression_tests += {fuzzer: []}
        endif
        # Meson parser provision for: fuzz_regression_tests[fuzzer] += [fuzz_in]
        l = fuzz_regression_tests[fuzzer]
        l += [[fuzz_testsdir, fuzz_in]]
        fuzz_regression_tests += {fuzzer: l}
endforeach
