# SPDX-License-Identifier: LGPL-2.1-or-later

generate_directives_py = files('generate-directives.py')

fuzz_regression_tests = {}

directives = [['fuzz-network-parser', 'directives.network', networkd_network_gperf_gperf],
              ['fuzz-netdev-parser', 'directives.netdev',   networkd_netdev_gperf_gperf],
              ['fuzz-link-parser', 'directives.link',       udev_link_gperf_gperf],
             ]

foreach tuple : directives
        directive = custom_target(
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
        name = f'directives.@unit_type@'
        unit_directives += custom_target(
                output: name,
                command: [generate_directives_py, load_fragment_gperf_gperf, sec_rx, unit_type],
                capture: true)
endforeach
dict = { 'directives' : unit_directives }
fuzz_regression_tests += { 'fuzz-unit-file' : dict }

############################################################

fuzz_testsdir = 'test/fuzz'

if git.found() and fs.is_dir(meson.project_source_root() / '.git')
        out = run_command(env, '-u', 'GIT_WORK_TREE',
                          git, '--git-dir=@0@/.git'.format(meson.project_source_root()),
                          'ls-files', ':/@0@/*/*'.format(fuzz_testsdir),
                          check: true)
else
        out = run_command(sh, '-c', 'cd "@0@"; printf "%s " @1@/*/*'.format(meson.project_source_root(), fuzz_testsdir), check: true)
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
