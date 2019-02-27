# SPDX-License-Identifier: LGPL-2.1+

sanitize_address = custom_target(
        'sanitize-address-fuzzers',
        output : 'sanitize-address-fuzzers',
        command : [meson_build_sh,
                   project_source_root,
                   '@OUTPUT@',
                   'fuzzers',
                   '-Db_lundef=false -Db_sanitize=address',
                   ' '.join(cc.cmd_array()),
                   cxx_cmd])

sanitizers = [['address', sanitize_address]]

if git.found()
        out = run_command(
                git,
                '--git-dir=@0@/.git'.format(project_source_root),
                 'ls-files', ':/test/fuzz/*/*')
else
        out = run_command(
                'sh', '-c', 'ls @0@/test/fuzz/*/*'.format(project_source_root))
endif

fuzz_regression_tests = []
foreach p : out.stdout().split()
        # Remove the last entry which is ''.
        #
        # Also, backslashes get mangled, so skip test. See
        # https://github.com/mesonbuild/meson/issues/1564.
        if not p.contains('\\')
                fuzz_regression_tests += p
        endif
endforeach
