# SPDX-License-Identifier: LGPL-2.1+

sanitize_address = custom_target(
        'sanitize-address-fuzzers',
        output : 'sanitize-address-fuzzers',
        command : [meson_build_sh,
                   meson.source_root(),
                   '@OUTPUT@',
                   'fuzzers',
                   '-Db_lundef=false -Db_sanitize=address',
                   ' '.join(cc.cmd_array()),
                   ' '.join(meson.get_compiler('cpp').cmd_array())])

sanitizers = [['address', sanitize_address]]

if git.found()
        out = run_command(
                git,
                '--git-dir=@0@/.git'.format(meson.source_root()),
                 'ls-files', ':/test/fuzz/*/*')
else
        out = run_command(
                'sh', '-c', 'ls @0@/*/*'.format(meson.current_source_dir()))
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
