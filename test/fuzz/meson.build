# SPDX-License-Identifier: LGPL-2.1-or-later

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

sanitizers = [['address,undefined', sanitize_address_undefined]]

if git.found() and fs.exists(project_source_root / '.git')
        out = run_command(env, '-u', 'GIT_WORK_TREE',
                          git, '--git-dir=@0@/.git'.format(project_source_root),
                          'ls-files', ':/test/fuzz/*/*',
                          check: true)
else
        out = run_command(sh, '-c', 'cd "@0@"; echo test/fuzz/*/*'.format(project_source_root), check: true)
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
