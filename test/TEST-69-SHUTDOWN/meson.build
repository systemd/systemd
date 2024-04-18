test_params += {
        'mkosi_args' : [
                '--kernel-command-line-extra',
                'systemd.mount-extra=/usr/share/testsuite-69-shutdown.raw:/run/extensions/testsuite-69-shutdown.raw::bind',
        ],
        'hook_module' : meson.current_source_dir() / 'hook.py',
        'skip_shutdown' : true,
}
