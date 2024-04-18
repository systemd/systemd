test_params += {
        'mkosi_args' : test_params['mkosi_args'] + [
                '--runtime-network=none',
                # We know that there won't be any devices so we can tell systemd
                # not to expect any to dynamically turn up.
                '--kernel-command-line-extra=' + ' '.join([
                        'rd.systemd.mask=systemd-networkd-wait-online.service',
                        'systemd.mask=systemd-networkd-wait-online.service',
                ]),
        ],
}
