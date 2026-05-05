# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-network-ovs-generator',
                'sources' : files('systemd-network-ovs-generator.c'),
                'conditions' : ['ENABLE_OPENVSWITCH'],
        },
]
