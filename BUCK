# SPDX-License-Identifier: LGPL-2.1-or-later

load("@tine//box:defs.bzl", "box")
load("@tine//distribution:defs.bzl", "distribution")
load("@tine//image:defs.bzl", "image")
load("@tine//package:defs.bzl", "package")
load("@tine//package_system/rpm:defs.bzl", "rpm")
load("@tine//platform:architecture.bzl", "architecture")
load("@tine//project:defs.bzl", "project")
load("@tine//tests:defs.bzl", "tests")
load("//tools/tine:defs.bzl", "packages")
load("//tools/tine:packages.bzl", "BOX", "IMAGE", "INITRD", "MINIMAL_BASE")

box.new(
    name = "systemd.box",
    packages = packages(BOX) + distribution.select({
        "DEFAULT": [],
        "debian": architecture.select({
            "arm64": ["linux-image-arm64", "qemu-system-arm"],
            "x86_64": ["linux-image-amd64", "qemu-system-x86"],
        }),
    }),
    release = distribution.release_target("release"),
)

command_alias(
    name = "box",
    exe = ":systemd.box",
)

project.source_tree(name = "source")

_PACKAGE_BUILDS = {"fedora": ":systemd.rpm"}

rpm.package(
    name = "systemd.rpm",
    package = "systemd",
    buildroot = "catalog//:fedora.rawhide.buildroot",
    source_tree = ":source",
    in_place_packaging = "tools/packaging.json",
    in_place_packaging_distro = "fedora",
    in_place_rpmbuild_options = [
        "--with=upstream",
        "--without=lto",
        "--define=_fortify_level 0",
        "--define=_distro_extra_cflags -O0 -g -Wp,-U_FORTIFY_SOURCE",
        "--define=meson_extra_configure_options -Dmode=developer -Dtime-epoch=1744207869 -Dvarlink-sftp=true",
        "--define=debug_package %{nil}",
        "--define=version_override %(cat meson.version)",
    ],
    build_requires = [
        "bindgen-cli",
        "rust",
    ],
    dev = True,
    release = "1",
    source_date_epoch = 1744207869,
    subpackages = [
        "systemd",
        "systemd-boot-unsigned",
        "systemd-container",
        "systemd-devel",
        "systemd-imds",
        "systemd-import-keys",
        "systemd-journal-remote",
        "systemd-libs",
        "systemd-networkd",
        "systemd-networkd-defaults",
        "systemd-oomd-defaults",
        "systemd-pam",
        "systemd-resolved",
        "systemd-rpm-macros",
        "systemd-shared",
        "systemd-standalone-repart",
        "systemd-standalone-report",
        "systemd-standalone-shutdown",
        "systemd-standalone-sysusers",
        "systemd-standalone-tmpfiles",
        "systemd-sysusers",
        "systemd-tests",
        "systemd-tools",
        "systemd-udev",
        "systemd-ukify",
    ],
)

package.local_repository(
    name = "systemd.repository",
    packages = distribution.select({family: [target] for family, target in _PACKAGE_BUILDS.items()}),
    visibility = ["PUBLIC"],
)

package.manager(
    name = "fedora.package-manager",
    base = "catalog//:fedora.rawhide.package-manager",
    additional_repositories = [":systemd.repository"],
)

image.generate_signing_key(name = "signing")

export_file(
    name = "minimal-base.postinst",
    src = "mkosi/mkosi.images/minimal-base/mkosi.postinst",
)

image.layer(
    name = "minimal-base",
    packages = packages(MINIMAL_BASE),
    install_docs = False,
    install_langs = ["C.UTF-8"],
    ops = [
        image.ops.copy("mkosi/mkosi.images/minimal-base/mkosi.extra", "/"),
        image.ops.run(
            [
                "env",
                "BUILDDIR=" + distribution.select({family: "$(location {}[build])".format(target) for family, target in _PACKAGE_BUILDS.items()}),
                "bash",
                "$(location :minimal-base.postinst)",
            ],
            env = {"BUILDROOT": "/buildroot"},
        ),
    ],
)

image.archive(
    name = "minimal-base.tar",
    parent = ":minimal-base",
    format = "tar",
)

[
    [
        export_file(
            name = "minimal-{}.postinst".format(index),
            src = "mkosi/mkosi.images/minimal-{}/mkosi.postinst".format(index),
        ),
        image.disk(
            name = "minimal-{}".format(index),
            parent = ":minimal-base",
            definitions = [
                image.partition(
                    type = "root",
                    filesystem = "squashfs",
                    copy_files = ["/"],
                    minimize = "best",
                    verity = "data",
                    verity_match_key = "root",
                ),
                image.partition(
                    type = "root-verity",
                    minimize = "best",
                    verity = "hash",
                    verity_match_key = "root",
                ),
                image.partition(
                    type = "root-verity-sig",
                    verity = "signature",
                    verity_match_key = "root",
                ),
            ],
            ops = [
                image.ops.copy("mkosi/mkosi.images/minimal-{}/mkosi.extra".format(index), "/"),
                image.ops.run(
                    ["sh", "$(location :minimal-{}.postinst)".format(index)],
                    env = {"BUILDROOT": "/buildroot"},
                ),
            ],
            verity_key = ":signing",
        ),
    ]
    for index in (0, 1)
]

# The VOA hierarchy has a directory for each os-release ID. The ID of Arch, Debian, and Fedora is the name
# of the distribution family.
_VOA_DIR = "/usr/share/voa/" + distribution.select({"arch": "arch", "debian": "debian", "fedora": "fedora"})

# The kernel keyring setup tests read the signing certificate and a test CA from the VOA hierarchy.
_VOA_OPS = [
    image.ops.copy(":signing[cert]", _VOA_DIR + "/kernel-keyring/dm-verity/x509/mkosi-certificate.pem"),
    image.ops.copy(":signing[cert]", _VOA_DIR + "/kernel-keyring/fs-verity/x509/mkosi-certificate.pem"),
    image.ops.copy(
        "mkosi/keyring-setup-test-ca.crt",
        _VOA_DIR + "/trust-anchor-kernel-keyring/dm-verity/x509/ca-certificate.pem",
    ),
]

image.initrd(
    name = "initrd",
    packages = packages(INITRD),
    ops = [
        image.ops.copy("mkosi/mkosi.extra.common", "/"),
        image.ops.copy("mkosi/mkosi.initrd.conf/mkosi.extra", "/"),
        image.ops.copy(":signing[cert]", "/usr/lib/verity.d/mkosi.crt"),
    ] + _VOA_OPS,
)

export_file(
    name = "postinst.chroot",
    src = "mkosi/mkosi.postinst.chroot",
)

image.disk(
    name = "image",
    initrd = ":initrd",
    definitions = [
        image.partition(
            type = "esp",
            filesystem = "vfat",
            copy_files = [
                "/boot:/",
                "/efi:/",
            ],
            size_min = "1G",
            size_max = "1G",
        ),
        image.partition(
            type = "linux-generic",
            filesystem = "ext4",
            size_min = "498M",
            size_max = "498M",
        ),
        image.partition(
            type = "root",
            filesystem = "ext4",
            copy_files = ["/"],
            size_min = "8G",
            size_max = "8G",
        ),
    ],
    packages = packages(IMAGE),
    ops = [
        image.ops.copy("mkosi/mkosi.extra.common", "/"),
        image.ops.copy("mkosi/mkosi.extra", "/"),
        image.ops.copy(":signing[cert]", "/usr/lib/verity.d/mkosi.crt"),
        [
            [
                image.ops.copy(":minimal-{}[partitions][root]".format(index), "/usr/share/minimal_{}.raw".format(index)),
                image.ops.copy(":minimal-{}[partitions][root-verity]".format(index), "/usr/share/minimal_{}.verity".format(index)),
                image.ops.copy(":minimal-{}[partitions][root-verity-sig]".format(index), "/usr/share/minimal_{}.verity.sig".format(index)),
            ]
            for index in (0, 1)
        ],
        image.ops.mkdir("/usr/share/TEST-13-NSPAWN-container-template"),
        image.ops.run([
            "tar",
            "--extract",
            "--numeric-owner",
            "--file=$(location :minimal-base.tar)",
            "--directory=/buildroot/usr/share/TEST-13-NSPAWN-container-template",
        ]),
        # mkosi.postinst.chroot copies packages from BUILDDIR and writes keydev.raw to OUTPUTDIR. The rpm and
        # keydev.raw are separate targets in this file. BUILDDIR is therefore an empty directory, and the
        # remove op below deletes the keydev.raw that the script writes to OUTPUTDIR.
        image.ops.run(
            [
                "env",
                "BUILDDIR=/var/empty",
                "BUILDROOT=/",
                "OUTPUTDIR=/var/tmp",
                "bash",
                "$(location :postinst.chroot)",
            ],
            chroot = True,
        ),
        image.ops.remove("/var/tmp/keydev.raw"),
        # mkosi.finalize marks /etc and /var as up to date, so units with ConditionNeedsUpdate= don't run on
        # the first boot.
        image.ops.write_file("/etc/.updated"),
        image.ops.write_file("/var/.updated"),
        image.ops.mkdir("/boot/loader/addons"),
        image.ops.run([
            "ukify",
            "build",
            "--stub=/buildroot/usr/lib/systemd/boot/efi/addonx64.efi.stub",
            "--cmdline=addonfoobar",
            "--signtool=systemd-sbsign",
            "--output=/buildroot/boot/loader/addons/test.addon.efi",
            "--secureboot-certificate=$(location :signing[cert])",
            "--secureboot-private-key=$(location :signing[key])",
        ]),
        image.ops.copy(":signing[cert]", "/usr/share/mkosi.crt"),
        image.ops.copy(":signing[key]", "/usr/share/mkosi.key"),
        _VOA_OPS,
        image.ops.preset(),
    ],
    cmdline = [
        "systemd.crash_shell",
        "systemd.log_level=debug,console:info",
        "systemd.log_ratelimit_kmsg=0",
        "printk.devkmsg=on",
        "rw",
        "selinux=0",
        "systemd.early_core_pattern=/core",
        "systemd.firstboot=no",
        "raid=noautodetect",
        "oops=panic",
        "panic=-1",
        "softlockup_panic=1",
        "panic_on_warn=1",
        "psi=1",
        "mitigations=off",
    ],
    secure_boot_key = ":signing",
    sign_expected_pcr_key = ":signing",
)

image.disk(
    name = "keydev",
    definitions = [
        image.partition(
            type = "linux-generic",
            label = "varcrypt_keydev",
            filesystem = "ext4",
            copy_files = ["/keyfile:/keyfile"],
            size_min = "16M",
        ),
    ],
    ops = [image.ops.copy("mkosi/mkosi.credentials/keyfile", "/keyfile")],
)

export_file(
    name = "credentials",
    src = "mkosi/mkosi.credentials",
)

image.vm(
    name = "vm",
    image = ":image",
    autologin = "root",
    credentials = {"journal.storage": "persistent"},
    ram = "4G",
    secure_boot = True,
    tpm = True,
    vmspawn_args = [
        "--load-credential=keyfile:$(location :credentials)/keyfile",
        "--load-credential=userdb.user.testuser:$(location :credentials)/userdb.user.testuser",
        "--load-credential=userdb.group.testuser:$(location :credentials)/userdb.group.testuser",
    ],
)

tests.vm_smoke(
    name = "vm-smoke",
    vm = ":vm",
    checks = [
        "systemctl --version | grep -F 263~devel",
        "userdbctl user testuser",
        "test -x /usr/share/TEST-13-NSPAWN-container-template/usr/bin/bash",
        "test -f /usr/share/minimal_0.roothash.p7s",
        "test -f /boot/loader/addons/test.addon.efi",
    ],
)
