#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! can_do_rootless_nspawn; then
    echo "Skipping unpriv nspawn test"
    exit 0
fi

# We need FSCONFIG_SET_FD support in overlayfs for .mstack to work. Let's skip
# this test on old kernels, that didn't have that yet. Ideally we'd check for
# the feature itself here, but I couldn't figure out a nice way to detect
# support for this from shell, hence let's do a version check instead.
if systemd-analyze condition 'ConditionVersion= < 6.13' ; then
    echo "Kernel too old for FSCONFIG_SET_FD support on overlayfs, skipping pull-oci test".
    exit 0
fi

export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal

at_exit() {
    rm -rf /var/tmp/pull-oci-test
    rm -rf /home/testuser/.local/state/machines/ocibasic
    rm -rf /home/testuser/.local/state/machines/ocilayer
}

trap at_exit EXIT

# Install a PK rule that allows 'testuser' user to register a machine even
# though they are not on an fg console, just for testing
mkdir -p /etc/polkit-1/rules.d
cat >/etc/polkit-1/rules.d/registermachinetest.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.machine1.register-machine" &&
        subject.user == "testuser") {
        return polkit.Result.YES;
    }
});
EOF

run0 -u testuser mkdir -p .local/state/machines

create_dummy_container /home/testuser/.local/state/machines/ocibasic
cat >/home/testuser/.local/state/machines/ocibasic/sbin/init <<EOF
#!/usr/bin/env bash
cat /etc/waldo
EOF
chmod +x /home/testuser/.local/state/machines/ocibasic/sbin/init
systemd-dissect --shift /home/testuser/.local/state/machines/ocibasic foreign

run0 -u testuser mkdir -p .local/state/machines/ocilayer/etc

cat >home/testuser/.local/state/machines/ocilayer/etc/waldo <<EOF
luftikus
EOF
systemd-dissect --shift /home/testuser/.local/state/machines/ocilayer foreign

loginctl enable-linger testuser

mkdir -p /var/tmp/pull-oci-test

run0 --pipe -u testuser importctl -m --user export-tar --format=gzip ocibasic - >/var/tmp/pull-oci-test/ocibasic.tar.gz
run0 --pipe -u testuser importctl -m --user export-tar --format=gzip ocilayer - >/var/tmp/pull-oci-test/ocilayer.tar.gz

OCIBASIC_SHA256="$(sha256sum /var/tmp/pull-oci-test/ocibasic.tar.gz | cut -d' ' -f1)"
OCIBASIC_SIZE="$(stat -c %s /var/tmp/pull-oci-test/ocibasic.tar.gz)"
OCILAYER_SHA256="$(sha256sum /var/tmp/pull-oci-test/ocilayer.tar.gz | cut -d' ' -f1)"
OCILAYER_SIZE="$(stat -c %s /var/tmp/pull-oci-test/ocilayer.tar.gz)"

# Let's now put together a simple, fake, static OCI registry that sits on
# file:// rather than https://, so that we don't have to spawn an HTTP
# server. After all we don't want to test the server side code, but only the
# client side code, and libcurl nicely abstracts https:// or ftp:// from us.

mkdir -p /var/tmp/pull-oci-test/v2/ocicombo/manifests
cat >/var/tmp/pull-oci-test/v2/ocicombo/manifests/latest <<EOF
{
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "layers":[
                {
                        "mediaType" : "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest" : "sha256:$OCIBASIC_SHA256",
                        "size" : $OCIBASIC_SIZE
                },
                {
                        "mediaType" : "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest" : "sha256:$OCILAYER_SHA256",
                        "size" : $OCILAYER_SIZE
                }
        ]
}
EOF

cat /var/tmp/pull-oci-test/v2/ocicombo/manifests/latest
jq < /var/tmp/pull-oci-test/v2/ocicombo/manifests/latest

cat > /usr/lib/systemd/oci-registry/registry.localfile.oci-registry <<EOF
{
        "defaultProtocol" : "file",
        "overrideRegistry" : "/var/tmp/pull-oci-test"
}
EOF

cat /usr/lib/systemd/oci-registry/registry.localfile.oci-registry
jq < /usr/lib/systemd/oci-registry/registry.localfile.oci-registry

mkdir /var/tmp/pull-oci-test/v2/ocicombo/blobs
ln -s /var/tmp/pull-oci-test/ocibasic.tar.gz /var/tmp/pull-oci-test/v2/ocicombo/blobs/sha256:"$OCIBASIC_SHA256"
ln -s /var/tmp/pull-oci-test/ocilayer.tar.gz /var/tmp/pull-oci-test/v2/ocicombo/blobs/sha256:"$OCILAYER_SHA256"

run0 -u testuser importctl -m --user pull-oci localfile/ocicombo:latest

ls -alR /home/testuser/.local/state/machines/ocicombo.mstack

run0 -u testuser systemd-mstack /home/testuser/.local/state/machines/ocicombo.mstack
systemd-mstack -M --read-only /home/testuser/.local/state/machines/ocicombo.mstack /tmp/ooo
test "$(cat /tmp/ooo/etc/waldo)" = "luftikus"
systemd-mstack -U /tmp/ooo

ls -alR /home/testuser/.local/state/machines/ocicombo.mstack

run0 -u testuser importctl list-images --user | grep -q ocicombo

ls -alR /home/testuser/.local/state/machines/ocicombo.mstack

run0 -u testuser systemd-nspawn -q --pipe -M ocicombo /sbin/init | grep -q luftikus

run0 -u testuser --pipe systemd-run -q --unit=fimpel --user -p PrivateUsers=managed -p RootMStack=/home/testuser/.local/state/machines/ocicombo.mstack --pipe /sbin/init | grep -q luftikus

run0 -u testuser machinectl list-images -a --user

run0 -u testuser machinectl --user remove ocibasic
run0 -u testuser machinectl --user remove ocilayer
run0 -u testuser machinectl --user remove ocicombo
run0 -u testuser machinectl --user remove .oci-sha256:"$OCIBASIC_SHA256"
run0 -u testuser machinectl --user remove .oci-sha256:"$OCILAYER_SHA256"

loginctl disable-linger testuser
