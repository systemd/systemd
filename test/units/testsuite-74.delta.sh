#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    rm -rfv /{run,etc}/systemd/system/delta-test*
}

trap at_exit EXIT

# Create a couple of supporting units with overrides
#
# Extended unit
cat >"/run/systemd/system/delta-test-unit-extended.service" <<EOF
[Service]
ExecStart=/bin/true
EOF
mkdir -p "/run/systemd/system/delta-test-unit-extended.service.d"
cat >"/run/systemd/system/delta-test-unit-extended.service.d/override.conf" <<EOF
[Unit]
Description=Foo Bar
[Service]
ExecStartPre=/bin/true
EOF
# Masked unit
cp -fv /run/systemd/system/delta-test-unit-extended.service /run/systemd/system/delta-test-unit-masked.service
systemctl mask delta-test-unit-masked.service
# Overridden unit
cp -fv /run/systemd/system/delta-test-unit-extended.service /run/systemd/system/delta-test-unit-overridden.service
cp -fv /run/systemd/system/delta-test-unit-overridden.service /etc/systemd/system/delta-test-unit-overridden.service
echo "ExecStartPost=/bin/true" >>/etc/systemd/system/delta-test-unit-overridden.service
# Overridden but equivalent unit
ln -srfv /run/systemd/system/delta-test-unit-extended.service /run/systemd/system/delta-test-unit-equivalent.service
ln -sfv /run/systemd/system/delta-test-unit-extended.service /etc/systemd/system/delta-test-unit-equivalent.service
# Redirected unit
ln -srfv /run/systemd/system/delta-test-unit-extended.service /run/systemd/system/delta-test-unit-redirected.service
ln -sfv /run/systemd/system/delta-test-unit-overidden.service /etc/systemd/system/delta-test-unit-extended.service

systemctl daemon-reload

systemd-delta
systemd-delta /run
systemd-delta systemd/system
systemd-delta /run systemd/system /run
systemd-delta /run foo/bar hello/world systemd/system /run
systemd-delta foo/bar
systemd-delta --diff=true
systemd-delta --diff=false

for type in masked equivalent redirected overridden extended unchanged; do
    systemd-delta --type="$type"
    systemd-delta --type="$type" /run
done
systemd-delta --type=equivalent,redirected

(! systemd-delta --diff=foo)
(! systemd-delta --type=foo)
(! systemd-delta --type=equivalent,redirected,foo)
