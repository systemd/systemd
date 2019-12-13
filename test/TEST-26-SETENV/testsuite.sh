#!/bin/bash
set -ex
set -o pipefail

# Make sure PATH is set
systemctl show-environment | grep -q '^PATH='

# Let's add an entry and override a built-in one
systemctl set-environment PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/testaddition FOO=BAR

# Check that both are set
systemctl show-environment | grep -q '^PATH=.*testaddition$'
systemctl show-environment | grep -q '^FOO=BAR$'

systemctl daemon-reload

# Check again after the reload
systemctl show-environment | grep -q '^PATH=.*testaddition$'
systemctl show-environment | grep -q '^FOO=BAR$'

# Drop both
systemctl unset-environment FOO PATH

# Check that one is gone and the other reverted to the built-in
! (systemctl show-environment | grep -q '^FOO=$')
! (systemctl show-environment | grep -q '^PATH=.*testaddition$')
systemctl show-environment | grep -q '^PATH='

echo OK > /testok

exit 0
