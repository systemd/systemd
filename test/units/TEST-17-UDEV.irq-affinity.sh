#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Test IRQAffinityPolicy configuration

udevadm control --log-level=debug

# Find a network interface with MSI IRQs (typically virtio-net in the VM)
# We need a real device to test actual IRQ affinity application
find_interface_with_msi_irqs() {
    for iface in /sys/class/net/*; do
        [[ -e "$iface" ]] || continue
        iface_name=$(basename "$iface")
        [[ "$iface_name" == "lo" ]] && continue
        msi_irqs_path="$iface/device/msi_irqs"
        if [[ -d "$msi_irqs_path" ]] && [[ -n "$(ls -A "$msi_irqs_path" 2>/dev/null)" ]]; then
            echo "$iface_name"
            return 0
        fi
    done
    return 1
}

get_interface_irqs() {
    local iface="$1"
    local msi_irqs_path="/sys/class/net/$iface/device/msi_irqs"
    if [[ -d "$msi_irqs_path" ]]; then
        ls "$msi_irqs_path"
    fi
}

check_irq_affinity() {
    local irq="$1"
    local expected_mask="$2"
    local affinity
    affinity=$(cat "/proc/irq/$irq/smp_affinity")
    # Remove leading zeros and commas for comparison
    affinity=$(echo "$affinity" | sed 's/^[0,]*//;s/,//g')
    expected_mask=$(echo "$expected_mask" | sed 's/^[0,]*//;s/,//g')
    [[ "$affinity" == "$expected_mask" ]]
}

# Test 1: Verify IRQ affinity is actually applied on a real device
if iface=$(find_interface_with_msi_irqs); then
    echo "Found interface with MSI IRQs: $iface"

    # Get the MAC address of the interface
    mac=$(cat "/sys/class/net/$iface/address")

    # Get IRQs before applying policy
    irqs=$(get_interface_irqs "$iface")
    echo "Interface $iface has IRQs: $irqs"

    # Create a link file to apply IRQ affinity policy
    mkdir -p /run/systemd/network/
    cat > /run/systemd/network/00-test-irq-affinity.link <<EOF
[Match]
MACAddress=$mac

[Link]
IRQAffinityPolicy=single
EOF

    udevadm control --reload

    # Trigger udev to re-apply the link configuration
    udevadm trigger --action=add "/sys/class/net/$iface"
    udevadm settle --timeout=30

    # Verify the link file was applied
    output=$(udevadm info --query property "/sys/class/net/$iface")
    assert_in "ID_NET_LINK_FILE=/run/systemd/network/00-test-irq-affinity.link" "$output"

    # Verify IRQ affinity was actually set to CPU 0 (mask "1")
    for irq in $irqs; do
        if check_irq_affinity "$irq" "1"; then
            echo "IRQ $irq correctly pinned to CPU 0"
        else
            actual=$(cat "/proc/irq/$irq/smp_affinity")
            echo "IRQ $irq affinity is '$actual', expected '1' (CPU 0)"
            exit 1
        fi
    done

    # Cleanup
    rm -f /run/systemd/network/00-test-irq-affinity.link
    udevadm control --reload
else
    echo "No interface with MSI IRQs found, skipping actual IRQ affinity test"
fi

# Test 2: Config parsing with dummy interfaces (no MSI IRQs)
mkdir -p /run/systemd/network/
cat >/run/systemd/network/10-test-irq.link <<EOF
[Match]
Kind=dummy
MACAddress=00:50:56:c0:00:20

[Link]
Name=testirq0
IRQAffinityPolicy=single
EOF

udevadm control --reload

# Create a dummy interface
ip link add address 00:50:56:c0:00:20 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/testirq0

# Check that the link file was applied
output=$(udevadm info --query property /sys/class/net/testirq0)
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test-irq.link" "$output"
assert_in "ID_NET_NAME=testirq0" "$output"

# Test that udevadm test-builtin parses the config correctly
output=$(udevadm test-builtin --action add net_setup_link /sys/class/net/testirq0 2>&1)
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test-irq.link" "$output"

# Test 3: Invalid policy values are rejected/warned
cat >/run/systemd/network/10-test-irq-invalid.link <<EOF
[Match]
Kind=dummy
MACAddress=00:50:56:c0:00:21

[Link]
Name=testirq1
IRQAffinityPolicy=invalid_policy
EOF

udevadm control --reload

# Create another dummy interface - invalid policy should be ignored
ip link add address 00:50:56:c0:00:21 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/testirq1

# Check that the link file was still applied (invalid policy is just ignored/warned)
output=$(udevadm info --query property /sys/class/net/testirq1)
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test-irq-invalid.link" "$output"

# Test 4: Empty policy (reset/disable)
cat >/run/systemd/network/10-test-irq-empty.link <<EOF
[Match]
Kind=dummy
MACAddress=00:50:56:c0:00:22

[Link]
Name=testirq2
IRQAffinityPolicy=
EOF

udevadm control --reload

ip link add address 00:50:56:c0:00:22 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/testirq2

output=$(udevadm info --query property /sys/class/net/testirq2)
assert_in "ID_NET_LINK_FILE=/run/systemd/network/10-test-irq-empty.link" "$output"

# Cleanup
ip link del dev testirq0
ip link del dev testirq1
ip link del dev testirq2

rm -f /run/systemd/network/10-test-irq.link
rm -f /run/systemd/network/10-test-irq-invalid.link
rm -f /run/systemd/network/10-test-irq-empty.link
udevadm control --reload --log-level=info

exit 0
