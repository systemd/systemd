#!/usr/bin/env bash

set -eux
set -o pipefail

check_ok () {
    [ $# -eq 3 ] || return

    x="$(systemctl show --value -p "$2" "$1")"
    case "$x" in
        *$3*) return 0 ;;
        *)    return 1 ;;
    esac
}

test_template_onfailure_dep_removal() {
    echo "Testing template on failure dependency removal..."

    # A template service which will be set as a system wide service failure
    # handler via service type drop-ins. Note, we make this fail in order to
    # check that it does not get an OnFailure dependency of itself (and thus
    # avoids recursion).
    cat > /etc/systemd/system/failure-handler@.service <<EOF
[Unit]
Description=Failure handler for service "%I"

[Service]
Type=oneshot
ExecStart=/bin/false
EOF

    # Drop-in for all service units.
    mkdir /etc/systemd/system/service.d
    cat > /etc/systemd/system/service.d/10-all-services-on-failure.conf <<EOF
[Unit]
OnFailure=failure-handler@%N.service
EOF

    # Drop-in for all mount units.
    mkdir /etc/systemd/system/mount.d
    cat > /etc/systemd/system/mount.d/10-all-mounts-on-failure.conf <<EOF
[Unit]
OnFailure=failure-handler@%N.service
EOF

    # Specific drop-in for the failure-handler@.service, this unsets the
    # OnFailure dependencies added by 10-all-services-on-failure.conf
    mkdir /etc/systemd/system/failure-handler@.service.d
    cat > /etc/systemd/system/failure-handler@.service.d/99-failure-handler.conf <<EOF
[Unit]
OnFailure=
EOF

    # Also clear out OnFailure for testsuite.service itself since we don't
    # want failure-handler@.service running again if testsuite.service fails
    # for some reason.
    mkdir /etc/systemd/system/testsuite.service.d
    cat > /etc/systemd/system/testsuite.service.d/99-failure-handler.conf <<EOF
[Unit]
OnFailure=
EOF

    # A service which we'll set to fail so to trigger
    # failure-handler@failing-service.service, we want to ensure this service
    # does not lose it's OnFailure dependency that will be added in service.d/
    cat > /etc/systemd/system/failing-service.service <<EOF
[Unit]
Description=Test service which will fail

[Service]
Type=oneshot
ExecStart=/bin/false
EOF

    # Pick up the unit files.
    systemctl daemon-reload

    # Ensure the OnFailure dependency list for
    # failure-handler@failing-service.service is empty since we cleared it out
    # via a drop-in.
    check_ok failure-handler@failing-service.service OnFailure ""

    # Ensure all services except the failure handler service itself have
    # the correct OnFailure dependency set.
    check_ok failing-service.service OnFailure "failure-handler@failing-service.service"

    # Start the service and make sure the only
    # failure-handler@failing-service.service runs as a consequence of the
    # service failing.
    set +e
    systemctl start failing-service.service
    set -e

    # Check there are no recursive template units lingering (i.e. we didn't
    # create one as a result of starting
    # failure-handler@failing-service.service which failed).
    units=$(systemctl list-units --no-legend)
    if [[ "$units" == *"failure-handler@failure-handler"* ]]; then
        # We saw some recursive dependencies generated, fail the test.
        return 1
    fi

    # We only expect to see failing-service.service and
    # failure-handler@failing-service.service in the failed state, there
    # shouldn't be a failure-handler@failure-handler@failing-service.service.
    nr_failed_units="$(systemctl list-units --no-legend --no-pager | grep -c failed)"
    if [ "${nr_failed_units}" != "2" ]; then
            return 1
    fi

    return 0
}

test_basic_onfailure_dep_removal() {
    echo "Testing basic failure dependency removal..."

    # A service which will be called via OnFailure from a.service, as
    # part of the test we'll remove this dependency.
    cat > /etc/systemd/system/failure-handler-one.service <<EOF
[Unit]
Description=Failure handler one for test.service

[Service]
Type=oneshot
ExecStart=/bin/echo "failure handler one"
EOF

    # A service which will be called via OnFailure from a.service, as
    # part of the test we'll add this back as a dependency after the
    # failure-handler-one.service dependency has been removed.
    cat > /etc/systemd/system/failure-handler-two.service <<EOF
[Unit]
Description=Failure handler two for test.service

[Service]
Type=oneshot
ExecStart=/bin/echo "failure handler two"
EOF

    # A service which adds failure-handler-one.service as an OnFailure
    # dependency, we'll remove this via a drop-in.
    cat > /etc/systemd/system/a.service <<EOF
[Unit]
Description=A test service
OnFailure=failure-handler-one.service

[Service]
Type=oneshot
ExecStart=/bin/false
EOF

    # Drop-in to remove the above OnFailure dependency.
    mkdir /etc/systemd/system/a.service.d
    cat > /etc/systemd/system/a.service.d/10-remove-deps.conf <<EOF
[Unit]
OnFailure=
EOF

    # Drop-in to re-add a different OnFailure dependency.
    cat > /etc/systemd/system/a.service.d/20-re-add-deps.conf <<EOF
[Unit]
OnFailure=failure-handler-two.service
EOF

    # Pick up the unit files.
    systemctl daemon-reload

    # We should have added failure-handler-one.service as an OnFailure
    # dependency first, then removed it then added failure-handler-two.service
    # as an OnFailure dependency.
    check_ok a.service OnFailure "failure-handler-two.service"
}

test_basic_onfailure_dep_removal
test_template_onfailure_dep_removal

touch /testok
