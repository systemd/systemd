#!/bin/sh

if which dbus-update-activation-environment >/dev/null 2>&1; then
        dbus-update-activation-environment DISPLAY XAUTHORITY
fi

systemctl --user import-environment DISPLAY XAUTHORITY
