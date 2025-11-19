# Includes

An overview of all documentation files that are wholly or partially included in other doc files. Note that some of these are simply collections of includes, while others are legitimate documentation pages, which have some of their content re-used elsewhere. These are not consistently placed where you would expect them, and the old build system apparently doesn’t care whether they’re in `/includes` or not.

## XML files used for includes

Included, but does not exist:
```
bpf-delegate.xml
```

Import collections:
```
cgroup-sandboxing.xml
common-variables.xml
ethtool-link-mode.xml
libsystemd-pkgconfig.xml
standard-conf.xml
standard-options.xml
standard-specifiers.xml
supported-controllers.xml
system-only.xml
system-or-user-ns.xml
system-or-user-ns-mountfsd.xml
tc.xml
threads-aware.xml
unit-states.xml
user-system-options.xml
```

Re-used documentation pages:
```
hostname.xml
importctl.xml
org.freedesktop.locale1.xml
sd_bus_add_match.xml
sd_bus_message_append_basic.xml
sd_bus_message_read_basic.xml
sd_journal_get_data.xml
systemctl.xml
systemd-resolved.service.xml
systemd.link.xml
systemd.mount.xml
systemd.netdev.xml
systemd.service.xml
timedatectl.xml
vpick.xml
```

## Literal Includes

This means that these files are not parsed, but displayed in the documentation literally (in docbook, this was denoted via `parse="text"` in the include directive). Note that this includes an `xml`, this is purposely not converted to `.rst` by the conversion script.

```
yubikey-crypttab.sh
fido2-crypttab.sh
tpm2-crypttab.sh
logcontrol-example.c
check-os-release.sh
check-os-release-simple.py
check-os-release.py
vtable-example.c
vtable-example.xml
print-unit-path-call-method.c
sd_bus_error-example.c
print-unit-path.c
send-unit-files-changed.c
sd-bus-container-append.c
sd-bus-container-read.c
sd_bus_service_reconnect.c
event-quick-child.c
inotify-watch-tmp.c
glib-event-glue.c
hwdb-usb-device.c
id128-app-specific.c
journal-enumerate-fields.c
journal-iterate-wait.c
journal-iterate-poll.c
journal-iterate-foreach.c
journal-iterate-unique.c
journal-stream-fd.c
notify-selfcontained-example.c
notify-selfcontained-example.py
path-documents.c
50-xdg-data-dirs.sh
90-rearrange-path.py
uki.conf.example
```
