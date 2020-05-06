# This file is part of systemd.
#
# Used by systemd --user instances.

m4_ifdef(`ENABLE_HOMED',
-account sufficient pam_systemd_home.so
)m4_dnl
account sufficient pam_unix.so
account required pam_permit.so

m4_ifdef(`HAVE_SELINUX',
session required pam_selinux.so close
session required pam_selinux.so nottys open
)m4_dnl
session required pam_loginuid.so
session optional pam_keyinit.so force revoke
m4_ifdef(`ENABLE_HOMED',
-session optional pam_systemd_home.so
)m4_dnl
session optional pam_systemd.so
