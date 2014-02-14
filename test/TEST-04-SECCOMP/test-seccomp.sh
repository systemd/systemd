#!/bin/bash -x

systemctl start will-fail.service
systemctl start will-fail2.service
systemctl start will-not-fail.service
systemctl start will-not-fail2.service
systemctl is-failed will-fail.service || exit 1
systemctl is-failed will-fail2.service || exit 1
systemctl is-failed will-not-fail.service && exit 1
systemctl is-failed will-not-fail2.service && exit 1

touch /testok
exit 0
