Setting up the agetty service in OpenRC
=================================xxxxxx

The agetty service is an OpenRC specific way to monitor and respawn a
getty, using agetty, on Linux. To use this method, make sure you aren't
spawning a getty manager for this port some other way (such as through
sysvinit/inittab), then run the following commands as root.

Note that [port] refers to the port you are spawning the getty on, for
example, tty1 or ttyS0. The full path to it, for example, /dev/tty1
should not be used.

```
# cd /etc/init.d
# ln -s agetty agetty.[port]
# cd /etc/conf.d
# cp agetty agetty.[port]
#rc-update add agetty.[port] [runlevel]
```
