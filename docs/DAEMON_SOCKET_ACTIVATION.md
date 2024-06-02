---
title: Socket Activation with Popular Daemons
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

## nginx

nginx includes an undocumented, internal socket-passing mechanism based on the `NGINX` environmental variable.
It uses this to perform reloads without having to close and reopen its sockets, but it's also useful for socket activation.

**/etc/nginx/my-nginx.conf**

```
http {
  server {
    listen [::]:80 ipv6only=on;
    listen 80;
  }
}
```

**/etc/systemd/system/my-nginx.service**

```
[Service]
User=nginx
Group=nginx
Environment=NGINX=3:4;
ExecStart=/usr/sbin/nginx -c/etc/nginx/my-nginx.conf
PrivateNetwork=true
```

**/etc/systemd/system/my-nginx.socket**

```
[Socket]
ListenStream=80
ListenStream=0.0.0.0:80
BindIPv6Only=ipv6-only

[Install]
WantedBy=sockets.target
```

## PHP-FPM

Like nginx, PHP-FPM includes a socket-passing mechanism an environmental variable.
In PHP-FPM's case, it's `FPM_SOCKETS`.

This configuration is possible with any web server that supports FastCGI (like Apache, Lighttpd, or nginx).
The web server does not need to know anything special about the socket; use a normal PHP-FPM configuration.

Paths are based on a Fedora 19 system.

### First, the configuration files

**/etc/php-fpm.d/my-php-fpm-pool.conf**

```
[global]
pid = /run/my-php-fpm-pool.pid ; Not really used by anything with daemonize = no, but needs to be writable.
error_log = syslog             ; Will aggregate to the service's systemd journal.
daemonize = no                 ; systemd handles the forking.

[www]
listen = /var/run/my-php-fpm-pool.socket  ; Must match systemd socket unit.
user = nginx ; Ignored but required.
group = nginx ; Ignored but required.
pm = static
pm.max_children = 10
slowlog = syslog
```

**/etc/systemd/system/my-php-fpm-pool.service**

```
[Service]
User=nginx
Group=nginx
Environment="FPM_SOCKETS=/var/run/my-php-fpm-pool.socket=3"
ExecStart=/usr/sbin/php-fpm --fpm-config=/etc/php-fpm.d/my-php-fpm-pool.conf
KillMode=process
```

**/etc/systemd/system/my-php-fpm-pool.socket**

```
[Socket]
ListenStream=/var/run/my-php-fpm-pool.socket

[Install]
WantedBy=sockets.target
```

### Second, the setup commands

```sh
sudo systemctl --system daemon-reload
sudo systemctl start my-php-fpm-pool.socket
sudo systemctl enable my-php-fpm-pool.socket
```

After accessing the web server, the service should be running.

```sh
sudo systemctl status my-php-fpm-pool.service
```

It's possible to shut down the service and re-activate it using the web browser, too.
It's necessary to stop and start the socket to reset some shutdown PHP-FPM does that otherwise breaks reactivation.

```sh
sudo systemctl stop my-php-fpm-pool.socket my-php-fpm-pool.service
sudo systemctl start my-php-fpm-pool.socket
```
