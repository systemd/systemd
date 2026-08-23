/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression r;
@@
- (r < 0 && ERRNO_IS_TRANSIENT(r))
+ ERRNO_IS_NEG_TRANSIENT(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_DISCONNECT(r))
+ ERRNO_IS_NEG_DISCONNECT(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_ACCEPT_AGAIN(r))
+ ERRNO_IS_NEG_ACCEPT_AGAIN(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_RESOURCE(r))
+ ERRNO_IS_NEG_RESOURCE(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_NOT_SUPPORTED(r))
+ ERRNO_IS_NEG_NOT_SUPPORTED(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_PRIVILEGE(r))
+ ERRNO_IS_NEG_PRIVILEGE(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_DISK_SPACE(r))
+ ERRNO_IS_NEG_DISK_SPACE(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_DEVICE_ABSENT(r))
+ ERRNO_IS_NEG_DEVICE_ABSENT(r)
@@
expression r;
@@
- (r < 0 && ERRNO_IS_XATTR_ABSENT(r))
+ ERRNO_IS_NEG_XATTR_ABSENT(r)
