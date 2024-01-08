---
title: Home Area Bulk Directories
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2024 GNOME Foundation Inc.
#     Original Author: Adrian Vovk
---

# Home Area Bulk Directories

The bulk directories are for storing binary or unstructured data that would
otherwise be stored in [JSON User Records](USER_RECORD.md). This generally
includes large unstructured text data, or binary files such as images.

See [`systemd-homed-sync-bulk.service(8)`](https://www.freedesktop.org/software/systemd/man/systemd-homed-sync-bulk.service.html)
for more details.

<!--- TODO: A rework of the docs above --->

## Known Files

`avatar` → An image file that should be used as the user's avatar picture.
The exact file type and resolution of this image are left unspecified,
and requirements will depend on the capabilities of the components that will
display it. However, we suggest the use of commonly-supported picture formats
(i.e. PNG or JPEG) and a resolution of 512 x 512. This image should not have any
transparency. If missing, of an incompatible file type, or otherwise unusable,
then the user does not have a profile picture and a default will be used instead.

`login-background` → An image file that will be used as the user's background on the
login screen (i.e. in GDM). The exact file type and resolution are left unspecified
and are ultimately up to the components that will render this background image.
We suggest that the image is blurred to protect the user's privacy and to improve
readability of GUI components rendered over top of it. This image should not have any
transparency. If missing, of an incompatible file type, or otherwise unusable, a fallback
background of some kind will be used.
