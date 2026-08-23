---
title: Appstream Bundle
category: Interfaces
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Appstream Bundle

NOTE: This document is a work-in-progress.

NOTE: This isn't yet implemented in libappstream and the software centers.

[Appstream catalogs](https://www.freedesktop.org/software/appstream/docs/chap-CatalogData.html)
are a standardized way to expose metadata about system components, apps, and updates to software
centers (i.e. GNOME Software and KDE Discover). The `<bundle/>` tag links an appstream component
to a packaging format. This is used by the software centers to decide which code path (or plugin)
should handle the component. For instance: components with a `<bundle type="package">...</bundle>`
will be handled by [PackageKit](https://www.freedesktop.org/software/PackageKit/), and components
with a `<bundle type="flatpak">...</bundle>` will be handled by [libflatpak](https://docs.flatpak.org/).
This document will define how to format an appstream component's `<bundle>` tag such that software
centers will know to manage it using systemd. The following syntax will be supported:

A `type="systemd"` attribute. This tells the software center that it should treat the bundle tag
as described in this document.

A `class=""` attribute, with the following possible values: `sysupdate`, `extension`, `confext`,
or `portable`. These correspond to sysupdate components, sysexts, confexts, and portable services
respectively.

The value of the tag will be used as the name of the image (corresponding to the `class=` attribute).
So for instance, `<bundle type="systemd" class="extension">foobar</bundle>` corresponds to a sysext
named "foobar". For `class="sysupdate"`, there is a special case: if the value is empty, then the
bundle actually refers to the host system.

## Examples

```xml
<component type="addon">
	<id>com.example.Devel</id>
	<extends>com.example.OS</extends>
	<name>Development Tools</name>
	<summary>Tools essential to develop Example OS</summary>
	<provides>
		<binary>gcc</binary>
		<binary>g++</binary>
		<binary>make</binary>
		<binary>autoconf</binary>
		<binary>cmake</binary>
		<binary>meson</binary>
		<binary>ninja</binary>
	</provides>
	<developer_name>Example, inc.</developer_name>
	<releases>
		<release version="45" date="2024-01-15" />
		<release version="44" date="2023-12-08" />
		<release version="43" date="2023-11-10" />
	</releases>
	<bundle type="systemd" class="extension">devel</bundle>
</component>
```

defines a sysext named `devel` to be presented by the software center. It will be
updated via `systemd-sysupdated`'s `extension:devel` target. It will be treated
as a plugin for the operating system itself.

```xml
<component merge="append">
	<id>com.example.OS</id>
	<releases>
		<release version="45" date="2024-01-15" urgency="high">
			<description>
				<p>This release includes various bug fixes and performance improvements</p>
			</description>
		</release>
	</releases>
	<bundle type="systemd" class="sysupdate" />
</component>
```

extends existing appstream metadata for the host OS with a changelog. It also tells the software
center that the host OS should be updated using the `host` target for `systemd-sysupdated`.

```xml
<component type="service">
	<id>com.example.Foobar</id>
	<name>Foobar Service</name>
	<summary>Service that does foo to bar</summary>
	<icon type="remote">https://example.com/products/foobar/logo.svg</icon>
	<url type="homepage">https://example.com/products/foobar</url>
	<provides>
		<dbus type="system">com.example.Foobar</dbus>
	</provides>
	<developer_name>Example, inc.</developer_name>
	<releases>
		<release version="1.0.1" date="2024-02-16" urgency="critical">
			<description>
				<p>This release fixes a major security vulnerability. Please update ASAP.</p>
			</description>
			<issues>
				<issue type="cve">CVE-2024-28153</issue>
			</issues>
		</release>
		<release version="1.1-beta" date="2024-01-08" type="development" />
		<release version="1.0" date="2023-11-23">
			<description>
				<p>Initial release!</p>
			</description>
		</release>
	</releases>
	<bundle type="systemd" class="portable">foobar</bundle>
</component>
```

defines a portable service named `foobar` to be presented by the software center. It will be
updated via `systemd-sysupdated`'s `portable:foobar` target. It will be marked as an
urgent update. It will be presented to the user with a display name, a description, and
a custom icon.
