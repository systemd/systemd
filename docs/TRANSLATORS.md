---
title: Notes for Translators
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Notes for Translators

systemd depends on the `gettext` package for multilingual support.

You'll find the i18n files in the `po/` directory.

The build system (meson/ninja) can be used to generate a template (`*.pot`),
which can be used to create new translations.

It can also merge the template into the existing translations (`*.po`), to pick
up new strings in need of translation.

Finally, it is able to compile the translations (to `*.gmo` files), so that
they can be used by systemd software. (This step is also useful to confirm the
syntax of the `*.po` files is correct.)

## Creating a New Translation

To create a translation to a language not yet available, start by creating the
initial template:

```
$ meson compile -C build/ systemd-pot
```

This will generate file `po/systemd.pot` in the source tree.

Then simply copy it to a new <code><i>${lang_code}</i>.po</code> file, where
<code><i>${lang_code}</i></code> is the two-letter code for a language
(possibly followed by a two-letter uppercase country code), according to the
ISO 639 standard.

In short:

<pre>
$ cp po/systemd.pot po/<i>${lang_code}</i>.po
</pre>

Then edit the new <code>po/<i>${lang_code}</i>.po</code> file (for example,
using the `poedit` GUI editor.)

## Updating an Existing Translation

Start by updating the `*.po` files from the latest template:

```
$ meson compile -C build/ systemd-update-po
```

This will touch all the `*.po` files, so you'll want to pay attention when
creating a git commit from this change, to only include the one translation
you're actually updating.

Edit the `*.po` file, looking for empty translations and translations marked as
"fuzzy" (which means the merger found a similar message that needs to be
reviewed as it's expected not to match exactly.)

You can use any text editor to update the `*.po` files, but a good choice is
the `poedit` editor, a graphical application specifically designed for this
purpose.

Once you're done, create a git commit for the update of the `po/*.po` file you
touched. Remember to undo the changes to the other `*.po` files (for instance,
using `git checkout -- po/` after you commit the changes you do want to keep.)

## Recompiling Translations

You can recompile the `*.po` files using the following command:

```
$ meson compile -C build/ systemd-gmo
```

The resulting files will be saved in the `build/po/` directory.
