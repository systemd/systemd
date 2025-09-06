# Migration of Documentation from Docbook to Sphinx

- [Migration of Documentation from Docbook to Sphinx](#migration-of-documentation-from-docbook-to-sphinx)
  - [Prerequisites](#prerequisites)
  - [Transformation Process](#transformation-process)
    - [1. Docbook to `rst`](#1-docbook-to-rst)
    - [2. `rst` to Sphinx](#2-rst-to-sphinx)
      - [Sphinx Extensions](#sphinx-extensions)
        - [sphinxcontrib-globalsubs](#sphinxcontrib-globalsubs)
      - [Custom Sphinx Extensions](#custom-sphinx-extensions)
        - [directive_roles.py (90% done)](#directive_rolespy-90-done)
        - [external_man_links.py](#external_man_linkspy)
      - [Includes](#includes)
  - [Todo:](#todo)

## Prerequisites

Python dependencies for parsing docbook files and generating `rst`:

- `lxml`

Python dependencies for generating `html` and `man` pages from `rst`:

- `sphinx`
- `sphinxcontrib-globalsubs`
- `furo` (The Sphinx theme)

To install these (see [Sphinx Docs](https://www.sphinx-doc.org/en/master/tutorial/getting-started.html#setting-up-your-project-and-development-environment)):

```sh
# Generate a Python env:
$ python3 -m venv .venv
$ source .venv/bin/activate
# Install deps
$ python3 -m pip install -U lxml
$ python3 -m pip install -U sphinx
$ python3 -m pip install -U sphinxcontrib-globalsubs
$ python3 -m pip install -U furo
$ cd doc-migration && ./convert.sh
```

## Transformation Process

You can run the entire process with `./convert.sh` in the `doc-migration` folder. The individual steps are:

### 1. Docbook to `rst`

Use the `main.py` script to convert a single Docbook file to `rst`:

```sh
# in the `doc-migration` folder:
$ python3 main.py --file ../man/busctl.xml --output 'in-progress'
```

This file calls `db2rst.py` that parses Docbook elements on each file, does some string transformation to the contents of each, and glues them all back together again. It will also output info on unhandled elements, so we know whether our converter is feature complete and can achieve parity with the old docs.

To run the script against all files you can use :

```sh
# in the `doc-migration` folder:
$ python3 main.py --dir ../man --output 'in-progress'
```

> When using the script to convert all files at once in our man folder we recommend using "in-progress" folder name as our output dir so we don't end up replacing some the files that were converted and been marked as finished inside the source folder.

After using the above script at least once you will get two files(`errors.json`,`successes_with_unhandled_tags.json`) in the output dir.

`errors.json` will have all the files that failed to convert to rst with the respective error message for each file.
running : `python3 main.py --errored` will only process the files that had an error and present in `errors.json`

`successes_with_unhandled_tags.json` will have all the files that were converted but there were still some tags that are not defined in `db2rst.py` yet.

running : `python3 main.py --unhandled-only` will only process the files that are present in `successes_with_unhandled_tags.json`

This is to avoid running all files at once when we only need to work on files that are not completely processed.

### 2. `rst` to Sphinx

```sh
# in the `/doc-migration` folder
$ rm -rf build
# ☝️ if you already have a build
$ make html man
```

- The `html` files end up in `/doc-migration/build/html`. Open the `index.html` there to browse the docs.
- The `man` files end up in `/doc-migration/build/man`. Preview an individual file with `$ mandoc -l build/man/busctl.1`

#### Sphinx Extensions

We use the following Sphinx extensions to achieve parity with the old docs:

##### sphinxcontrib-globalsubs

Allows referencing variables in the `global_substitutions` object in `/doc-migrations/source/conf.py` (the Sphinx config file).

#### Custom Sphinx Extensions

##### directive_roles.py (90% done)

This is used to add custom Sphinx directives and roles to generate systemD directive lists page.

To achieve the functionality exiting in `tools/make-directive-index.py` by building the Directive Index page from custom Sphinx role, here is an example:

The formula for those sphinx roles is like this: `:directive:{directive_id}:{type}`

For example we can use an inline Sphinx role like this:

```
 :directive:environment-variables:var:`SYSEXT_SCOPE=`
```

This will be then inserted in the SystemD directive page on build under the group `environment-variables`
we can use the `{type}` to have more control over how this will be treated inside the Directive Index page.

##### external_man_links.py

This is used to create custom sphinx roles to handle external links for man pages to avoid having full urls in rst for example:

`:die-net:`refentrytitle(manvolnum)` will lead to 'http://linux.die.net/man/{manvolnum}/{refentrytitle}'
a full list of these roles can be found in [external_man_links](source/_ext/external_man_links.py).

#### Includes

1. Versions
   In the Docbook files you may find lines like these: `<xi:include href="version-info.xml" xpointer="v205"/>` which would render into `Added in version 205` in the docs. This is now archived with the existing [sphinx directive ".. versionadded::"](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-versionadded) and represented as `.. versionadded:: 205` in the rst file

2. Code Snippets
   These can be included with the [literalinclude directive](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-literalinclude) when living in their own file.

   Example:

  ```rst
  .. literalinclude:: ./check-os-release-simple.py
  :language: python
  ```

  There is also the option to include a [code block](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-code-block) directly in the rst file.

  Example:

  ```rst
  .. code-block:: sh

  a{sv} 3 One s Eins Two u 2 Yes b true

  ```

3. Text Snippets

  There are a few xml files were sections of these files are reused in multiple other files. While it is no problem to include a whole other rst file the concept of only including a part of that file is a bit more tricky. You can choose to include text partial that starts after a specific text and also to stop before reaching another text. So we decided it would be best to add start and stop markers to define the section in these source files. These markers are: `.. inclusion-marker-do-not-remove` / ``So that a`<xi:include href="standard-options.xml" xpointer="no-pager" />` turns into:

  ```rst
  .. include:: ./standard-options.rst
    :start-after: .. inclusion-marker-do-not-remove no-pager
    :end-before: .. inclusion-end-marker-do-not-remove no-pager
  ```

## Todo

An incomplete list.

- [ ] Custom Link transformations:
  - [ ] `custom-man.xsl`
  - [x] `custom-html.xsl`
- [ ] See whether `tools/tools/xml_helper.py` does anything we don’t do, this also contains useful code for:
  - [ ] Build a man index, as in `tools/make-man-index.py`
  - [x] Build a directives index, as in `tools/make-directive-index.py`
  - [ ] DBUS doc generation `tools/update-dbus-docs.py`
- [ ] See whether `tools/update-man-rules.py` does anything we don’t do
- [ ] Make sure the `man_pages` we generate for Sphinx’s `conf.py` match the Meson rules in `man/rules/meson.build`
- [ ] Re-implement check-api-docs
