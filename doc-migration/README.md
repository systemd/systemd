# Migration of Documentation from Docbook to Sphinx

- [Migration of Documentation from Docbook to Sphinx](#migration-of-documentation-from-docbook-to-sphinx)
  - [Prerequisites](#prerequisites)
    - [Manual installation](#manual-installation)
  - [Transformation Process](#transformation-process)
    - [1. Docbook to `rst`](#1-docbook-to-rst)
    - [2. `rst` to Sphinx html and man](#2-rst-to-sphinx-html-and-man)
      - [Notes on incremental builds](#notes-on-incremental-builds)
      - [Notes on `man_pages` generation](#notes-on-man_pages-generation)
      - [Notes on aliases](#notes-on-aliases)
      - [Sphinx Options](#sphinx-options)
      - [Custom Sphinx Extensions](#custom-sphinx-extensions)
        - [systemd\_domain.py](#systemd_domainpy)
        - [preprocessor.py](#preprocessorpy)
        - [autogen\_index.py](#autogen_indexpy)
        - [external\_man\_links.py](#external_man_linkspy)
      - [Includes](#includes)
  - [Todo](#todo)

## Prerequisites

Python dependencies for parsing docbook files and generating `rst`:

- `lxml`

Python dependencies for generating `html` and `man` pages from `rst`:

- `sphinx`
- `furo` (The Sphinx theme)

To install these (see [Sphinx Docs](https://www.sphinx-doc.org/en/master/tutorial/getting-started.html#setting-up-your-project-and-development-environment)):

`sudo dnf install python3-{lxml,furo,sphinx,sphinx_reredirects}'

### Manual installation

```sh
# Generate a Python env:
$ python3 -m venv .venv
$ source .venv/bin/activate
# Install deps
$ .venv/bin/pip install lxml
$ .venv/bin/pip install sphinx
$ .venv/bin/pip install sphinx_reredirects
$ .venv/bin/pip install furo
$ cd doc-migration && ./convert.sh
```

## Transformation Process

You can run the entire process with `./convert.sh` in the `doc-migration` folder. The individual steps are described below:

1. Docbook to `rst` with `db2rst.py`
2. Sphinx `Makefile`
   1. Preprocessor Extension for Sphinx
   2. Sphinx itself
   3. Some progressive enhancement to further improve the html output in `/source/_static/js/custom.js`

### 1. Docbook to `rst`

This step migrates the old Docbook `xml` files to Sphinx `rst` files. While the vast majority of the docs is converted correctly, the result is not perfect: there are a number of cases listed in the `/EDGE_CASES.md` file that require manual fixes before or after this conversion. In some cases, `rst` is simply not flexible enough to achieve a clean mapping of the old `xml` syntax, in others, the switch to a different markup language necessitates extra character escaping, in yet other the effort required to handle them automatically far exceeded the effort needed to just fix them once manually after this conversion. We have document as many of these as we could find to make the final sprint over the finish line as painless as possible for systemd.

**Usage:**

Use the `main.py` script to convert a single Docbook file to `rst`:

```sh
# in the `doc-migration` folder:
$ python3 main.py --file ../man/busctl.xml --output 'source/docs'
# or whatever your local Python version is, adpat as needed in all examples:
$ python3.13 main.py --file ../man/busctl.xml --output 'source/docs'
```

This file calls `db2rst.py` that parses Docbook elements on each file, does some string transformation to the contents of each, and glues them all back together again. It will also output info on unhandled elements, so we know whether our converter is feature complete and can achieve parity with the old docs.

To run the script against all files you can use :

```sh
# in the `doc-migration` folder:
$ python3 main.py --dir ../man --output 'source/docs'
```

To do the actual conversion of all files:
```sh
# you may need
$ rm -rf source/docs/ && python3 main.py --dir ../man --output 'source/docs'
```

After using the above script at least once you will get two files(`errors.json`,`successes_with_unhandled_tags.json`) in the output dir.

`errors.json` will have all the files that failed to convert to rst with the respective error message for each file.
running : `python3 main.py --errored` will only process the files that had an error and present in `errors.json`

`successes_with_unhandled_tags.json` will have all the files that were converted but there were still some tags that are not defined in `db2rst.py` yet.

running : `python3 main.py --unhandled-only` will only process the files that are present in `successes_with_unhandled_tags.json`

This is to avoid running all files at once when we only need to work on files that are not completely processed.

At the time of delivery of this work package (Dec. 2025), all tags are handled, and no errors are logged. The script does emit two warnings about unhandled inline comments, as `rst` does not have those and there is no good way to convert them. These are listed in `EDGE_CASES.md`, along with other issues that require some manual intervention.

At some point, this step will be discarded, as all documentation now lives in `rst` files.

### 2. `rst` to Sphinx html and man

This will be the new regular documentation build step:

```sh
# in the `/doc-migration` folder
$ rm -rf build
# ☝️ if you already have a build
$ make html man
```

- The `html` files end up in `/doc-migration/build/html`. Open the `index.html` there to browse the docs.
- The `man` files end up in `/doc-migration/build/man`. Preview an individual file with `$ mandoc -l build/man/busctl.1`

Note that the Sphinx entry point, `index.rst` in `/doc-migration/source`, is autogenerated by the [autogen\_index.py extension](#autogen_indexpy).

#### Notes on incremental builds

Sphinx supports parallel and incremental builds, but this only applies to `rst` reads and `html` writes, not to `man` writes. It is possible to write an extension that patches Sphinx’s `ManualPageBuilder` to only write actually changed files, but this needs to take into account changed includes as well. This might be considered as a future optimisation.

#### Notes on `man_pages` generation

Sphinx requires the explicit listing of all man pages in the `man_pages` conf variable. We build this at runtime from the files themselves. Note that this process has a side-effect, see [Notes on aliases](#notes-on-aliases) below.

#### Notes on aliases

Systemd makes extensive use of alias pages (effectively redirects), where all the `name`s of a page should also be valid reference targets. To achieve this in Sphinx, a fair amount of hoop-jumping is necessary:

1. All alias pages should be declared in each `rst` file’s metadata, e.g.:
   ```rst
    :title: os-release
    :manvolnum: 5
    :summary: Operating system identification
    :aliases: initrd-release, extension-release
   ```
2. These aliases are parsed in `conf.py` as a side-effect of generating the `man_pages` config var and injected into Sphinx’s handling of the `:ref:` role. This allows authors to directly reference an alias which links to the real page while still displaying the alias’s page title without having to explicitly declare it, so ``:ref:`initrd-release` `` just works. It links to the `os-release` page, but displays `initrd-release` as the link text.
3. To make direct navigation from outside possible, we also need to register http redirects for all aliases. These are handled by the `sphinx_reredirects` extension and also automatically configured in `conf.py`.

#### Sphinx Options

Sphinx-build takes [many options](https://www.sphinx-doc.org/en/master/man/sphinx-build.html#options) that can be passed in like this: `SPHINXOPTS="-a -E -v" make html`. The most useful ones:

- `-j auto` -> Distribute the build over however many CPU cores are available. Parallel builds are generally much faster. Does not work on Windows. Highly Recommended.

For debugging etc:
- `-v` -> Verbose. Logs all the things.
- `-a` -> Always rebuilds all files. If you have a caching issue, try this.
- `-E` -> Fresh-Env, rebuilds the cross-reference environment.

#### Custom Sphinx Extensions

We use the following custom Sphinx extensions to achieve parity with the old docs. These live in `/source/_ext` and are activated via the `extensions` variable in `conf.py`.

##### systemd_domain.py

A custom Sphinx domain for systemd. This allows us to have a neat, concise syntax for defining and referencing systemd properties. Anything declared this way will also be picked up in the directives list, which is itself a custom systemd Sphinx directive used in `directives.rst`.

Based on the directives config that we’ve migrated to `directives_data` in `conf.py`, we define four roles/directives:
1. `var`
2. `env`
3. `option`
4. `constant`

These can be used as block-level declarations to define a systemd property, e.g.:

```rst
.. systemd:option:: ExternalSizeMax=, JournalSizeMax=
   :group: config-directives

    Optional text content follows here.
```

As you can see, there is an optional `:group:` attribute that maps to the directive groups in `directives_data` in `conf.py`, and results in the directives being grouped into the proper sections in the directives overview.

Several examples follow:

```rst
.. systemd:option:: list

   Show all peers on the bus, by their service names. By default, shows both unique and well-known names, but this may be changed with the :code:`--unique` and :code:`--acquired` switches. This is the default operation if no command is specified.
```

```rst
.. systemd:var:: $SYSTEMD_LESSCHARSET
   :group: environment-variables

   Override the charset passed to :code:`less` (by default "utf-8", if the invoking terminal is determined to be UTF-8 compatible).
```

```rst
.. systemd:constant:: K
  :group: environment-variables

  This option instructs the pager to exit immediately when :kbd:`Ctrl` + :kbd:`C` is pressed.
```

You can also declare multiple directives at once by comma-separating them, and each will be linkable individually, and appear in the directives list individually:

```rst
.. systemd:option:: SystemMaxUse=, SystemKeepFree=, SystemMaxFileSize=, SystemMaxFiles=, RuntimeMaxUse=, RuntimeKeepFree=, RuntimeMaxFileSize=, RuntimeMaxFiles=
   :group: config-directives
```

To reference (link) to any directive, use the role syntax:

```rst
:systemd:option:`SystemMaxUse=` and :systemd:option:`RuntimeMaxUse=` control how much disk space the journal may use up at most.
```

```rst
:systemd:constant:`SYSTEMD_LOG_LEVEL=debug,console:info` specifies to log at debug level.
```

Really, just throw the whole entry in there:

```rst
:systemd:option:`set-property SERVICE OBJECT INTERFACE PROPERTY SIGNATURE ARGUMENT...`
```

If the same name is defined in multiple documents, you can qualify the reference with the document’s basename (without `.rst` or the manvolnum). For example: `OOMPolicy=` exists in both `systemd.scope(5)` and `systemd.service(5)`, to specify whoch one you want to reference/link to, prefix the doc name like this:

```rst
:systemd:option:`systemd.scope:OOMPolicy=`
:systemd:option:`systemd.service:OOMPolicy=`
```

You may also use the full docname including the `docs/` prefix:

```rst
:systemd:option:`docs/systemd.unit:After=`
```

The qualifier is matched against:
- full docname (e.g. `docs/systemd.unit`)
- basename (e.g. `systemd.unit`)
- slug form used in anchors (e.g. `systemd-unit`)

When no qualifier is given, resolution prefers a definition in the same document, otherwise the first one found.

To display the directives list (currently in `directives.rst`), simply use this custom Sphinx directive:

```rst
.. systemd:directiveindex::
```

To link to this directives page, use

```rst
:ref:`systemd.directives(7)`
.. or
:doc:`directives`
```

##### preprocessor.py

This extension does the variable substitutions defined in the `global_substitutions` object in `/doc-migrations/source/conf.py` (the Sphinx config file). We originally tried solving this problem with the `globalsubs` Sphinx extension and the `rst_prolog` feature, but neither were sufficient, more details can be found at the top of `preprocessor.py`.

The preprocessor also handles a custom include tag (e.g. `%% include="standard-specifiers.rst" id="a" %%`) for some cases that could not be handled with `rst` alone. This was a necessary workaround since the old docs do partial includes of tables in other tables, and other inner-block includes rst does not support. Using this tag also resolves Sphinx confusion when including a footnote reference and its footnote with two separate includes (since there are no inline/inline-block footnotes in `rst`), using the `%% include…` syntax for both solves the problem.

##### autogen_index.py

A separate extension that overwrites `/doc-migration/source/index.rst` with a html and a man toc generated from the files in `/doc-migration/source/docs`, and also generates alias entries.

##### external_man_links.py

This is used to create custom sphinx roles to handle external links for man pages to avoid having full urls in rst, for example:

```rst
:die-net:`refentrytitle(manvolnum)`
```

…will lead to 'http://linux.die.net/man/{manvolnum}/{refentrytitle}'.

A full list of these roles can be found in [external_man_links](source/_ext/external_man_links.py).

#### Includes

1. Versions
   In the Docbook files you may find lines like these: `<xi:include href="version-info.xml" xpointer="v205"/>` which would render into `Added in version 205` in the docs. This is now achieved with the existing [sphinx directive ".. versionadded::"](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-versionadded) and represented as `.. versionadded:: 205` in the rst file, no includes required.

2. Block Includes

  There are a few xml files were sections of these files are reused in multiple other files. While it trivial to include an `rst` file in another one, only including parts of other files is slightly more involved, since `rst` has no easily adressable elements. Mapping to the rst `.. include::` directive’s `start-after` and `end-before`options, we use corresponding marker comments to define includable sections in these source files. These markers are: `.. inclusion-marker-do-not-remove {xpointer-id}|` and `.. inclusion-end-marker-do-not-remove {xpointer-id}|`, for example:

  This directive is enclosed by inclusion markers generated from `<varlistentry id='no-pager'>`:

  ```rst
  .. inclusion-marker-do-not-remove no-pager|

     .. systemd:option:: --no-pager

       Do not pipe output into a pager.

  .. inclusion-end-marker-do-not-remove no-pager|
  ```

  > [!IMPORTANT]
  > Note the pipe `|` used to delimit the marker’s end. This is crucial, as markers with the same prefix are often nested, and omitting a delimiter causes problems, since the include can then run too short or too long. We STRONGLY encourage always delimiting include ids this way.

  Below is the syntax to include a section, converted from `<xi:include href="standard-options.xml" xpointer="no-pager" />` to:

  ```rst
  .. include:: ./standard-options.rst
    :start-after: .. inclusion-marker-do-not-remove no-pager|
    :end-before: .. inclusion-end-marker-do-not-remove no-pager|
  ```

  Since rst does not support all inclusion scenarios that occur within the systemd docs, we have added a second inclusion syntax that is handled in a Sphinx preprocessor extension (see the file `_ext/preprocessor.py`). The syntax is similar:

  ```
  %% include="standard-specifiers.rst" id="a|" %%
  ```

  This essentially does the same thing as the longer `.. include::` declaration above, but works inside tables and other block elements within which `rst` doesn’t allow includes. So `%% include` can also be used as a shorthand for `.. include::`. Note the `|` pipe delimiter inside the id here too.

## Todo

An incomplete list.

- [ ] The footnote in common-variables…
- [ ] Clean up literal include file copying, there are currently pointless files in /includes
- [ ] HTML improvements:
  - [ ] Render directive headlines so furo picks them up in the sidebar (probably an issue with the content replacement when `.. systemd:directiveindex::` is parsed in `systemd_domain.py`)
  - [ ] Extremely optional: Make higher order headlines foldable?
- [ ] Unclear what these do:
  - [ ] DBUS doc generation `tools/update-dbus-docs.py`
  - [ ] See whether `tools/update-man-rules.py` does anything we don’t do
  - [ ] check-api-docs
