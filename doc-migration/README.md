# Migration of Documentation from Docbook to Sphinx

- [Migration of Documentation from Docbook to Sphinx](#migration-of-documentation-from-docbook-to-sphinx)
  - [Prerequisites](#prerequisites)
  - [Transformation Process](#transformation-process)
    - [1. Docbook to `rst`](#1-docbook-to-rst)
    - [2. `rst` to Sphinx](#2-rst-to-sphinx)
      - [Sphinx Extensions](#sphinx-extensions)
        - [sphinxcontrib-globalsubs](#sphinxcontrib-globalsubs)
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

Use the `db2rst.py` script to convert a single Docbook file to `rst`:

```sh
# in the `doc-migration` folder:
$ python3 db2rst.py ../man/busctl.xml > source/busctl.rst
```

This file parses Docbook elements, does some string transformation to the contents of each, and glues them all back together again. It will also output info on unhandled elements, so we know whether our converter is feature complete and can achieve parity with the old docs.

### 2. `rst` to Sphinx

```sh
# in the `/doc-migration` folder
$ rm -rf build
# ☝️ if you already have a build
$ make html
```

The built `html` files end up in `/doc-migration/build/html`. Open the `index.html` there to browse the docs.

#### Sphinx Extensions

We use the following Sphinx extensions to achieve parity with the old docs:

##### sphinxcontrib-globalsubs

Allows referencing variables in the `global_substitutions` object in `/doc-migrations/source/conf.py` (the Sphinx config file).

## Todo:

- [ ] Custom Link transformations:
  - [ ] `custom-man.xsl`
  - [x] `custom-html.xsl`
