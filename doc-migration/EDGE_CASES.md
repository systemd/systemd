# Edge Cases and other Steps that Require Manual Intervention

This file lists all outstanding work. This covers:

- Work that systemd has more knowledge of or control over (e.g. env vars)
- Issues we could not resolve automatically without changing the source `xml` (e.g. use of `rst`-significant chars) or manually correcting the `rst` output of the `db2rst.py` script (e.g. misinterpreted references).
- Issues which would have required an unreasonable amount of effort for one-off problems (e.g. table formatting, complex include statements, occasional one-off indentation errors). Since we don’t want this script to be tied to a specific version of the source `xml` docs, we list these issues here so they can be handled when the actual switch to Sphinx happens.
- Genuine omissions, typos and errors in the original documentation that are now flagged by Sphinx.

- [Config Issues](#config-issues)
- [Manual Fixes](#manual-fixes)
- [Sphinx Complaints](#sphinx-complaints)
- [Might Be Automatable](#might-be-automatable)
- [Table Issues](#table-issues)

# Config Issues

- [ ] The environment vars used in `conf.py` need to be set somehow before the Sphinx build runs.

# Manual Fixes
- [ ] Inline xml comments are skipped, since `rst` does not support inline comments. The conversion script logs these occurances. There are only 2 of them.
- [ ] Manual escaping of significant characters. There are some remaining occurances of the Sphinx warning `Inline emphasis start-string without end-string`, for example in `systemd.time.rst:167`, where some `*` for example need to be escaped with a backslash so they are not interpreted as `rst` syntax.
- [ ] In the same vein, some strings are interpreted as references, eg `"cap_???"` in `systemd-analyze.rst` is assumed to link to something called `cap`. Occurances like these register as `ERROR: Unknown target name` in Sphinx. The pragmatic approach would probably be to wrap these in ``:code:`"cap_???"` `` or some other inline literal declaration post conversion.
- [ ] Some include directives are too complex to convert, e.g. in `man/systemctl.xml`:
    ```xml
    <xi:include href="standard-options.xml" xpointer="xpointer(//varlistentry[@id='option-P']/listitem/para)" />
    ```
    There is no sensible way of converting these other than adding an `id` to the target element in the source `xml` and modifying the `<xi:include>` element to point to the new target. This occurs in 3 files: `systemctl.xml`, `systemd.scope.xml` and `timedatectl.xml`
- [ ] `systemd-resolved.service.rst` ends up with some faulty indents in the first footnote, this needs manual fixing.
- [ ] In `ukify.xml` line 845, `<programlisting>` has both inline text and `<xi:include>`, the inline text is lost in the conversion.

# Sphinx Complaints
- [ ] Occasional use of unorthodox whitespace in the source `xml` causes issues, eg `char *const *` in `man/sd_bus_message_append_strv.xml` uses the invisible `U+00a0`. This results in Sphinx complaining about `WARNING: Inline emphasis start-string without end-string.`. Unclear what the original intent here was.
- [ ] 230 `WARNING: undefined label: 'systemd-sysusers.service(8)' [ref.ref]`-type errors during `make html`. These pages fall into two categories:
    1. The page actually doesn’t exist, e.g. `umask(2)` also doesn’t exist in the original docs, despite being linked to:
    2. One page occurs multiple times with different names, e.g. in the original docs, `systemd-sysusers(8)` is the same as `systemd-sysusers.service(8)`, where the latter is not actually a proper file, but some sort of alias. Sometimes it’s the other way around, so `systemd-journal-gatewayd.service(8)` exists as a proper file, but `systemd-journal-gatewayd(8)` doesn’t. There is also the case of `sd` being used as the alias for `systemd`, so `sd-stub` is an alias for `systemd-stub`. The new docs system does not account for these yet.

# Might Be Automatable
- `<citerefentry>` elements without a `project` or `href` attribute seem to be intend to fall back to _both_ `man7.org` and the local systemd docs. It is probably possible to differentiate between the two by checking whether the target exists as a local file during the `db2rst.py` conversion, but we wanted to be sure about the intent first.

# Table Issues
- Table Includes: Some xml tables include parts of other xml tables, we handle this to some degree (includes of `<row>` elements, as peers of other `<row>` elements inside `<tbody`), but these are too complex:
  - `sd_bus_message_append.xml`: includes `<colspec>` and `<thead>` elements from `sd_bus_message_append_basic.xml` element, we don’t even register these because they’re outside of outside of the `<tbody>`
  - `sd_bus_message_append.xml`: also includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
  - `sd_bus_message_read.xml`: includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
- [ ] The table in `sd_bus_message_append.xml` needs to be converted manually, see the "complex include directives" point under [General Issues](#general-issues). Sphinx complains about column number mismatch,
