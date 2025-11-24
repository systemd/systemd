# One-Off Conversion Issues



- `ukify.xml`
  - [ ] `<programlisting>` has both text and `<xi:include>`
- `bootctl.xml`
  - [ ] program listing at the end is not rendered as a code block
- [ ] `systemd-resolved.service.rst` ends up with some faulty indents in the first footnote, this needs manual fixing.
- Imports from `standard-conf.xml`:
  - [ ] the `xpointer="usr-local-footnote"` import adds _both_ the footnote link as well as the footnote. This isn’t possible in rst, and was worked around by using a preprocessor include. This file is included from 25 xml files. 20 work fine, but 5 of these import the footnote _as inline text_:
    - man/systemd.environment-generator.xml: xpointer="usr-local-footnote"
    - man/systemd.generator.xml: xpointer="usr-local-footnote"
    - man/systemd.link.xml: xpointer="usr-local-footnote"
    - man/systemd.network.xml: xpointer="usr-local-footnote"
    - man/systemd.unit.xml: xpointer="usr-local-footnote"

# General Issues
- [ ] Inline xml comments are skipped, since rst does not support inline comments. The conversion script logs these occurances, there are only 2 of them.

# Table Issues

- Table Includes: Some xml tables include parts of other xml tables, we handle this to some degree (includes of `<row>` elements, as peers of other `<row>` elements inside `<tbody`), but these are too complex:
  - `sd_bus_message_append.xml`: includes `<colspec>` and `<thead>` elements from `sd_bus_message_append_basic.xml` element, we don’t even register these because they’re outside of outside of the `<tbody>`
  - `sd_bus_message_append.xml`: also includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
  - `sd_bus_message_read.xml`: includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
