- `ukify.xml`
  - [ ] `<programlisting>` with text and `<xi:include>`
- `bootctl.xml`
  - [ ] program listing at the end is not rendered as a code block
- [ ] Inline xml comments are skipped, since rst does not support inline comments. The conversion script logs these occurances.
- `standard-conf.xml`
  - [ ] the `xpointer="usr-local-footnote"` import adds _both_ the footnote link as well as the footnote. This isn’t possible in rst, afaik. Used in:
    ```
    man/standard-conf.xml
    man/systemd.environment-generator.xml
    man/systemd.generator.xml
    man/systemd.link.xml
    man/systemd.network.xml
    man/systemd.unit.xml
    ```
- Table Includes: Some xml tables include parts of other xml tables, we handle this to some degree (includes of `<row>` elements, as peers of other `<row>` elements inside `<tbody`), but these are too complex:
  - `sd_bus_message_append.xml`: includes `<colspec>` and `<thead>` elements from `sd_bus_message_append_basic.xml` element, we don’t even register these because they’re outside of outside of the `<tbody>`
  - `sd_bus_message_append.xml`: also includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
  - `sd_bus_message_read.xml`: includes the all the children of another `<tbody>` from `sd_bus_message_append_basic.xml`
